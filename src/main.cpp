#include <Arduino.h>
#include <SPI.h>
#include <MFRC522.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>

// RFID RC522 pin definitions
#define SS_PIN 5
#define RST_PIN 0

// BLE UART-style service for iPhone apps
static const char *BLE_DEVICE_NAME = "RFID-Reader";
static const char *BLE_SERVICE_UUID = "6E400001-B5A3-F393-E0A9-E50E24DCCA9E";
static const char *BLE_CHAR_UUID = "6E400003-B5A3-F393-E0A9-E50E24DCCA9E";

// Create MFRC522 instance
MFRC522 rfid(SS_PIN, RST_PIN);

BLEServer *bleServer = nullptr;
BLECharacteristic *bleTxCharacteristic = nullptr;
bool bleDeviceConnected = false;

// Array to store the last UID read from a PICC
byte lastUid[10];
byte lastUidSize = 0;

class BleServerCallbacks : public BLEServerCallbacks {
  void onConnect(BLEServer *server) override {
    bleDeviceConnected = true;
  }

  void onDisconnect(BLEServer *server) override {
    bleDeviceConnected = false;
    BLEDevice::startAdvertising();
  }
};

String uidToString(const byte *uid, byte uidSize) {
  String result;
  result.reserve(uidSize * 3);
  for (byte i = 0; i < uidSize; i++) {
    if (uid[i] < 0x10) {
      result += " 0";
    } else {
      result += ' ';
    }
    char buffer[3];
    snprintf(buffer, sizeof(buffer), "%02X", uid[i]);
    result += buffer;
  }
  return result;
}

String buildCardLine(MFRC522::PICC_Type piccType, const byte *uid, byte uidSize, bool isNewCard) {
  String line;
  line.reserve(96);
  line += '[';
  line += millis();
  line += F("ms] ");
  line += rfid.PICC_GetTypeName(piccType);
  line += F(":");
  line += uidToString(uid, uidSize);
  line += isNewCard ? F(" [NEW]") : F(" [REPEATED]");
  return line;
}

void sendBleLine(const String &line) {
  if (bleDeviceConnected && bleTxCharacteristic != nullptr) {
    bleTxCharacteristic->setValue(line.c_str());
    bleTxCharacteristic->notify();
  }
}

void logCardDetection(MFRC522::PICC_Type piccType, byte *uid, byte uidSize, bool isNewCard) {
  String line = buildCardLine(piccType, uid, uidSize, isNewCard);
  Serial.println(line);
  if (isNewCard) {
    sendBleLine(line);
  }
}

// Helper function to compare UIDs
bool isNewUID(const byte *newUID, byte newSize, const byte *oldUID, byte oldSize) {
  if (newSize != oldSize) {
    return true;
  }

  for (byte i = 0; i < newSize; i++) {
    if (newUID[i] != oldUID[i]) return true;
  }
  return false;
}

void setupBle() {
  BLEDevice::init(BLE_DEVICE_NAME);
  bleServer = BLEDevice::createServer();
  bleServer->setCallbacks(new BleServerCallbacks());

  BLEService *service = bleServer->createService(BLE_SERVICE_UUID);
  bleTxCharacteristic = service->createCharacteristic(
    BLE_CHAR_UUID,
    BLECharacteristic::PROPERTY_NOTIFY | BLECharacteristic::PROPERTY_READ
  );
  bleTxCharacteristic->addDescriptor(new BLE2902());
  bleTxCharacteristic->setValue("Waiting for RFID card...");
  service->start();

  BLEAdvertising *advertising = BLEDevice::getAdvertising();
  advertising->addServiceUUID(BLE_SERVICE_UUID);
  advertising->setScanResponse(true);
  advertising->setMinPreferred(0x06);
  advertising->setMinPreferred(0x12);
  BLEDevice::startAdvertising();
}

void setup() {
  // Initialize Serial communication
  Serial.begin(9600);
  delay(100);

  // Initialize BLE for iPhone-compatible discovery
  setupBle();
  
  // Initialize SPI bus
  SPI.begin(18, 19, 23, SS_PIN);
  
  // Initialize MFRC522
  rfid.PCD_Init();

  Serial.print(F("RC522 firmware: 0x"));
  Serial.println(rfid.PCD_ReadRegister(rfid.VersionReg), HEX);
  
  Serial.println(F("\n========================================"));
  Serial.println(F("RFID RC522 Reader - Serial Logging"));
  Serial.println(F("========================================"));
  Serial.print(F("BLE device name: "));
  Serial.println(F("RFID-Reader"));
  Serial.println(F("Waiting for RFID card..."));
  Serial.println();

  if (bleTxCharacteristic != nullptr) {
    bleTxCharacteristic->setValue("Waiting for RFID card...");
  }
}

void loop() {
  // Check if a new card is present
  if (!rfid.PICC_IsNewCardPresent()) {
    return;
  }

  Serial.println(F("[DEBUG] Card detected in field."));

  // Verify if the NUID has been read
  if (!rfid.PICC_ReadCardSerial()) {
    Serial.println(F("[DEBUG] Card present, but serial read failed."));
    return;
  }

  Serial.print(F("[DEBUG] UID size: "));
  Serial.println(rfid.uid.size);
  Serial.print(F("[DEBUG] UID raw: "));
  Serial.println(uidToString(rfid.uid.uidByte, rfid.uid.size));

  // Get the card type
  MFRC522::PICC_Type piccType = rfid.PICC_GetType(rfid.uid.sak);
  Serial.print(F("[DEBUG] PICC type: "));
  Serial.println(rfid.PICC_GetTypeName(piccType));

  bool isClassicMifare = piccType == MFRC522::PICC_TYPE_MIFARE_MINI ||
                         piccType == MFRC522::PICC_TYPE_MIFARE_1K ||
                         piccType == MFRC522::PICC_TYPE_MIFARE_4K;

  if (!isClassicMifare) {
    Serial.println(F("[WARN] Tag is not MIFARE Classic, but UID will still be logged."));
  }

  // Check if this is a new card (different from the last one)
  if (isNewUID(rfid.uid.uidByte, rfid.uid.size, lastUid, lastUidSize)) {
    // Store the new UID
    lastUidSize = rfid.uid.size;
    for (byte i = 0; i < lastUidSize; i++) {
      lastUid[i] = rfid.uid.uidByte[i];
    }
    
    // Log the new card detection and notify the phone
    logCardDetection(piccType, rfid.uid.uidByte, rfid.uid.size, true);
  } else {
    // Card read previously - log locally only
    logCardDetection(piccType, rfid.uid.uidByte, rfid.uid.size, false);
  }

  // Halt PICC - put the RFID reader to idle state
  rfid.PICC_HaltA();
  
  // Stop encrypted data on PCD
  rfid.PCD_StopCrypto1();
}