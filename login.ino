//#define DEBUG
#define CENSOR

#ifdef DEBUG
  #define PRINTDEBUG(STR) Serial.println(STR)
#else
  #define PRINTDEBUG(STR) /*NOTHING*/
#endif

#include <HID-Project.h>    // NicoHood HID-Project Library
#include <MFRC522.h>        // MiguelBalboa MFRC522 Library
#include <SPI.h>

// Needs crypto library from: https://github.com/rweather/arduinolibs
#include <Crypto.h>
#include <BLAKE2s.h>
#include <ChaCha.h>

#define HASH_SIZE 32
BLAKE2s blake2s;
ChaCha chacha;

//   SDA  to  10
//   SCK  to  15
//   MOSI to  16
//   MISO to  14
//   IRQ      N/A
//   GND  to  GND
//   RST  to  18 = A0
//   3.3V to  3.3V
#define RST_PIN 18 // RST-PIN for RC522
#define SS_PIN  10  // SDA-PIN for RC522
MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance


#define AUTHORIZED_LENGTH 7       // Minimum required length of UID - 7 is recommended
#define AUTHORIZED_COUNT  1
const String AUTHORIZED_HASHES[AUTHORIZED_COUNT] = {
  "uid hash from the serial monitor"
};

#define PASSWORD_LENGTH 10
const byte PLAIN_PASSWORD[] = "PASSWORD_TO_BE_ENCRYPTED";
const byte ENCRYPTED_PASSWORDS[AUTHORIZED_COUNT][PASSWORD_LENGTH]  = {
  {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
};

const byte IV[8]       = {101, 102, 103, 104, 105, 106, 107, 108};
const byte COUNTER[8]  = {109, 110, 111, 112, 113, 114, 115, 116};




//// Helper routine to dump a byte array as hex values to Serial
//void dump_byte_array_hex(byte *buffer, byte bufferSize) {
//  for (byte i = 0; i < bufferSize; ++i) {
//    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
//    Serial.print(buffer[i], HEX);
//  }
//}


// Helper routine to dump a byte array to Serial
void dump_byte_array(byte *buffer, byte bufferSize) {
  for (byte i = 0; i < bufferSize; ++i) {
    Serial.print(buffer[i] < 100 ? buffer[i] < 10 ? " 00" : " 0" : " ");
    Serial.print(buffer[i]);
  }
}


// Helper routine to dump a byte array as hex values to String
String byte_array_hex_string(byte *buffer, byte bufferSize) {
  String hex = "";
  for (byte i = 0; i < bufferSize; ++i) {
    hex += String(buffer[i], HEX);
  }
  return hex;
}


//Helper routine to dump a byte array as a String
String byte_array_string(byte *buffer, byte bufferSize) {
  String str = "";
  for (byte i = 0; i < bufferSize; ++i) {
    str += char(buffer[i]);
  }
  return str;
}


//Helper routine to convert C string to String
String cstring_string(const byte *buffer) {
  String str = "";
  byte i = 0;
  while(buffer[i] != '\0') {
    str += char(buffer[i]);
    ++i;
  }
  return str;
}


// UID hashing
String uid_hash(byte *buffer, byte bufferSize) {
  if(bufferSize < AUTHORIZED_LENGTH)
    return String("The UID is too short!");
  uint8_t hash[HASH_SIZE];
  blake2s.reset();
  blake2s.update(buffer, bufferSize);
  blake2s.finalize(hash, sizeof(hash));
  blake2s.reset();
  return byte_array_hex_string(hash, HASH_SIZE);
}


// Helper routine to check authorization
int check_auth(byte *buffer, byte bufferSize) {
  if(bufferSize < AUTHORIZED_LENGTH)
    return -1;
  String uid = uid_hash(buffer, bufferSize);    
  for(int key = 0; key < AUTHORIZED_COUNT; ++key) {
    if(AUTHORIZED_HASHES[key] == uid)
      return key;
  }
  return -1;
}


// Encrypt password
String encrypt_pwd(const byte *pwd, byte *uid, byte uidSize) {
  byte output[PASSWORD_LENGTH];

  chacha.clear();
  chacha.setNumRounds(20);
  chacha.setKey(uid, uidSize);
  chacha.setIV(IV, 8);
  chacha.setCounter(COUNTER, 8);
  //memset(output, 0xBA, sizeof(output));
  chacha.encrypt(output, pwd, PASSWORD_LENGTH);
  chacha.clear();
  
  String str = "{";
  for (byte i = 0; i < PASSWORD_LENGTH; ++i) {
    str += String(output[i]) + ", ";
  }
  str.remove(str.length()-2);
  str += "};";
  return str;
}


// Decrypt password
String decrypt_pwd(const byte *pwd, byte *uid, byte uidSize) {
  byte output[PASSWORD_LENGTH];

  chacha.clear();
  chacha.setNumRounds(20);
  chacha.setKey(uid, uidSize);
  chacha.setIV(IV, 8);
  chacha.setCounter(COUNTER, 8);
  //memset(output, 0xBA, sizeof(output));
  chacha.decrypt(output, pwd, PASSWORD_LENGTH);
  chacha.clear();
  
  return byte_array_string(output, PASSWORD_LENGTH);
}


// Send password with numbers typed on numeric keypad
void enter_password(String pwd) {
  for(int i = 0; i < pwd.length(); ++i) {
    switch(pwd[i]) {
      case '0':
        BootKeyboard.write(KEYPAD_0);
        break;
      case '1':
        BootKeyboard.write(KEYPAD_1);
        break;
      case '2':
        BootKeyboard.write(KEYPAD_2);
        break;      
      case '3':
        BootKeyboard.write(KEYPAD_3);
        break;
      case '4':
        BootKeyboard.write(KEYPAD_4);
        break;
      case '5':
        BootKeyboard.write(KEYPAD_5);
        break;
      case '6':
        BootKeyboard.write(KEYPAD_6);
        break;
      case '7':
        BootKeyboard.write(KEYPAD_7);
        break;
      case '8':
        BootKeyboard.write(KEYPAD_8);
        break;
      case '9':
        BootKeyboard.write(KEYPAD_9);
        break;
      default:
        BootKeyboard.write(pwd[i]);
    }
  }
  BootKeyboard.write(KEY_ENTER);  
}





////////////////////////// SETUP //////////////////////////////////////////////////////
void setup() {
  #ifdef DEBUG
    Serial.begin(9600);    // Initialize serial communications
    while (!Serial);       // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
  #endif
  PRINTDEBUG("Serial connected");

  #ifdef DEBUG
    Serial1.begin(9600);
  #endif

  SPI.begin();           // Init SPI bus
  PRINTDEBUG("SPI started");

  mfrc522.PCD_Init();    // Init MFRC522
  PRINTDEBUG("MFRC522 started");
  PRINTDEBUG("Getting Antenna Gain");
  PRINTDEBUG(String(mfrc522.PCD_GetAntennaGain()));
  delay(100);
  PRINTDEBUG("Setting Max Antenna Gain");
  mfrc522.PCD_SetAntennaGain(mfrc522.RxGain_max);
  delay(100);
  PRINTDEBUG("Getting Antenna Gain");
  PRINTDEBUG(String(mfrc522.PCD_GetAntennaGain()));
  delay(100);

  BootKeyboard.begin();
  PRINTDEBUG("Keyboard started");
}





////////////////////////// LOOP //////////////////////////////////////////////////////
void loop() {

  // Look for new cards
  if ( ! mfrc522.PICC_IsNewCardPresent()) {
    //PRINTDEBUG("No card");
    delay(50);
    return;
  }

  // Select one of the cards
  if ( ! mfrc522.PICC_ReadCardSerial()) {
    PRINTDEBUG();
    PRINTDEBUG("Selection failed");
    delay(50);
    return;
  }

  // Show some details of the PICC (that is: the tag/card)
  PRINTDEBUG();
  #ifndef CENSOR
    PRINTDEBUG("Card UID:");
    #ifdef DEBUG
      dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
      delay(10);
    #endif
    PRINTDEBUG();
  #endif
  PRINTDEBUG("UID BLAKE2s Hash:");
  PRINTDEBUG(" " + uid_hash(mfrc522.uid.uidByte, mfrc522.uid.size));
  PRINTDEBUG("Password \"" + cstring_string(PLAIN_PASSWORD) + "\" encrypted with UID using ChaCha:");
  PRINTDEBUG(" " + encrypt_pwd(PLAIN_PASSWORD, mfrc522.uid.uidByte, mfrc522.uid.size));

  int auth = check_auth(mfrc522.uid.uidByte, mfrc522.uid.size);
  if(auth > -1)
  {
    PRINTDEBUG("Authorized");
    PRINTDEBUG("Decrypting password");
    String password = decrypt_pwd(ENCRYPTED_PASSWORDS[auth], mfrc522.uid.uidByte, mfrc522.uid.size);
    #ifndef CENSOR
      PRINTDEBUG(" " + password);
    #endif
    if(BootKeyboard.getLeds() & LED_NUM_LOCK) // checks that the num lock is ON
    {
      PRINTDEBUG("Num Lock is ON");
    }
    else
    {
      PRINTDEBUG("Num Lock is OFF. Turning ON...");
      BootKeyboard.write(KEY_NUM_LOCK);
    }
    PRINTDEBUG("Sending password...");
    enter_password(password);
    delay(10000);
  }
  else
  {
    PRINTDEBUG("Not Authorized");
    delay(10000);
  }
}

