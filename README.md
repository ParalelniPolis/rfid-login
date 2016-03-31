# Hardware-based Password Writer
Platform independent device for entering passwords using an RFID tag. Once configured, it only needs HID drivers on the host machine. The basic idea is, that once you tap an authorized tag on the reader, the appropriate password is decrypted and typed on an emulated keyboard. The tag UID is stored as a BLAKE2s hash to check whether it is authorized. The passwords are encrypted using ChaCha20 algorithm with the tag UID as a key. There is support for multiple tags and multiple passwords.

## Components
- Arduino Pro Micro 3.3V
- MFRC-522 RFID shield

## Pin Layout

### RC522:
- SDA  to  10
- SCK  to  15
- MOSI to  16
- MISO to  14
- IRQ      N/A
- GND  to  GND
- RST  to  18 = A0
- 3.3V to  3.3V

## Source Code Configuration
The source code in **login.ino** needs to be configured for your tags and passwords in the following parts:
- You have to uncomment the DEBUG flag in the beginning to see the debug outputs over serial monitor. To have full information, you can also comment out the CENSOR flag.
- First, you need to replace PASSWORD_TO_BE_ENCRYPTED with the password that you want to use. Then run the code while monitoring it through serial monitor. Tap your tag on the reader. The serial monitor should give you the following data:
  - UID hash - place it into `AUTHORIZED_HASHES` array
  - Encrypted password - place it into the `ENCRYPTED_PASSWORDS` array
- Now you can just replace the plaintext password with something harmless and disable the debugging flag. Upload the configured code to the device and you are ready to roll.

## Known Issues and Limitations
- The UID hashing should be supplemented with a fixed random salt to prevent precomputed dictionary attacks. However, the space of values is very large (~72e15 values) in case of 7 bytes long UIDs so a precomputed dictionary might be impractical anyway.
- Currently, multi-tag use is limited to passwords of the same length. Changes required to allow passwords of varying length are simple and will be added eventually. If you do the changes yourself, please submit a pull request.
- Notice: If the attacker has access to both the RFID tag and the hardware, he will have access to plain text password! If the attacker steals just the hardware, he can decrypt your passwords given enough time to do so.

## Donations
Development is funded through bitcoin donations:
https://blockchain.info/address/1BHPGY7Rb9WaBBkYPKjZTnKYRzt5mC8NPM
