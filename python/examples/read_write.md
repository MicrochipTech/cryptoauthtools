
## Read Write Example

The Read command reads from one of the memory zones of the device. The data may optionally be encrypted before being returned to the system.

The Write command writes to the EEPROM zones on the device. Depending upon the value of the WriteConfig byte for a slot, the data may be required to be encrypted by the system prior to being sent to the device

This examples illustrates the use of clear text write, clear text read, encrpted read and encrypted writes

### Prerequisite software before running the example:
- Atmel Crypto Evaluation Studio (ACES)
- python 3.x
- cryptoauthlib python module, can be install through pip with
    "pip install cryptoauthlib" command
- binascii python module

### Supported hardware:
- AT88microbase
- CryptoAuth-XSTK

###  Supported devices:
- [ATSHA204A](http://www.microchip.com/ATSHA204A)
- [ATECC508A](http://www.microchip.com/ATECC508A)
- [ATECC608A](http://www.microchip.com/ATECC608A)

### Steps to run the example:

Step I: Provisioning the device

The device can be provisioned through the programmer.py python script availabe under "provisioning_utility" directory. The device needs to programmed with "CAL_ECC608" or "CAL_ECC508" or "CAL_SHA204" configuration for teh example to work. For example to run this example in ECC608 device the following command should be used to program the "CAL_ECC608" config into the ATECC608 device.

    python programmer.py -dev ECC608 -conf CAL_ECC608

Step II: Executing the python script

Once the device is provisioned, then the example can be run, just by invoking command prompt/shell then using

    python "example_name.py"