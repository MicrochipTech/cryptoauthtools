## ECC Sign Verify Example

The Sign command generates a signature using the private key in slot with ECDSA algorithm. The Verify command takes an ECDSA [R,S] signature and verifies that it is correctly generated given an input message digest and public key.

This example illustrates the use of ECC Sign and Verify command on supported CryptoAuthentication device.

In the example:-
    - ECC key pair will be generated
    - Random message is generated
    - The message is signed with the private key
    - The signed message is verified with the associated public key

### Prerequisite software before running the example:
- Atmel Crypto Evaluation Studio (ACES)
- python 3.x
- cryptoauthlib python module, can be install through pip with
    "pip install cryptoauthlib" command
- binascii python module

### Supported hardware:
- AT88microbase
- CryptoAuth-XSTK

### Supported devices:
- [ATECC508A](http://www.microchip.com/ATECC508A)
- [ATECC608A](http://www.microchip.com/ATECC608A)

### Steps to run the example:

Step I: Provisioning the device

The device can be provisioned through the programmer.py python script availabe under "provisioning_utility" directory. The device needs to programmed with "CAL_ECC608" or "CAL_ECC508" or "CAL_SHA204" configuration for teh example to work. For example to run this example in ECC608 device the following command should be used to program the "CAL_ECC608" config into the ATECC608 device.

    python programmer.py -dev ECC608 -conf CAL_ECC608

Step II: Executing the python script

Once the device is provisioned, then the example can be run, just by invoking command prompt/shell then using

    python "example_name.py"