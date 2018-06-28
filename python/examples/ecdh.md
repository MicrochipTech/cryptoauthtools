## ECDH Example

The ECDH command implements the Elliptic Curve Diffie-Hellman algorithm to 
combine an internal private key with an external public key to calculate a
shared secret.

The example genkey command to generate two independent EC Keypairs then
calculate the shared secret through ECDH commands.

### Prerequisite software before running the example:
- cryptoauthlib python module, can be install through pip with
    "pip install cryptoauthlib" command

### Supported devices:
- [ATECC508A](http://www.microchip.com/ATECC508A)
- [ATECC608A](http://www.microchip.com/ATECC608A)

### Steps to run the example:

Prerequisite: Configure the device with the standard TLS configuration

    $ python config.py

Running the example: Once the device is configured, then the example can be
run, just by invoking command prompt/shell then using

    $ python ecdh.py
