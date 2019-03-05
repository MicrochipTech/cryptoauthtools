# Python CryptoAuthLib Examples

This directory contains a number of examples for using the python cryptoauthlib
module

## Prerequesites
Install the python requirements via the command:
```
    pip install -r requirements.txt
```

## Running the examples
The examples are intended to be simple and straightforward to illustrate the
basic concepts. To get help on any example you can consult the associated
document (e.g. [info.py](info.py) has an accompanying [info.md](info.md)
document) or from the command line:
```
    info.py -h
```

```
usage: info.py [-h] [-i {i2c,hid}]

## Info Example

This example extracts identifying information and configuration from a device.

* Device type identification and mask revision
* Serial number
* Configuration zone data
* Lock status

### Prerequisite software before running the example:
- cryptoauthlib python module, can be install through pip with
    "pip install cryptoauthlib" command

### Supported devices:
- [ATSHA204A](http://www.microchip.com/ATSHA204A)
- [ATECC508A](http://www.microchip.com/ATECC508A)
- [ATECC608A](http://www.microchip.com/ATECC608A)

optional arguments:
  -h, --help            show this help message and exit
  -i {i2c,hid}, --iface {i2c,hid}
                        Interface type (default: hid)
```

## list of Examples

- [config.py](config.py): Configure and provision a blank device for these
  examples. See [config.md](config.md)
- [info.py](info.py): Read device info. See [info.md](info.md)
- [key_attestation.py](key_attestation.md): Demonstrate a key attestation flow
  for proving possesion of an asymmetric key.
  See [key_attestation.md](key_attestation.md)
- [ecdh.py](ecdh.py): Perform ECDH calculation. See [ecdh.md](ecdh.md)
- [sign_verify.py](sign_verify.py): Perform ECDSA signature and verification.
  See [sign_verify.md](sign_verify.md)
- [read_write.py](read_write.py): Perform encrypted writes and successive reads
  from a slot. See [read_write.md](read_write.md)

## What does the Python CryptoAuthLib package do?
CryptoAuthLib module gives access to most functions available as part of
standard cryptoauthlib (which is written in 'C'). These python functions for
the most part are very similar to 'C' functions. The module in short acts as a
wrapper over the 'C' cryptoauth library functions.

Microchip cryptoauthlib product page: 
[Link]( http://www.microchip.com/SWLibraryWeb/product.aspx?product=CryptoAuthLib)

## Supported hardware
- [AT88CK101](http://www.microchip.com/DevelopmentTools/ProductDetails/AT88CK101SK-MAH-XPRO)
- [CryptoAuthentication Starter Kit (DM320109)](https://www.microchip.com/developmenttools/ProductDetails/DM320109)
- ATECC508A, ATECC608A, ATSHA204A device directly connected via I2C (Linux Only)