TNG Certificates Example
===============================================================================
Some Microchip parts (TNG) have generic certificates that can be used for a
wide range of purposes. This script demonstrates reading out those certificates
using the TNG utility functions in CryptoAuthLib.

Please note, this example will only work for TNG parts, which are currently
the ATECC608A-MAHTN-T.

Prerequisites:
-------------------------------------------------------------------------------
See [requirements.txt](requirements.txt) or install via:

    $ pip install -r requirements.txt

Supported devices:
* [ATECC608A-MAHTN-T](https://www.microchip.com/design-centers/security-ics/cryptoauthentication/cloud-authentication/lora-security-with-tti-join-server)

Steps to run the example:
-------------------------------------------------------------------------------
To view the script command options:

    $ python tng_certs.py -h

The example can be run by:

    $ python tng_certs.py

The certificates can be saved as files with the ```--save``` option.