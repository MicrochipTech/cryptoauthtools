ECDH Example
===============================================================================
The ECDH command implements the Elliptic Curve Diffie-Hellman algorithm to 
combine an internal private key with an external public key to calculate a
shared secret.

The example genkey command to generate two independent EC key-pairs then
calculates the shared secret through ECDH commands.

Prerequisites:
-------------------------------------------------------------------------------
See [requirements.txt](requirements.txt) or install via:

    $ pip install -r requirements.txt

If the device has not been previously configured for use a basic configuration
that supports a number of use cases can be written (this is irreversible):

    $ python config.py

Supported devices:
-------------------------------------------------------------------------------
* [ATECC508A](http://www.microchip.com/ATECC508A)
* [ATECC608A](http://www.microchip.com/ATECC608A)

Steps to run the example:
-------------------------------------------------------------------------------
To view the script command options:

    $ python ecdh.py -h

The example can be run by:

    $ python ecdh.py

-------------------------------------------------------------------------------
