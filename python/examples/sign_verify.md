ECDSA Sign Verify Example
===============================================================================
The Sign command generates a signature using the private key in slot with ECDSA
algorithm. The Verify command takes an ECDSA signature and verifies that it is
correctly generated given an input message digest and public key.

This example illustrates the use of ECC Sign and Verify command on supported
CryptoAuthentication device as well as the host side steps to create and verify
signatures.

In this example:
* Random message is generated
* The message is signed with the private key
* The signed message is verified with the associated public key

The signature creation and verification can be performed by either the device
or the host depending on script arguments.

Prerequisites:
-------------------------------------------------------------------------------
See [requirements.txt](requirements.txt) or install via:

    $ pip install -r requirements.txt

If the device has not been previously configured for use a basic configuration
that supports a number of use cases can be written (this is irreversible):

    $ python config.py

Supported devices:
----
* [ATECC508A](http://www.microchip.com/ATECC508A)
* [ATECC608A](http://www.microchip.com/ATECC608A)

Steps to run the example:
-------------------------------------------------------------------------------
To view the script command options:

    $ python sign_verify.py -h

The example can be run by:

    $ python sign_verify.py

Alternatively the device can be used to verify a host signature:

    $ python sign_verify.py --signer host --verifier device

-------------------------------------------------------------------------------
