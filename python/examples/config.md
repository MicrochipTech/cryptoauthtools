Example Configurations
===============================================================================
Before a CryptoAuthentication device may be used it's configuration must be set
for the intended use case(s). Configurations can be quite complex and need to
be carefully created and analyzed for security gaps that could be introduced
by an unintended configuration interaction. When developing a new configuration
please consult both the datasheet and your FAE.

This script will program a general purpose configuration that allows for a
variety of examples to be evaluated. __This configuration should be modified
before use in a production device__. The following is a list of items set in
order for the configuration to be easier to use for an experimenter.

ATECC508A Configuraiton
* Slot 4 & 6 allow unencrypted writes which means the io protection key can
be rewritten without prior knowledge of a secret.

ATECC608A Configuration:
* Slot 6 allows unencrypted writes which means the io protection key can
be rewritten without prior knowledge of a secret.
* Slot 6 is additionally used as the io protection key for reading ECDH 
premaster secret and KDF material.

ATSHA204A Configuration:
* Slots may be freely written without prior knowledge of the slot contents

The rational for the above is principally to remove the requirement that the
user/experimenter of the device to carefully set and manage secrets and keys
that would otherwise render the device unusuable if they were lost or set
carelessly.


Prerequisites:
-------------------------------------------------------------------------------
See [requirements.txt](requirements.txt) or install via:

    $ pip install -r requirements.txt

If the device has not been previously configured for use a basic configuration
that supports a number of use cases can be written (this is irreversible):

    $ python config.py

Supported devices:
-------------------------------------------------------------------------------
- [ATSHA204A](http://www.microchip.com/ATSHA204A)
- [ATECC508A](http://www.microchip.com/ATECC508A)
- [ATECC608A](http://www.microchip.com/ATECC608A)

Steps to run the configuration script:
-------------------------------------------------------------------------------
To view the script command options:

    $ python config.py -h
    
The example can be run by:

    $ python config.py

-------------------------------------------------------------------------------
