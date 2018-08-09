Read Write Example
===============================================================================
The Read command reads from one of the memory zones of the device. The data may
optionally be encrypted before being returned to the system.

The Write command writes to the EEPROM zones on the device. Depending upon the
value of the WriteConfig byte for a slot, the data may be required to be
encrypted by the system prior to being sent to the device

This examples illustrates the use of clear text write, clear text read, 
encrypted read and encrypted writes

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

Steps to run the example:
-------------------------------------------------------------------------------
To view the script command options:

    $ python read_write.py -h

The example can be run by:

    $ python read_write.py

-------------------------------------------------------------------------------
