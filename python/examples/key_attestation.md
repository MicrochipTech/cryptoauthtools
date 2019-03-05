Key Attestation Example
===============================================================================
Key attestation is the process of proving that a particular key is held by the
secure element. This is often required when the secure element is asked to
generate a new internal random key and one wants to make sure the key is
held by the secure element, and not some man-in-the-middle attacker, before
trusting the key.

Key attestation requires a separate attestation key pair be setup to be the
authority in this operation. This key can be created at the same time as the
primary key. The attestation key is stored in a specially configured slot that
can only be used to sign messages about the internal state and contents of the
secure element. The proper configuration for this key includes:
 - Is a private key: `KeyConfig.Private=1`
 - External sign is disabled: `SlotConfig.ReadKey[0]=0`
 - Internal sign is enabled: `SlotConfig.ReadKey[1]=1`

It's assumed the attestation public key is read and stored in a trusted
location (e.g. manufacturing) to establish trust between the verifier and the
device.

Once that trust is established, the key attestation process has the following
steps:
 1. Verifier sends a starting nonce/challenge to the device to start the key
    attestation process.
 2. Device creates an attestation nonce, combining the verifier nonce with its
    own random nonce using the Nonce command.
 3. Device create a PubKey digest using the GenKey command with the Digest mode
    (0x08). This special mode combines TempKey (attestation nonce) with the
    public key being attested using SHA256 and stores the resulting digest
    back into TempKey.
 4. Use attestation key to sign (Sign command in internal mode) a message
    including the PubKey digest in TempKey with additional slot/key
    configuration and state information.
 5. The verifier is now sent the data from the device required to perform key
    attestation. This includes the public key being attested, device nonce,
    key/slot configuration and state, and attestation signature.
 6. The verifier builds the attestation message from this information and
    verifies it against the signature and the trusted attestation public key.
 7. If the verification succeeds, then the key being attested is in the secure
    element.

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

    $ python key_attestation.py -h

The example can be run by:

    $ python key_attestation.py

