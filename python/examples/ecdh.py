from cryptoauthlib import *
from cryptoauthlib.iface import *
from common import *

import time

# Slot 4 IO Encryption key
SLOT_4_KEY = bytearray([
    0x37, 0x80, 0xe6, 0x3d, 0x49, 0x68, 0xad, 0xe5,
    0xd8, 0x22, 0xc0, 0x13, 0xfc, 0xc3, 0x23, 0x84,
    0x5d, 0x1b, 0x56, 0x9f, 0xe7, 0x05, 0xb6, 0x00,
    0x06, 0xfe, 0xec, 0x14, 0x5a, 0x0d, 0xb1, 0xe3
])

def ECDH(iface='hid'):
    ATCA_SUCCESS = 0x00

    # Loading cryptoauthlib(python specific)
    load_cryptoauthlib()

    # Get a default config
    if iface is 'i2c':
        cfg = cfg_ateccx08a_i2c_default()
    else:
        cfg = cfg_ateccx08a_kithid_default()
    
    # Initialize the stack
    assert atcab_init(cfg) == ATCA_SUCCESS
    
    # Check device type
    info = bytearray(4)
    assert atcab_info(info) == ATCA_SUCCESS
    dev_type = get_device_type_id(get_device_name(info))
    
    if dev_type in [0, 0x20]:
        raise ValueError('Device does not support ECDH operations')
    elif dev_type != cfg.devtype:
        assert atcab_release() == ATCA_SUCCESS
        time.sleep(1)
        assert atcab_init(cfg) == ATCA_SUCCESS

    # Writing IO protection key. This key is used to encrypt the pre-master secret which
    # is read out of the device.
    assert atcab_write_zone(2, 4, 0, 0, SLOT_4_KEY, 32) == ATCA_SUCCESS

    Key_id_alice = 0x00
    key_id_bob = 0x02

    # Get Alice's public key
    pub_alice = bytearray(64)
    assert atcab_get_pubkey(Key_id_alice, pub_alice) == ATCA_SUCCESS
    print("\nAlice's slot {} public key :\n".format(Key_id_alice))
    print(pretty_print_hex(pub_alice))

    # Generating Bob's Private Key in Slot and getting the associated Public Key
    pub_bob = bytearray(64)
    assert atcab_genkey(key_id_bob, pub_bob) == ATCA_SUCCESS
    print("Bob's slot {} public key :\n".format(key_id_bob))
    print(pretty_print_hex(pub_bob))

    # Generating Alice pre-master secret with bob public key
    pms_alice = bytearray(32)
    assert atcab_ecdh_enc(Key_id_alice, pub_bob, pms_alice, SLOT_4_KEY, 4) == ATCA_SUCCESS
    print("\nAlice's pre-master secret :\n")
    print(pretty_print_hex(pms_alice))

    # Generating Bob pre-master secret with Alice public key
    pms_bob = bytearray(32)
    assert atcab_ecdh(key_id_bob, pub_alice, pms_bob) == ATCA_SUCCESS
    print("Bob's pre-master secret :\n")
    print(pretty_print_hex(pms_bob))

    if pms_alice == pms_bob:
        print("\nGenerated pre-master secret for both sides match!")
    else:
        print("\nError generating pre-master secret")

    assert atcab_release() == ATCA_SUCCESS


if __name__ == '__main__':
    parser = setup_example_runner(__file__)
    args = parser.parse_args()

    ECDH(args.iface)
