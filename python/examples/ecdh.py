from cryptoauthlib import *
from common import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

import time


def ECDH(slot, iface='hid'):
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
        cfg.dev_type = dev_type
        assert atcab_release() == ATCA_SUCCESS
        time.sleep(1)
        assert atcab_init(cfg) == ATCA_SUCCESS

    # Read config zone
    config_zone = bytearray(128)
    assert atcab_read_config_zone(config_zone) == ATCA_SUCCESS

    # Create a host private key
    host_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Convert host's public key into ATECCx08 format
    host_pub = host_key.public_key().public_numbers().encode_point()[1:]

    # Display the host's public key
    print("\nHost Public Key:")
    print(pretty_print_hex(host_pub, indent='    '))

    # Buffers for device public key and shared secret
    device_pub = bytearray(64)
    device_shared = bytearray(32)

    # Generate a device private key and perform the ECDH operation
    # This step is using the unencrypted form of the ECDH calls due to configuration details that will be specific
    # for the use case. See atcab_ecdh_enc and atcab_ecdh_tempkey_ioenc functions.
    if dev_type == get_device_type_id('ATECC508A'):
        assert atcab_genkey(slot, device_pub) == ATCA_SUCCESS
        assert atcab_ecdh(slot, host_pub, device_shared) == ATCA_SUCCESS
    else:
        assert atcab_genkey(0xFFFF, device_pub) == ATCA_SUCCESS
        assert atcab_ecdh_tempkey(host_pub, device_shared) == ATCA_SUCCESS

    # Display the device's public key
    print("\nDevice public key:")
    print(pretty_print_hex(device_pub, indent='    '))

    # Convert device public key to a cryptography public key object
    device_pub = ec.EllipticCurvePublicNumbers.from_encoded_point(ec.SECP256R1(), b'\04' + device_pub).public_key(default_backend())

    # Perform the host side ECDH computation
    host_shared = host_key.exchange(ec.ECDH(), device_pub)

    # Display the host side computed symmetric key
    print('\nHost Calculated Shared Secret:')
    print(pretty_print_hex(host_shared, indent='    '))

    # Display the device side computed symmetric key
    print('\nDevice Calculated Shared Secret:')
    print(pretty_print_hex(device_shared, indent='    '))

    # Compare both independently calculated
    print('\nComparing host and device generated secrets:')
    if host_shared == device_shared:
        print("    Success - Generated secrets match!")
    else:
        print("    Error in calculation")

    assert atcab_release() == ATCA_SUCCESS


if __name__ == '__main__':
    parser = setup_example_runner(__file__)
    parser.add_argument('-s', '--slot', default=2, type=int, help='Slot to use for key generation (ATECC508A only)')
    args = parser.parse_args()

    print('\nPerforming ECDH operations in the clear - see datasheet for encryption details')
    ECDH(args.slot, args.iface)
    print('\nDone')
