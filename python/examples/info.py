from cryptoauthlib import *
from common import *


def info(iface='hid'):
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
    print('')
    
    # Request the Revision Number
    info = bytearray(4)
    assert atcab_info(info) == ATCA_SUCCESS
    print('\nDevice Part:')
    print('    ' + get_device_name(info))

    # Request the Serial Number
    serial_number = bytearray(9)
    assert atcab_read_serial_number(serial_number) == ATCA_SUCCESS
    print('\nSerial number: ')
    print(pretty_print_hex(serial_number, indent='    '))

    # Read the configuration zone
    config_zone = bytearray(128)
    assert atcab_read_config_zone(config_zone) == ATCA_SUCCESS

    print('\nConfiguration Zone:')
    print(pretty_print_hex(config_zone, indent='    '))

    # Check the device locks
    print('\nCheck Device Locks')
    is_locked = bytearray(1)
    assert atcab_is_locked(0, is_locked) == ATCA_SUCCESS
    print('    Config Zone is %s' % ('locked' if is_locked[0] else 'unlocked'))

    assert atcab_is_locked(1, is_locked) == ATCA_SUCCESS
    print('    Data Zone is %s' % ('locked' if is_locked[0] else 'unlocked'))

    # Free the library
    atcab_release()


if __name__ == '__main__':
    parser = setup_example_runner(__file__)
    args = parser.parse_args()

    info(args.iface)
    print('\nDone')
