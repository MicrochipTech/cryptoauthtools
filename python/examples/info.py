from cryptoauthlib import *
from cryptoauthlib.iface import *
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
    print('Device Part: %s\n' % get_device_name(info))

    # Request the Serial Number
    serial_number = bytearray(9)
    assert atcab_read_serial_number(serial_number) == ATCA_SUCCESS
    print('Serial number: %s\n' % pretty_print_hex(serial_number))

    # Read the configuration zone
    config_zone = bytearray(128)
    assert atcab_read_config_zone(config_zone) == ATCA_SUCCESS

    print('Configuration Zone:\n')
    print(pretty_print_hex(config_zone))

    # Check the device locks
    print('')
    is_locked = bytearray(1)
    assert atcab_is_locked(0, is_locked) == ATCA_SUCCESS
    print('Config Zone is %s\n' % ('locked' if is_locked[0] else 'unlocked'))
    
    assert atcab_is_locked(1, is_locked) == ATCA_SUCCESS
    print('Data Zone is %s\n' % ('locked' if is_locked[0] else 'unlocked'))
        
    # Free the library
    atcab_release()


if __name__ == '__main__':
    parser = setup_example_runner(__file__)
    args = parser.parse_args()

    info(args.iface)