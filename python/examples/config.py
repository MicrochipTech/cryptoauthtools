"""
Basic Configuration Common Use Cases
"""
# (c) 2015-2018 Microchip Technology Inc. and its subsidiaries.
#
# Subject to your compliance with these terms, you may use Microchip software
# and any derivatives exclusively with Microchip products. It is your
# responsibility to comply with third party license terms applicable to your
# use of third party software (including open source software) that may
# accompany Microchip software.
#
# THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
# EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
# WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
# PARTICULAR PURPOSE. IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT,
# SPECIAL, PUNITIVE, INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE
# OF ANY KIND WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF
# MICROCHIP HAS BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE
# FORESEEABLE. TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL
# LIABILITY ON ALL CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED
# THE AMOUNT OF FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR
# THIS SOFTWARE.

from cryptoauthlib import *
from common import *
import time

_atsha204_config = bytearray.fromhex(
    'C8 00 55 00 8F 80 80 A1 82 E0 C4 F4 84 00 A0 85'
    '86 40 87 07 0F 00 C4 64 8A 7A 0B 8B 0C 4C DD 4D'
    'C2 42 AF 8F FF 00 FF 00 FF 00 FF 00 FF 00 FF 00'
    'FF 00 FF 00 FF FF FF FF FF FF FF FF FF FF FF FF'
    'FF FF FF FF 00 00 55 55')

# Example configuration for ATECC508A minus the first 16 bytes which are fixed by the factory
_atecc508_config = bytearray.fromhex(
    'B0 00 55 00 8F 20 C4 44 87 20 87 20 8F 0F C4 36'
    '9F 0F 82 20 0F 0F C4 44 0F 0F 0F 0F 0F 0F 0F 0F'
    '0F 0F 0F 0F FF FF FF FF 00 00 00 00 FF FF FF FF'
    '00 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF'
    'FF FF FF FF 00 00 55 55 FF FF 00 00 00 00 00 00'
    '33 00 1C 00 13 00 13 00 7C 00 1C 00 3C 00 33 00'
    '3C 00 3C 00 3C 00 30 00 3C 00 3C 00 3C 00 30 00')

# Example configuration for ATECC608A minus the first 16 bytes which are fixed by the factory
_atecc608_config = bytearray.fromhex(
    'B0 00 55 01 8F 20 C4 44  87 20 87 20 8F 0F C4 36'
    '9F 0F 82 20 0F 0F C4 44  0F 0F 0F 0F 0F 0F 0F 0F'
    '0F 0F 0F 0F FF FF FF FF  00 00 00 00 FF FF FF FF'
    '00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00'
    '00 00 00 00 00 00 55 55  FF FF 06 40 00 00 00 00'
    '33 00 1C 00 13 00 13 00  7C 00 1C 00 3C 00 33 00'
    '3C 00 3C 00 3C 00 30 00  3C 00 3C 00 3C 00 30 00')

_configs = {'ATSHA204A': _atsha204_config,
            'ATECC508A': _atecc508_config,
            'ATECC608A': _atecc608_config }

# Safe input if using python 2
try: input = raw_input
except NameError: pass


def configure_device(iface='hid', device='ecc', i2c_addr=None, keygen=True, **kwargs):
    ATCA_SUCCESS = 0x00

    # Loading cryptoauthlib(python specific)
    load_cryptoauthlib()

    # Get the target default config
    cfg = eval('cfg_at{}a_{}_default()'.format(atca_names_map.get(device), atca_names_map.get(iface)))

    # Set interface parameters
    if kwargs is not None:
        for k, v in kwargs.items():
            icfg = getattr(cfg.cfg, 'atca{}'.format(iface))
            setattr(icfg, k, int(v, 16))

    # Basic Raspberry Pi I2C check
    if 'i2c' == iface and check_if_rpi():
        cfg.cfg.atcai2c.bus = 1

    # Initialize the stack
    assert atcab_init(cfg) == ATCA_SUCCESS
    print('')

    # Check device type
    info = bytearray(4)
    assert atcab_info(info) == ATCA_SUCCESS
    dev_name = get_device_name(info)
    dev_type = get_device_type_id(dev_name)

    # Reinitialize if the device type doesn't match the default
    if dev_type != cfg.devtype:
        cfg.dev_type = dev_type
        assert atcab_release() == ATCA_SUCCESS
        time.sleep(1)
        assert atcab_init(cfg) == ATCA_SUCCESS

    # Request the Serial Number
    serial_number = bytearray(9)
    assert atcab_read_serial_number(serial_number) == ATCA_SUCCESS
    print('\nSerial number: ')
    print(pretty_print_hex(serial_number, indent='    '))

    # Check the zone locks
    print('\nReading the Lock Status')
    is_locked = AtcaReference(False)
    assert ATCA_SUCCESS == atcab_is_locked(0, is_locked)
    config_zone_lock = bool(is_locked.value)

    assert ATCA_SUCCESS == atcab_is_locked(1, is_locked)
    data_zone_lock = bool(is_locked.value)

    print('    Config Zone: {}'.format('Locked' if config_zone_lock else 'Unlocked'))
    print('    Data Zone: {}'.format('Locked' if data_zone_lock else 'Unlocked'))

    # Get Current I2C Address
    print('\nGetting the I2C Address')
    response = bytearray(4)
    assert ATCA_SUCCESS == atcab_read_bytes_zone(0, 0, 16, response, 4)
    print('    Current Address: {:02X}'.format(response[0]))
    if 'ecc' == device and not config_zone_lock:
        if i2c_addr is None:
            i2c_addr = 0xB0
        if 0xC0 != i2c_addr:
            print('\n    The AT88CK590 Kit does not support changing the I2C addresses of devices.')
            print('    If you are not using an AT88CK590 kit you may continue without errors')
            print('    otherwise exit and specify a compatible (0xC0) address.')
            if 'Y' != input('    Continue (Y/n): '):
                exit(0)
            print('    New Address: {:02X}'.format(i2c_addr))

    # Program the configuration zone
    print('\nProgram Configuration')
    if not config_zone_lock:
        config = _configs.get(dev_name)
        if config is not None:
            print('    Programming {} Configuration'.format(dev_name))
        else:
            print('    Unknown Device')
            raise ValueError('Unknown Device Type: {:02X}'.format(dev_type))

        # Update with the target I2C Address
        if i2c_addr is not None:
            config[0] = i2c_addr

        # Write configuration
        assert ATCA_SUCCESS == atcab_write_bytes_zone(0, 0, 16, config, len(config))
        print('        Success')

        # Verify Config Zone
        print('    Verifying Configuration')
        config_qa = bytearray(len(config))
        atcab_read_bytes_zone(0, 0, 16, config_qa, len(config_qa))

        if config_qa != config:
            raise ValueError('Configuration read from the device does not match')
        print('        Success')

        print('    Locking Configuration')
        assert ATCA_SUCCESS == atcab_lock_config_zone()
        print('        Locked')
    else:
        print('    Locked, skipping')
    
    # Check data zone lock
    print('\nActivating Configuration')
    if not data_zone_lock:
        # Lock the data zone
        assert ATCA_SUCCESS == atcab_lock_data_zone()
        print('    Activated')
    else:
        print('    Already Active')

    # Generate new keys
    if keygen or not data_zone_lock:
        if 'ATSHA204A' == dev_name:
#            print('\nProgramming Keys')
             print('\nProgram SHA204 Keys manually')
        else:
            print('\nGenerating New Keys')
            pubkey = bytearray(64)
            assert ATCA_SUCCESS == atcab_genkey(0, pubkey)
            print('    Key 0 Success:')
            print(pretty_print_hex(pubkey, indent='    '))

            assert ATCA_SUCCESS == atcab_genkey(2, pubkey)
            print('    Key 2 Success:')
            print(pretty_print_hex(pubkey, indent='    '))

            assert ATCA_SUCCESS == atcab_genkey(3, pubkey)
            print('    Key 3 Success:')
            print(pretty_print_hex(pubkey, indent='    '))

            assert ATCA_SUCCESS == atcab_genkey(7, pubkey)
            print('    Key 7 Success:')
            print(pretty_print_hex(pubkey, indent='    '))

    atcab_release()

if __name__ == '__main__':
    parser = setup_example_runner(__file__)
    parser.add_argument('--i2c', help='I2C Address (in hex)')
    parser.add_argument('--gen', default=True, help='Generate new keys')
    args = parser.parse_args()

    if args.i2c is not None:
        args.i2c = int(args.i2c, 16)

    print('\nConfiguring the device with an example configuration')
    configure_device(args.iface, args.device, args.i2c, args.gen, **parse_interface_params(args.params))
    print('\nDevice Successfully Configured')
