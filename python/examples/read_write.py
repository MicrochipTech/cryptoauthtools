"""
Slot Read/Write Example to demonstrate encrypted and unencrypted transfers
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

# Slot 4 IO Encryption key
ENC_KEY = bytearray([
    0x37, 0x80, 0xe6, 0x3d, 0x49, 0x68, 0xad, 0xe5,
    0xd8, 0x22, 0xc0, 0x13, 0xfc, 0xc3, 0x23, 0x84,
    0x5d, 0x1b, 0x56, 0x9f, 0xe7, 0x05, 0xb6, 0x00,
    0x06, 0xfe, 0xec, 0x14, 0x5a, 0x0d, 0xb1, 0xe3
])

read_write_config = {
    'ATSHA204A': {'clear': 8, 'encrypted': 3},
    'ATECC508A': {'clear': 8, 'encrypted': 9},
    'ATECC608A': {'clear': 8, 'encrypted': 9}
}


def read_write(iface='hid', device='ecc'):
    IO_key_slot = 4
    ATCA_SUCCESS = 0x00

    # Loading cryptoauthlib(python specific)
    load_cryptoauthlib()

    # Get the target default config
    cfg = eval('cfg_at{}a_{}_default()'.format(atca_names_map.get(device), atca_names_map.get(iface)))

    # Initialize the stack
    assert atcab_init(cfg) == ATCA_SUCCESS

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

    slots = read_write_config.get(dev_name)
    if slots is None:
        raise ValueError('No slot configuration for {}'.format(dev_name))

    write_data = bytearray(32)
    read_data = bytearray(32)

    print('\nGeneraing data using RAND command')
    assert atcab_random(write_data) == ATCA_SUCCESS
    print('    Generated data:')
    print(pretty_print_hex(write_data, indent='        '))

    # Writing a data to slot
    print('\nWrite command:')
    print('    Writing data to slot {}'.format(slots['clear']))
    assert atcab_write_zone(2, slots['clear'], 0, 0, write_data, 32) == ATCA_SUCCESS
    print('    Write Success')

    # Reading the data in the clear from slot
    print('\nRead command:')
    print('    Reading data stored in slot {}'.format(slots['clear']))
    assert atcab_read_zone(2, slots['clear'], 0, 0, read_data, 32) == ATCA_SUCCESS
    print('    Read data:')
    print(pretty_print_hex(read_data, indent='        '))

    # Compare the read data to the written data
    print('\nVerifing read data matches written data:')
    print('    Data {}!'.format('Matches' if (read_data == write_data) else 'Does Not Match'))

    # Writing IO protection key. This key is used as IO encryption key.
    print('\nWriting IO Protection Secret')
    assert atcab_write_zone(2, IO_key_slot, 0, 0, ENC_KEY, 32) == ATCA_SUCCESS

    print('\nGeneraing data using RAND command')
    assert atcab_random(write_data) == ATCA_SUCCESS
    print('    Generated data:')
    print(pretty_print_hex(write_data, indent='        '))

    # Writing a key to slot '1' through encrypted write
    print('\nEncrypted Write Command:')
    print('    Writing data to slot {}'.format(slots['encrypted']))
    assert atcab_write_enc(slots['encrypted'], 0, write_data, ENC_KEY, IO_key_slot) == ATCA_SUCCESS
    print('    Write Success')

    # Reading the key in plain text from slot '10'
    print('\nEncrypted Read Command:')
    print('    Reading data stored in slot {}'.format(slots['encrypted']))
    assert atcab_read_enc(slots['encrypted'], 0, read_data, ENC_KEY, IO_key_slot) == ATCA_SUCCESS
    print('    Read data:')
    print(pretty_print_hex(read_data, indent='        '))

    # Compare the read data to the written data
    print('\nVerifing read data matches written data:')
    print('    Data {}!'.format('Matches' if (read_data == write_data) else 'Does Not Match'))

    # Free the library
    atcab_release()


if __name__ == '__main__':
    parser = setup_example_runner(__file__)
    args = parser.parse_args()

    print('\nBasic Read/Write Example')
    read_write(args.iface, args.device)
    print('\nDone')
