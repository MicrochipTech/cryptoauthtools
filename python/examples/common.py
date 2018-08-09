""" Common helper functions for cryptoauthlib examples """
import argparse
import os
import base64

# Maps common name to the specific name used internally
atca_names_map = {'i2c': 'i2c', 'hid': 'kithid', 'sha': 'sha204', 'ecc': 'eccx08'}


def get_device_name(revision):
    """
    Returns the device name based on the info byte array values returned by atcab_info
    """
    devices = {0x10: 'ATECC108A', 
               0x50: 'ATECC508A', 
               0x60: 'ATECC608A',
               0x00: 'ATSHA204A',
               0x02: 'ATSHA204A'}
    return devices.get(revision[2], 'UNKNOWN')


def get_device_type_id(name):
    """
    Returns the ATCADeviceType value based on the device name
    """
    devices = {'ATSHA204A': 0,
               'ATECC108A': 1, 
               'ATECC508A': 2,
               'ATECC608A': 3,
               'UNKNOWN': 0x20 }
    return devices.get(name.upper())


def setup_example_runner(module):
    """
    Common helper function that sets up the script entry for all examples
    """
    example = os.path.basename(module).split('.')[0]

    try:
        with open(example + '.md', 'r') as f:
            details = f.read()
    except FileNotFoundError:
        details = example.upper() + ' Example'

    parser = argparse.ArgumentParser(description=details, 
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    
    parser.add_argument('-i', '--iface', default='hid', choices=['i2c', 'hid'], help='Interface type (default: hid)')
    parser.add_argument('-d', '--device', default='ecc', choices=['ecc', 'sha'], help='Device type (default: ecc)')
    
    return parser


def pretty_print_hex(a, l=16, indent=''):
    s = ''
    a = bytearray(a)
    for x in range(0, len(a), l):
        s += indent + ''.join(['%02X ' % y for y in a[x:x+l]]) + '\n'
    return s

    
def convert_ec_pub_to_pem(raw_pub_key):
    """
    Convert to the key to PEM format. Expects bytes
    """
    public_key_pem = bytearray.fromhex('3059301306072A8648CE3D020106082A8648CE3D03010703420004') + raw_pub_key
    public_key_pem = '-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(public_key_pem).decode('ascii') + '\n-----END PUBLIC KEY-----'
    return public_key_pem
    
