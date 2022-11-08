"""
ECDH Shared Secret Generation Example
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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.utils import int_from_bytes

import time


def ECDH(slot, iface='hid', **kwargs):
    ATCA_SUCCESS = 0x00

    # Loading cryptoauthlib(python specific)
    load_cryptoauthlib()

    # Get the target default config
    cfg = eval('cfg_ateccx08a_{}_default()'.format(atca_names_map.get(iface)))

    # Set interface parameters
    if kwargs is not None:
        for k, v in kwargs.items():
            icfg = getattr(cfg.cfg, 'atca{}'.format(iface))
            setattr(icfg, k, int(v, 16))


    # Basic Raspberry Pi I2C check
    if 'bus' not in kwargs:
        if 'i2c' == iface and check_if_rpi():
            cfg.cfg.atcai2c.bus = 1

    # Initialize the stack
    assert atcab_init(cfg) == ATCA_SUCCESS
    
    # Get the device type from the info command
    info = bytearray(4)
    assert atcab_info(info) == ATCA_SUCCESS
    dev_name = get_device_name(info)
    dev_type = get_device_type_id(dev_name)

    # Check device type
    if dev_type in ['ATSHA204A', 'ATECC108A']:
        raise ValueError('Device does not support ECDH operations')
    elif dev_type != cfg.devtype:
        cfg.dev_type = dev_type
        assert atcab_release() == ATCA_SUCCESS
        time.sleep(1)
        assert atcab_init(cfg) == ATCA_SUCCESS

    # Create a host private key
    host_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Convert host's public key into ATECCx08 format
    host_pub = host_key.public_key().public_bytes(encoding=Encoding.X962, format=PublicFormat.UncompressedPoint)[1:]

    # Display the host's public key
    print("\nHost Public Key:")
    print(convert_ec_pub_to_pem(host_pub))

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
    print(convert_ec_pub_to_pem(device_pub))

    # Convert device public key to a cryptography public key object
    device_pub = ec.EllipticCurvePublicNumbers(
        curve=ec.SECP256R1(),
        x=int_from_bytes(device_pub[0:32], byteorder='big'),
        y=int_from_bytes(device_pub[32:64], byteorder='big'),
    ).public_key(default_backend())

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
    ECDH(args.slot, args.iface, **parse_interface_params(args.params))
    print('\nDone')
