"""
ECDSA Sign Verify Example
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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.exceptions import InvalidSignature
from cryptography.utils import int_from_bytes, int_to_bytes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import time

ATCA_SUCCESS = 0x00


def init_device(iface='hid', slot=0, **kwargs):
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
    
    # Check device type
    info = bytearray(4)
    assert atcab_info(info) == ATCA_SUCCESS
    dev_type = get_device_type_id(get_device_name(info))
    
    if dev_type in [0, 0x20]:
        raise ValueError('Device does not support Sign/Verify operations')
    elif dev_type != cfg.devtype:
        cfg.dev_type = dev_type
        assert atcab_release() == ATCA_SUCCESS
        time.sleep(1)
        assert atcab_init(cfg) == ATCA_SUCCESS

    # Get the device's public key
    public_key = bytearray(64)
    assert atcab_get_pubkey(slot, public_key) == ATCA_SUCCESS
    
    return public_key


def sign_device(digest, slot):
    """
    Sign message using an ATECC508A or ATECC608A
    """
    signature = bytearray(64)
    assert atcab_sign(slot, digest, signature) == ATCA_SUCCESS

    return signature


def verify_device(message, signature, public_key):
    """
    Verify a signature using a device
    """
    is_verified = AtcaReference(False)
    assert atcab_verify_extern(message, signature, public_key, is_verified) == ATCA_SUCCESS

    return bool(is_verified.value)


def sign_host(digest, key):
    signature = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    (r,s) = utils.decode_dss_signature(signature)
    signature = int_to_bytes(r, 32) + int_to_bytes(s, 32)
    return signature
    
    
def verify_host(digest, signature, public_key_data):
    """
    Verify a signature using the host software
    """
    try:
        r = int_from_bytes(signature[0:32], byteorder='big', signed=False)
        s = int_from_bytes(signature[32:64], byteorder='big', signed=False)
        sig = utils.encode_dss_signature(r, s)

        public_key = ec.EllipticCurvePublicNumbers(
            curve=ec.SECP256R1(),
            x=int_from_bytes(public_key_data[0:32], byteorder='big'),
            y=int_from_bytes(public_key_data[32:64], byteorder='big'),
        ).public_key(default_backend())
        public_key.verify(sig, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False


if __name__ == '__main__':
    parser = setup_example_runner(__file__)
    parser.add_argument('-k', '--key', default=0, type=int, help='Key Id (Slot number) device private key for signing')
    parser.add_argument('-s', '--signer', choices=['device', 'host'], default='device', help='Signature will be performed by the device or host (default: device)')
    parser.add_argument('-v', '--verifier', choices=['device', 'host'], default='host', help='Verify will be performed by the device or host (default: host)')
    args = parser.parse_args()

    print('\nSign/Verify Example\n')

    if 'device' in [args.signer, args.verifier]:
        public_key = init_device(args.iface, args.key, **parse_interface_params(args.params))

    if 'host' == args.signer:
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = key.public_key().public_bytes(encoding=Encoding.X962, format=PublicFormat.UncompressedPoint)[1:]


    print('Signing Public key:')
    print(convert_ec_pub_to_pem(public_key))

    # Generate a random message
    message = os.urandom(32)

    # Create a digest of the message for signing
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    message = digest.finalize()

    print('Message Digest:')
    print(pretty_print_hex(message, indent='    '))
    
    # Sign the message
    print("\nSigning the Message Digest")
    if 'device' == args.signer:
        print('    Signing with device')
        signature = sign_device(message, args.key)
    else:
        print('    Signing with host')
        signature = sign_host(message, key)

    print('\nSignature:')
    print(pretty_print_hex(signature, indent='    '))

    # Verify the message
    print("\nVerifing the signature:")
    if 'device' == args.verifier:
        print('    Verifying with device')
        verified = verify_device(message, signature, public_key)
    else:
        print('    Verifying with host')
        verified = verify_host(message, signature, public_key)

    print('    Signature is %s!' % ('valid' if verified else 'invalid'))
    
    # Clean up
    if 'device' in [args.signer, args.verifier]:
        atcab_release()

    print('\nDone')
