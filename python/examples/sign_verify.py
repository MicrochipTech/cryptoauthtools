from cryptoauthlib import *
from cryptoauthlib.iface import *
from common import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.exceptions import InvalidSignature
from cryptography.utils import int_from_bytes, int_to_bytes

import time

ATCA_SUCCESS = 0x00

def init_device(iface='hid', slot=0):
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
        raise ValueError('Device does not support Sign/Verify operations')
    elif dev_type != cfg.devtype:
        assert atcab_release() == ATCA_SUCCESS
        time.sleep(1)
        assert atcab_init(cfg) == ATCA_SUCCESS

    # Get the device's public key
    public_key = bytearray(64)
    assert atcab_get_pubkey(slot, public_key) == ATCA_SUCCESS
    
    return public_key
    
def sign_device(digest, slot):
    # Sign message
    signature = bytearray(64)
    assert atcab_sign(slot, message, signature) == ATCA_SUCCESS

    return signature


def verify_device(message, signature, public_key):
    """
    Verify a signature using a device
    """
    is_verified = bytearray(1)

    assert atcab_verify_extern(message, signature, public_key, is_verified) == ATCA_SUCCESS

    return (1 == is_verified[0])


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
        public_key_data = b'\x04' + public_key_data

        r = int_from_bytes(signature[0:32], byteorder='big', signed=False)
        s = int_from_bytes(signature[32:64], byteorder='big', signed=False)
        sig = utils.encode_dss_signature(r, s)
    
        public_key = ec.EllipticCurvePublicNumbers.from_encoded_point(ec.SECP256R1(), public_key_data).public_key(default_backend())
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
        public_key = init_device(args.iface, args.key)
        
    if 'host' == args.signer:
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = key.public_key().public_numbers().encode_point()[1:]


    print('Signing Public key:')
    print(pretty_print_hex(public_key))

    # Generate a random message
    message = os.urandom(32)

    # Create a digest of the message for signing
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    message = digest.finalize()

    print('Message Digest:')
    print(pretty_print_hex(message))
    
    # Sign the message
    print("\nSigning the Message Digest\n")
    if 'device' == args.signer:
        signature = sign_device(message, args.key)
    else:
        signature = sign_host(message, key)

    print('Signature:')
    print(pretty_print_hex(signature))

    # Verify the message
    print("\nVerifing the signature\n")
    if 'device' == args.verifier:
        verified = verify_device(message, signature, public_key)
    else:
        verified = verify_host(message, signature, public_key)
        
    print('Signature is %s!' % ('valid' if verified else 'invalid'))
    
    # Clean up
    if 'device' in [args.signer, args.verifier]:
        atcab_release()
    