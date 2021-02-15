"""
Asymmetric Key Attestation Example
"""
# (c) 2015-2019 Microchip Technology Inc. and its subsidiaries.
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

from textwrap import TextWrapper
import os
from hashlib import sha256
import struct
import copy
from cryptoauthlib import *
from cryptoauthlib.device import *
from cryptoauthlib.library import ctypes_to_bytes
from common import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.exceptions import InvalidSignature
from cryptography.utils import int_from_bytes, int_to_bytes

import time


ATCA_SUCCESS = 0x00


def init_device(iface='hid', **kwargs):
    """Initialize CryptoAuthLib for the current device"""
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
    if 'i2c' == iface and check_if_rpi():
        cfg.cfg.atcai2c.bus = 1

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

    return dev_name


def read_config(dev_name):
    """Read the device configuration into the appropriate config structure"""
    config_data = bytearray(128)
    assert ATCA_SUCCESS == atcab_read_config_zone(config_data)
    if dev_name == 'ATSHA204A':
        config = Atsha204aConfig.from_buffer(config_data[:88])
    elif dev_name == 'ATECC508A':
        config = Atecc508aConfig.from_buffer(config_data)
    elif dev_name == 'ATECC608A':
        config = Atecc608aConfig.from_buffer(config_data)
    else:
        raise ValueError('Unsupported device {}'.format(dev_name))
    return config


def find_attestation_key_slot(config):
    """Search for a suitable private attestation key."""
    for slot in range(16):
        if not config.KeyConfig[slot].Private:
            continue  # Slot is not a private key
        if config.SlotConfig[slot].ReadKey & 0x03 == 0x02:
            # External sign is disabled (bit 0) and internal sign is enabled (bit 1)
            return slot

    raise RuntimeError('No suitable attestation key found.')


def find_external_key_slot(config):
    """Search for a suitable private key that can perform external signs."""
    for slot in range(16):
        if not config.KeyConfig[slot].Private:
            continue  # Slot is not a private key
        if config.SlotConfig[slot].ReadKey & 0x01 == 0x01:
            # External sign is enabled (bit 0)
            return slot

    raise RuntimeError('No suitable external key found.')


def key_attestation(dev_name, attestation_key_slot, key_slot):
    """Demo the key attestation flow"""

    print('Setup: Establish Trust with Attestation Key')

    wrapper = TextWrapper(width=70, initial_indent='    ',  subsequent_indent='    ')
    print(wrapper.fill(
        'The verifier (entity requesting key attestation) needs to trust the'
        ' attestation key in the device for this process to work. This could'
        ' be as simple as reading and storing the attestation public keys in'
        ' a trusted environment (e.g. during manufacturing). The verifier also'
        ' needs to know the expected configuration and state of the key/slot'
        ' being attested.'
    ))

    print('\n    Reading attestation public key from slot {}:'.format(attestation_key_slot))
    attestation_public_key = bytearray(64)
    assert ATCA_SUCCESS == atcab_get_pubkey(key_id=attestation_key_slot, public_key=attestation_public_key)
    print(convert_ec_pub_to_pem(attestation_public_key))

    print('\n    Read configuration:')
    config = read_config(dev_name)
    print(pretty_print_hex(ctypes_to_bytes(config), indent='    '))

    if config.LockConfig == 0x55:
        raise RuntimeError('Config zone must be locked for this example to run')
    if config.LockValue == 0x55:
        raise RuntimeError('Data zone muct be locked for this example to run')

    print('\nVERIFIER: Send key attestation request')
    print('    Generate verifier challenge/nonce:')
    verifier_nonce = os.urandom(20)
    print(pretty_print_hex(verifier_nonce, indent='    '))


    print('\nDEVICE: Generate key attestation signature')
    print(wrapper.fill(
        'Generate attestation nonce in TempKey from verifier and internal'
        ' device nonces.'
    ))
    device_nonce = bytearray(32)
    assert ATCA_SUCCESS == atcab_nonce_rand(num_in=verifier_nonce, rand_out=device_nonce)
    print('\n    Device nonce:')
    print(pretty_print_hex(device_nonce, indent='    '))

    print('\n' + wrapper.fill(
        'Create a PubKey digest using the GenKey command with the Digest mode'
        ' (0x08). This special mode combines TempKey (attestation nonce) with'
        ' the public key being attested using SHA256 and stores the resulting'
        ' digest back into TempKey.'
    ))
    # Note that other_data is ignored and not required for this mode
    public_key = bytearray(64)
    assert ATCA_SUCCESS == atcab_genkey_base(mode=0x08, key_id=key_slot, other_data=b'\x00'*3, public_key=public_key)
    print('\n    Public key being attested from slot {}:'.format(key_slot))
    print(convert_ec_pub_to_pem(public_key))

    print('\n' + wrapper.fill(
        'Use attestation key to sign (Sign command in internal mode) a message'
        ' including the PubKey digest in TempKey with additional slot/key'
        ' configuration and state information.'
    ))
    signature = bytearray(64)
    assert ATCA_SUCCESS == atcab_sign_internal(
        key_id=attestation_key_slot,
        is_invalidate=False,
        is_full_sn=False,
        signature=signature)
    print('\n    Key attestation signature:')
    print(pretty_print_hex(signature, indent='    '))


    print('\nVERIFIER: Validate key attestation signature')
    print(wrapper.fill(
        'The verifier has now has the data from the device required to'
        ' perform key attestation. This includes the public key being'
        ' attested, device nonce, key/slot configuration and state, and'
        ' attestation signature. The verifier will need to build the'
        ' attestation message from this information and verify it against the'
        ' signature and the trusted attestation public key.'
    ))
    print('\n    Calculate attestation nonce from verifier and device nonces:')
    nonce = calc_nonce(mode=0x00, zero=0x0000, num_in=verifier_nonce, rand_out=device_nonce)
    print(pretty_print_hex(nonce, indent='    '))

    print('\n    Calculate PubKey digest:')
    pubkey_digest = calc_genkey_pubkey_digest(
        mode=0x08,
        key_id=key_slot,
        public_key=public_key,
        temp_key=nonce,
        sn=ctypes_to_bytes(config.SN03) + ctypes_to_bytes(config.SN48)
    )
    print(pretty_print_hex(pubkey_digest, indent='    '))

    print('\n    Calculate the internal sign message digest:')
    msg_digest = calc_sign_internal_digest(
        mode=0x00,
        key_id=attestation_key_slot,
        temp_key=pubkey_digest,
        temp_key_key_id=key_slot,
        temp_key_source_flag=0,  # Device nonce in internally generated random number
        temp_key_gendig_data=False,
        temp_key_genkey_data=True,
        temp_key_no_mac=False,
        config=config
    )
    print(pretty_print_hex(msg_digest, indent='    '))

    print('\n    Verifying signature:')

    attestation_public_key = ec.EllipticCurvePublicNumbers(
        curve=ec.SECP256R1(),
        x=int_from_bytes(attestation_public_key[0:32], byteorder='big'),
        y=int_from_bytes(attestation_public_key[32:64], byteorder='big'),
    ).public_key(default_backend())

    r = int_from_bytes(signature[0:32], byteorder='big', signed=False)
    s = int_from_bytes(signature[32:64], byteorder='big', signed=False)
    attestation_public_key.verify(
        signature=utils.encode_dss_signature(r, s),
        data=msg_digest,
        signature_algorithm=ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )
    print('    SUCCESS! Key has been attested.')


def calc_nonce(mode, zero, num_in, rand_out=None, temp_key=None):
    """Replicate the internal TempKey calculations of the Nonce command"""
    if mode == 0x03:
        # Passthrough mode
        if len(num_in) != 32:
            raise ValueError('num_in must be 32 bytes')
        return copy.copy(num_in)
    elif mode == 0x00 or mode == 0x01:
        # Random mode
        if len(rand_out) != 32:
            raise ValueError('rand_out must be 32 bytes')
        if len(num_in) != 20:
            raise ValueError('num_in must be 20 bytes')
        msg = b''
        msg += rand_out
        msg += num_in
        msg += b'\x16'  # Nonce Opcode
        msg += struct.pack("B", mode)
        msg += struct.pack("<H", zero)[:1]

        return sha256(msg).digest()
    else:
        raise BadArgumentError('Unsupported or invalid mode 0x{:02X}'.format(mode))


def calc_genkey_pubkey_digest(mode, key_id, public_key, temp_key, sn, other_data=None):
    """
    Replicate the internal TempKey calculations of the GenKey command in
    digest mode.
    """
    if len(public_key) != 64:
        raise ValueError('public_key must be 64 bytes')
    if len(temp_key) != 32:
        raise ValueError('temp_key must be 32 bytes')
    msg = b''
    msg += temp_key
    msg += b'\x40'  # GenKey Opcode
    if mode & 0x10:
        # Slot is storing a public key directly, use OtherData for Mode and KeyID
        if len(other_data) != 3:
            raise ValueError('other_data must be 3 bytes')
        msg += other_data
    else:
        # Slot is storing a private key and the public key is generated
        msg += struct.pack("B", mode)
        msg += struct.pack("<H", key_id)
    msg += sn[8:9]
    msg += sn[0:2]
    msg += b'\x00'*25
    msg += public_key

    return sha256(msg).digest()


def calc_sign_internal_digest(mode, key_id, temp_key, temp_key_key_id, temp_key_source_flag, temp_key_gendig_data,
                              temp_key_genkey_data, temp_key_no_mac, config, for_invalidate=False):
    """
    Replicate the internal message digest calculations of the Sign command in
    sign internal mode.
    """
    # TODO: Doesn't work for ATECC108A
    if mode & 0x80:
        raise ValueError('Invalid mode, not internal sign')
    if len(temp_key) != 32:
        raise ValueError('temp_key must be 32 bytes')
    msg = b''
    msg += temp_key
    msg += b'\x41'  # Sign Opcode
    msg += struct.pack('B', mode)
    msg += struct.pack('<H', key_id)
    msg += ctypes_to_bytes(config.SlotConfig[temp_key_key_id])
    msg += ctypes_to_bytes(config.KeyConfig[temp_key_key_id])
    temp_key_flags = 0
    if temp_key_key_id < 0 or temp_key_key_id > 15:
        raise ValueError('temp_key_key_id must be 0 to 15')
    if temp_key_gendig_data and temp_key_genkey_data:
        raise ValueError(
            'temp_key_gendig_data and temp_key_genkey_data are mutually exclusive and both can not be true'
        )
    temp_key_flags += temp_key_key_id
    temp_key_flags += (1 << 4) if temp_key_source_flag else 0
    temp_key_flags += (1 << 5) if temp_key_gendig_data else 0
    temp_key_flags += (1 << 6) if temp_key_genkey_data else 0
    temp_key_flags += (1 << 7) if temp_key_no_mac else 0
    msg += struct.pack('B', temp_key_flags)
    msg += b'\x00'*2
    is_full_sn = bool(mode & 0x40)
    sn = ctypes_to_bytes(config.SN03) + ctypes_to_bytes(config.SN48)
    msg += sn[8:9]
    msg += sn[4:8] if is_full_sn else b'\x00'*4
    msg += sn[0:2]
    msg += sn[2:4] if is_full_sn else b'\x00'*2
    msg += b'\x01' if config.SlotLocked & (1 << temp_key_key_id) else b'\x00'
    msg += b'\x01' if for_invalidate else b'\x00'
    msg += b'\x00'

    return sha256(msg).digest()


if __name__ == '__main__':
    parser = setup_example_runner(__file__)
    parser.add_argument(
        '-a',
        '--attestation-key',
        help='Slot of the attestation key. If omitted, a suitable key will be searched for.',
        default=None,
        type=int
    )
    parser.add_argument(
        '-k',
        '--key',
        help='Slot of the key being attested. If omitted, a suitable key will be searched for.',
        default=None,
        type=int
    )
    args = parser.parse_args()

    dev_name = init_device(args.iface, **parse_interface_params(args.params))

    if 'ECC' not in dev_name:
        raise RuntimeError('Unsupported device {}'.format(dev_name))

    config = None

    if args.attestation_key is None:
        if config is None:
            config = read_config(dev_name)
        args.attestation_key = find_attestation_key_slot(config)

    if args.key is None:
        if config is None:
            config = read_config(dev_name)
        args.key = find_external_key_slot(config)

    key_attestation(dev_name=dev_name, attestation_key_slot=args.attestation_key, key_slot=args.key)


