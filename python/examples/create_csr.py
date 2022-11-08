"""
Example of CSR Creation for a Device
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

# Certificate handling dependencies
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from ctypes import POINTER, c_uint8, create_string_buffer

# Python 2/3 switch
try:
    to_unicode = unicode
except NameError:
    to_unicode = str

# This was generated from a template and the offsets extracted from it. Do not modify
ATCACERT_DEF_CSR_SUBJECT_LENGTH = 49
ATCACERT_DEF_CSR = {
    'type': atcacert_cert_type_t.CERTTYPE_X509,
    'template_id': 2,
    'chain_id': 0,
    'private_key_slot': 0,
    'sn_source': atcacert_cert_sn_src_t.SNSRC_PUB_KEY_HASH,
    'cert_sn_dev_loc': { 
        'zone': atcacert_device_zone_t.DEVZONE_NONE,
        'slot': 0,
        'is_genkey': 0,
        'offset': 0,
        'count': 0,
    },
    'issue_date_format': atcacert_date_format_t.DATEFMT_RFC5280_UTC,
    'expire_date_format': atcacert_date_format_t.DATEFMT_RFC5280_UTC,
    'tbs_cert_loc': {
        'offset': 3,
        'count': 165
    },
    'expire_years': 0,
    'public_key_dev_loc': {
        'zone': atcacert_device_zone_t.DEVZONE_NONE,
        'slot': 0,
        'is_genkey': 1,
        'offset': 0,
        'count': 64
    },
    'comp_cert_dev_loc': {
        'zone': atcacert_device_zone_t.DEVZONE_NONE,
        'slot': 0,
        'is_genkey': 0,
        'offset': 0,
        'count': 0
    },
    'std_cert_elements': [
        { 'offset': 85, 'count': 64 },
        { 'offset': 180, 'count': 74 },
        { 'offset': 0, 'count':  0 },
        { 'offset': 0, 'count':  0 },
        { 'offset': 0, 'count':  0 },
        { 'offset': 0, 'count':  0 },
        { 'offset': 0, 'count':  0 },
        { 'offset': 0, 'count':  0 }
    ]
}


def info(iface='hid', device='ecc', **kwargs):
    ATCA_SUCCESS = 0x00

    # Get the target default config
    cfg = eval('cfg_at{}a_{}_default()'.format(atca_names_map.get(device), atca_names_map.get(iface)))

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
    print('')

    # Load the device serial number
    sernum = bytearray(9)
    assert 0 == atcab_read_serial_number(sernum)
    sernum = ''.join(['%02X' % n for n in sernum])

    # Create the Certificate Subject Name
    subj_name = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u'Microchip Technology Inc'),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, to_unicode(sernum))])

    # Create a dummy private key for building the CSR template
    pkey = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Create a CSR builder
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subj_name)

    # Finalize the CSR by signing it with the dummy private key
    csr_template = builder.sign(pkey, hashes.SHA256(), default_backend())

    # Convert to a template 
    atcacert_def_csr_template = bytearray(csr_template.public_bytes(serialization.Encoding.DER))

    # Calculate the new offsets
    length_delta = int(((len(atcacert_def_csr_template) - 3).bit_length() - 1) / 8)    # Outer tag: is a minimum of 3 bytes
    subject_delta = len(subj_name.public_bytes(default_backend())) - ATCACERT_DEF_CSR_SUBJECT_LENGTH

    # Update Offsets in the definition
    ATCACERT_DEF_CSR['tbs_cert_loc']['offset'] += length_delta
    ATCACERT_DEF_CSR['tbs_cert_loc']['count'] += subject_delta
    for x in ATCACERT_DEF_CSR['std_cert_elements']:
        if x['offset'] > 0:
            x['offset'] = x['offset'] + subject_delta + length_delta

    # Create a certificate definition structure
    csr_def = atcacert_def_t(**ATCACERT_DEF_CSR)

    # Attach the generated template with the updated subject name
    csr_def.cert_template_size = len(atcacert_def_csr_template)
    csr_def.cert_template = POINTER(c_uint8)(create_string_buffer(bytes(atcacert_def_csr_template), csr_def.cert_template_size))

    # Create a CSR based on the definition provided
    csr = bytearray(len(atcacert_def_csr_template)+8)
    csr_size = AtcaReference(len(csr))
    assert 0 == atcacert_create_csr(csr_def, csr, csr_size)

    # Encode the CSR in the expect format (PEM)
    csr_pem = base64.b64encode(csr).decode('ascii')
    csr_pem = ''.join(csr_pem[i:i+64] + '\n' for i in range(0,len(csr_pem),64))
    csr_pem = '-----BEGIN CERTIFICATE REQUEST-----\n' + csr_pem + '-----END CERTIFICATE REQUEST-----\n'

    print(csr_pem)

    # Free the library
    atcab_release()


if __name__ == '__main__':
    parser = setup_example_runner(__file__)
    args = parser.parse_args()

    info(args.iface, args.device, **parse_interface_params(args.params))
    print('\nDone')










