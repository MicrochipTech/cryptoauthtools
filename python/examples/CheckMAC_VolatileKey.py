"""
Example of Volatile key and few other common use cases
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
import cryptography
# from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Can be used to program a device for testing purposes

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!  Persistent Latch test 1
# ATECC608A minus the first 16 bytes which are fixed by the factory
# Example v1 configuration
_atecc608_config = bytearray.fromhex(
    'C0 00 00 00 8F 20 C5 80  83 80 C5 85 93 8F 8F 80'
    '00 00 00 00 00 00 00 00  0F 0F 0F 0F 0F 0F 00 00'
    '0F 0F 00 00 FF FF FF FF  00 00 00 00 FF FF FF FF'
    '00 00 00 00 00 82 00 00  00 00 00 00 00 00 00 00'
    '00 00 00 00 00 00 00 00  FF FF 00 00 00 00 00 00'
    '33 00 3C 10 7C 00 1C 00  1C 00 3C 00 1C 00 1C 00'
    '1C 00 1C 00 3C 00 30 00  3C 00 1C 00 3C 00 1C 00')

_configs = {'ATECC608A': _atecc608_config }

ATCA_SUCCESS = 0x00	
SN_8 = 0xEE
SN_0 = 0x01
SN_1 = 0x23

sup_device_name = 'ATECC608A'
slot_to_mac = 0x02  # VolatileKeyPermitSlot	 
slot_display = 0x01 # Display State Key - latched	
slot_ecc_device = 0x00 # Device Private Key ECC (secret)
slot_cloud = 0x03 # Another Cloud TLS Passphrase example 
slot_encrypt = 0x05 # to be used for ecrypted reads of slot 1 and 3
slot_parent = 0x04  # potentially needed to create the "random diversified key for cloud"
# other slots are included to store certificates and chain keys, all can be read and written in clear

# slot_to_mac key content
# The key below is an example of 128bit key and padding 0's to reach 256, just an example
VOL_KEY = bytearray([
    0x01, 0x23, 0x45, 0x67, 0x89, 0x10, 0x11, 0x12,
    0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
])

# slot_display and slot_encrypt and slot_parent key content
DISP_KEY = bytearray([
    0x01, 0x23, 0x45, 0x67, 0x89, 0x10, 0x11, 0x12,
    0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36
])

#slot_cloud is going to be filled with a random number

# Safe input if using python 2
try: input = raw_input
except NameError: pass


def configure_device(iface='hid', device='ecc', i2c_addr=None, keygen=True, **kwargs):

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
    print('\nProgram Configuration (if not locked)')
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
        
        print(pretty_print_hex(config, indent=' '))
        # Write configuration
        assert ATCA_SUCCESS == atcab_write_bytes_zone(0, 0, 16, config, len(config))
        print('        Success')

        # Verify Config Zone
        print('    Verifying Configuration')
        config_qa = bytearray(len(config))
        atcab_read_bytes_zone(0, 0, 16, config_qa, len(config_qa))
        print(pretty_print_hex(config_qa, indent=' '))
		
        #if config_qa != config:
        #    raise ValueError('Configuration read from the device does not match')
        #print('        Success')
        
        print('\n    Do You want to lock the config zone?')
        if 'Y' != input('    Lock config-zone (Y/N): '):
                print('    Config zone NOT locked')
        else :
            print('    Locking Configuration')
            assert ATCA_SUCCESS == atcab_lock_config_zone()
            print('        Locked')
    else:
        print('    Locked, skipping')
    
    atcab_release()

def write_device(iface='hid', device='ecc', **kwargs):
    # writing the data zone according to the configuration
    
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

	# Check the zone locks
    print('\nReading the Lock Status')
    is_locked = AtcaReference(False)
    assert ATCA_SUCCESS == atcab_is_locked(0, is_locked)
    config_zone_lock = bool(is_locked.value)

    assert ATCA_SUCCESS == atcab_is_locked(1, is_locked)
    data_zone_lock = bool(is_locked.value)

    print('    Config Zone: {}'.format('Locked' if config_zone_lock else 'Unlocked'))
    print('    Data Zone: {}'.format('Locked' if data_zone_lock else 'Unlocked'))
	 
	#	-------------------------------
	# WRITING data in the slots

    # Writing a data to slot
    #slot_to_mac = 0x02  # VolatileKeyPermitSlot	aka Intrusion Detect Re-enablement 
    print('\nWrite commands:')
    print('    Writing data to slot {:02X}'.format(slot_to_mac))
    if atcab_write_zone(2, slot_to_mac, 0, 0, VOL_KEY, 32) == ATCA_SUCCESS:
        print('    Write Success')
    else:
        print('    Write failed')
    if atcab_lock_data_slot(slot_to_mac) == ATCA_SUCCESS:
        print('    Slot locked')
 
    #slot_display = 0x01 # Display State Key - will be latched
    print('    Writing data to slot {:02X}'.format(slot_display))
    if atcab_write_zone(2, slot_display, 0, 0, DISP_KEY, 32) == ATCA_SUCCESS:
        print('    Write Success')
    else:
        print('    Write failed')
    if atcab_lock_data_slot(slot_display) == ATCA_SUCCESS:
        print('    Slot locked')
    
    #slot_cloud = 0x03 # Cloud TLS Cert Passphrase 
    write_data = bytearray(32)
    print('\nGeneraing data using RAND command')
    assert atcab_random(write_data) == ATCA_SUCCESS
    print('    Generated data:')
    print(pretty_print_hex(write_data, indent='        '))
    print('    Writing data to slot {:02X}'.format(slot_cloud))
    if atcab_write_zone(2, slot_cloud, 0, 0, write_data, 32) == ATCA_SUCCESS:
        print('    Write Success')
    else:
        print('    Write failed')
    
    #slot_encrypt = 0x05 # to be used for ecrypted reads of slot 1 and 3
    print('    Writing data to slot {:02X}'.format(slot_encrypt))
    if atcab_write_zone(2, slot_encrypt, 0, 0, DISP_KEY, 32) == ATCA_SUCCESS:
        print('    Write Success')
    else:
        print('    Write failed')
    if atcab_lock_data_slot(slot_encrypt) == ATCA_SUCCESS:
        print('    Slot locked')
    
    #slot_parent = 0x04  # potentially needed to create the "randome diversified key for cloud"    
    print('    Writing data to slot {:02X}'.format(slot_parent))
    if atcab_write_zone(2, slot_parent, 0, 0, DISP_KEY, 32) == ATCA_SUCCESS:
        print('    Write Success')
    else:
        print('    Write failed')
        
	# Check data zone lock
    print('\nActivating Configuration')
    if not data_zone_lock:
        # Lock the data zone
        print('\n    Do You want to lock the data zone?')
        if 'Y' != input('    Lock data-zone (Y/N): '):
                print('    Data zone NOT locked')
        else:
            assert ATCA_SUCCESS == atcab_lock_data_zone()
            print('    Data zone locked and Activated')
    else:
        print('    Already Active')

    print('\nGenerating New Keys')
    pubkey = bytearray(64)
    assert ATCA_SUCCESS == atcab_genkey(0, pubkey)
    print('    Key 0 Success:')
    print(pretty_print_hex(pubkey, indent='    '))
	
    # Free the library
    atcab_release()


def test_device(iface='hid', device='ecc', **kwargs):
    # testing and performing some examples

    result = ATCA_SUCCESS
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
    
    if dev_name != sup_device_name:
        raise ValueError('No valid script for {}'.format(dev_name))	
	
	# Check the zone locks
    print('\nReading the Lock Status')
    is_locked = AtcaReference(False)
    assert ATCA_SUCCESS == atcab_is_locked(0, is_locked)
    config_zone_lock = bool(is_locked.value)

    assert ATCA_SUCCESS == atcab_is_locked(1, is_locked)
    data_zone_lock = bool(is_locked.value)

    print('    Config Zone: {}'.format('Locked' if config_zone_lock else 'Unlocked'))
    print('    Data Zone: {}'.format('Locked' if data_zone_lock else 'Unlocked'))
	
    # Request the Serial Number
    serial_number = bytearray(9)
    assert atcab_read_serial_number(serial_number) == ATCA_SUCCESS
    print('\nSerial number: ')
    print(pretty_print_hex(serial_number, indent='    '))
    
    rand_out = bytearray(32)
    challenge = bytearray(32)
    digest_output = bytearray(32)
    host_to_be_hashed = bytearray (0)
    host_digest_output = bytearray(32)
    
    
    # -------------------------------
    # DEMO OF VOLATILE KEY and Persistent latch
    # -------------------------------
    print('\nVOLATILE KEY AND PERSISTENT LATCH EXAMPLE')        
    
    # Reading slot_display key through encrypted read (slot_encrypt), works even if latched
    print('\nEncrypted Read Command on slot {:}'.format(slot_display))
    slot_read_data = bytearray(32)
    if atcab_read_enc(slot_display, 0, slot_read_data, DISP_KEY, slot_encrypt) == ATCA_SUCCESS:
        print('    Read Success from slot {:}'.format(slot_display))
        print('    Read data:')
        print(pretty_print_hex(slot_read_data, indent='        '))
    else:
        print('    Read failed!')
    
    # MAC command using the cryptochip
    # slot_display key, SHALL fail if latch is NOT set
    challenge = os.urandom(20)
    print('\nMAC command:')
    print('    MAC computation using Slot {:02X}'.format(slot_display))
    mode = 0x00 # NONCE_MODE_SEED_UPDATE
    result = atcab_nonce_rand(challenge[:20], rand_out)
    if result != ATCA_SUCCESS:
        print('    NONCE result: '.format(result))
    mode = 0x41   
    # 0100 0001
    # <7> = 0 - <6> = 1 to include SN - <5-3> = 0 - <2> = [0 = Rand] TempKey.SourceFlag - <1> = [0 Dataslot / 1 Tempkey] - <0> = [0 challenge / 1 Tempkey] - ref. Table 11-30
    result = atcab_mac(mode, slot_display, challenge, digest_output)
    if result != ATCA_SUCCESS:
        print('    ERROR result: {:02X} -- Volatile key disabled by latch'.format(result))
    else:
        print('    Volatile key enabled by latch, MAC result:')
        print(pretty_print_hex(digest_output, indent='        '))
    
    # Get the State of the persistent latch
    print('\nCHECKING PERSISTENT LATCH value')
    persistent_latch_state = AtcaReference(0)
    result = atcab_info_get_latch(persistent_latch_state)
    if result != ATCA_SUCCESS:
        print('    Info get latch error: {:}'.format(result))
    print('    PERSISTENT LATCH state: {:}'.format(persistent_latch_state))
    #persistent latch to be set
    print('\nTRYING to SET THE LATCH')
    persistent_latch_state = AtcaReference(1)
    result = atcab_info_set_latch(persistent_latch_state); 
    if result != ATCA_SUCCESS:
        print('    Info set latch error: {:02X}'.format(result))
    else:
        print('    Persistent latch is set')
        
    print('\nCHECKMAC COMMAND to SET THE LATCH')

    # KeyConfig[slot_to_mac].ReqRandom is one, a NONCE is required for checkMAC and the RNG must have been used
    # NONCE needed before MAC
    print('\nExecuting NONCE command')
    # NOTE: The input value is designed to prevent replay attacks against the host, and it must be externally generated by the system
    print('\nGeneraing data using OS host command')
    challenge = os.urandom(20)
    print('    Generated data (RND of the host):')
    print(pretty_print_hex(challenge, indent='        '))
    mode = 0x00 # NONCE_MODE_SEED_UPDATE
    result = atcab_nonce_rand(challenge[:20], rand_out)
    if result != ATCA_SUCCESS:
        print('    NONCE result: '.format(result))
    print('    Generated data (output of the RNG):')
    print(pretty_print_hex(rand_out, indent='        '))
    # Now Tepmkey is valid and TempKey.SourceFlag is Rand (0). 
    # Calculate what's stored on Tempkey by performing the same SHA-256 on host side (ref. 11.12 of datasheet)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    host_to_be_hashed = bytearray()
    host_to_be_hashed.extend(rand_out)
    host_to_be_hashed.extend(challenge[:20])
    host_to_be_hashed.extend([0x16])
    host_to_be_hashed.extend([mode])
    host_to_be_hashed.extend([0x00])
    print('    Data to be hashed on HOST side to compute THE SAME NONCE currently in TempKey:')
    print(pretty_print_hex(host_to_be_hashed, indent='        '))
    digest.update(bytes(host_to_be_hashed))
    rand_out = digest.finalize()
    print('    HOST NONCE result (currently is stored in TempKey):')
    print(pretty_print_hex(rand_out, indent='        '))
    
    # -------------------------------
    # EXAMPLE CheckMAC on Slot {slot_to_mac} to enable Persistent latch
    # -------------------------------
        
    other_data = bytearray([0x08, mode, slot_to_mac, 0x00, 0x00, 0x00, 0x00, serial_number[4], 
        serial_number[5], serial_number[6], serial_number[7], serial_number[2], serial_number[3]])
    #other_data = bytearray([0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC])
    print('    Other DATA array:')
    print(pretty_print_hex(other_data, indent='        '))
    
    mode = 0x01 #CHECKMAC_MODE_BLOCK2_TEMPKEY
    print('\nComputing the MAC using standard SHA-256 on host side (without cryptochip)')
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    host_to_be_hashed = bytearray()
    host_to_be_hashed.extend(VOL_KEY)
    host_to_be_hashed.extend(rand_out)
    host_to_be_hashed.extend(other_data[0:4])   # checkMAC specific
    host_to_be_hashed.extend([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])   # checkMAC specific
    host_to_be_hashed.extend(other_data[4:7])  # checkMAC specific
    host_to_be_hashed.extend([SN_8])
    host_to_be_hashed.extend(other_data[7:11])  # checkMAC specific
    host_to_be_hashed.extend([SN_0, SN_1])
    host_to_be_hashed.extend(other_data[11:13])  # checkMAC specific
    print('    Data to be hashed:')
    print(pretty_print_hex(host_to_be_hashed, indent='        '))
    
    digest.update(bytes(host_to_be_hashed))
    host_digest_output = digest.finalize()
    print('    HOST MAC result:')
    print(pretty_print_hex(host_digest_output, indent='        '))
    
    # CheckMAC command
    other_array = bytearray(32)
    # CheckMAC mode [0000 0001]
    mode = 0x01 # CHECKMAC_MODE_BLOCK2_TEMPKEY
    result = ATCA_SUCCESS
    #result = atcab_checkmac(mode, slot_to_mac, rand_out, host_digest_output, other_data) # NOTE rand_out is not used!!!!
    result = atcab_checkmac(1, 2, other_array, host_digest_output, other_data)
    if result == ATCA_SUCCESS:
        print('CheckMAC passed!')
    else:
        print('    checkmac error: {:02X}'.format(result))
    
    #persistent latch to be set
    persistent_latch_state = AtcaReference(1)
    result = atcab_info_set_latch(persistent_latch_state); 
    if result != ATCA_SUCCESS:
        print('    Info set latch error: {:}'.format(result))
    else:
        print('    Persistent latch is set')
    result = atcab_info_get_latch(persistent_latch_state)
    if result != ATCA_SUCCESS:
        print('    Info get latch error: {:}'.format(result))
    print('    PERSISTENT LATCH state: {:}'.format(persistent_latch_state))
    
    # Reading slot_display key through encrypted read (slot_encrypt), works regardless the latch status
    print('\nEncrypted Read Command on slot {:}'.format(slot_display))
    slot_read_data = bytearray(32)
    if atcab_read_enc(slot_display, 0, slot_read_data, DISP_KEY, slot_encrypt) == ATCA_SUCCESS:
        print('    Read Success from slot {:}'.format(slot_display))
        print('    Read data:')
        print(pretty_print_hex(slot_read_data, indent='        '))
    else:
        print('    Read failed!')
    
    # MAC command using the cryptochip
    # slot_display key, SHALL fail if latch is NOT set
    rand_out = bytearray(32)
    challenge = bytearray(32)
    digest_output = bytearray(32)
    challenge = os.urandom(20)
    print('\nMAC command:')
    print('    MAC computation using Slot {:02X}'.format(slot_display))
    mode = 0x00 # NONCE_MODE_SEED_UPDATE
    result = atcab_nonce_rand(challenge[:20], rand_out)
    if result != ATCA_SUCCESS:
        print('    NONCE result: '.format(result))
    mode = 0x41   
    # 0100 0001
    # <7> = 0 - <6> = 1 to include SN - <5-3> = 0 - <2> = [0 = Rand] TempKey.SourceFlag - <1> = [0 Dataslot / 1 Tempkey] - <0> = [0 challenge / 1 Tempkey] - ref. Table 11-30
    result = atcab_mac(mode, slot_display, challenge, digest_output)
    if result != ATCA_SUCCESS:
        print('    ERROR result: {:02X} -- Volatile key disabled by latch'.format(result))
    else:
        print('    Volatile key enabled by latch, MAC result:')
        print(pretty_print_hex(digest_output, indent='        '))
    
    print('\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -') 
    
    # ------------------------------------------------------------------------------
	# EXAMPLE OF MAC calculation on Slot {slot_encrypt} with device and on HOST side
    # ------------------------------------------------------------------------------
    rand_out = bytearray(32)
    challenge = bytearray(32)
    digest_output = bytearray(32)
    host_to_be_hashed = bytearray (0)
    host_digest_output = bytearray(32)
    
    print('\nEXAMPLE OF MAC ON DEVICE AND ON HOST SIDE')
    # 20bytes input for NONCE
    print('\nGeneraing data using OS host command')
    challenge = os.urandom(20)
    # Below an alternative way to generate the challenge using ATECC608, 
    # BUT to prevent replay attacks it is better to generate the random on host (or cloud) side!
    #print('\nGeneraing data using ATECC608A RAND command')
    #assert atcab_random(challenge) == ATCA_SUCCESS
    print('    Generated data:')
    print(pretty_print_hex(challenge, indent='        '))
        
    # NONCE needed before MAC
    print('\nExecuting NONCE command')
    # NOTE: The input value is designed to prevent replay attacks against the host, and it must be externally generated by the system
    mode = 0x00
    zero = 0x0000
    result = atcab_nonce_base(mode, zero, challenge[:20], rand_out)
    if result != ATCA_SUCCESS:
        print('    NONCE result: {:02X}'.format(result))
    print('    Generated data (output of the RNG):')
    print(pretty_print_hex(rand_out, indent='        '))
    # Now Tepmkey is valid and TempKey.SourceFlag is Rand (0). 
    # Calculate what's stored on Tempkey by performing the same SHA-256 on host side (ref. 11.12 of datasheet)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    host_to_be_hashed = bytearray()
    host_to_be_hashed.extend(rand_out)
    host_to_be_hashed.extend(challenge[:20])
    host_to_be_hashed.extend([0x16])
    host_to_be_hashed.extend([mode])
    host_to_be_hashed.extend([0x00])
    print('    Data to be hashed on HOST side to compute THE SAME NONCE currently in TempKey:')
    print(pretty_print_hex(host_to_be_hashed, indent='        '))
    digest.update(bytes(host_to_be_hashed))
    rand_out = digest.finalize()
    print('    HOST NONCE result:')
    print(pretty_print_hex(rand_out, indent='        '))
    
    # MAC command using the cryptochip
    print('\nMAC command:')
    print('    MAC computation using Slot {:02X}'.format(slot_encrypt))
    mode = 0x41   
    # 0100 0001
    # <7> = 0 - <6> = 1 to include SN - <5-3> = 0 - <2> = [0 = Rand] TempKey.SourceFlag - <1> = [0 Dataslot / 1 Tempkey] - <0> = [0 challenge / 1 Tempkey] - ref. Table 11-30
    result = atcab_mac(mode, slot_encrypt, challenge, digest_output)
    if result != ATCA_SUCCESS:
        print('    ERROR result: {:02X}'.format(result))
    print('    MAC result:')
    print(pretty_print_hex(digest_output, indent='        '))
    
    # Computing the SAME MAC using standard SHA-256 on host side (without cryptochip)
    print('\nExecuting the SAME MAC using standard SHA-256 on host side (without cryptochip)')
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    host_to_be_hashed = bytearray()
    host_to_be_hashed.extend(DISP_KEY)
    host_to_be_hashed.extend(rand_out)
    host_to_be_hashed.extend([0x08])
    host_to_be_hashed.extend([mode])
    host_to_be_hashed.extend([slot_encrypt, 0x00]) # slot_to_mac, NOTE THE bytes swap!!!
    host_to_be_hashed.extend([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    host_to_be_hashed.extend([SN_8])
    host_to_be_hashed.extend(serial_number[4:8])
    host_to_be_hashed.extend([SN_0, SN_1])
    host_to_be_hashed.extend(serial_number[2:4])
    print('    Data to be hashed:')
    print(pretty_print_hex(host_to_be_hashed, indent='        '))
    
    digest.update(bytes(host_to_be_hashed))
    host_digest_output = digest.finalize()
    print('    HOST MAC result:')
    print(pretty_print_hex(host_digest_output, indent='        '))
    
    if host_digest_output == digest_output:
        print('\nHost implementation matches the ATECCx08A implementation of the MAC command!')
    print('\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -') 
    
    # Free the library
    atcab_release()
    
    
if __name__ == '__main__':
    parser = setup_example_runner(__file__)
    parser.add_argument('--i2c', help='I2C Address (in hex)')
    parser.add_argument('--gen', default=True, help='Generate new keys')
    args = parser.parse_args()

    if args.i2c is not None:
        args.i2c = int(args.i2c, 16)
    
    print('\n    MENU:')
    print('\n        1 - Configure device and lock config zone')
    print('        2 - wite data zone (configuration shall be locked)')
    print('        3 - Perform crypto operations')
    choice = input('\n    choose option: ')
    if choice == '1':
        print('\nConfiguring the device with the configuration included in the script')
        configure_device(args.iface, args.device, args.i2c, args.gen, **parse_interface_params(args.params))
    if choice == '2':
        print('\nwriting data zone, see the script for details')
        write_device(args.iface, args.device, **parse_interface_params(args.params))
    if choice == '3':
        print('\nperforming some crypto operations')
        test_device(args.iface, args.device, **parse_interface_params(args.params))
    print('\nDONE')
