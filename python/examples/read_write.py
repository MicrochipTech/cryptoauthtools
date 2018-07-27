from cryptoauthlib import *
from common import *
import binascii

# Slot 4 IO Encryption key
ENC_KEY = bytearray([
    0x37, 0x80, 0xe6, 0x3d, 0x49, 0x68, 0xad, 0xe5,
    0xd8, 0x22, 0xc0, 0x13, 0xfc, 0xc3, 0x23, 0x84,
    0x5d, 0x1b, 0x56, 0x9f, 0xe7, 0x05, 0xb6, 0x00,
    0x06, 0xfe, 0xec, 0x14, 0x5a, 0x0d, 0xb1, 0xe3
])

def read_write():
    # Loading cryptoauthlib(python specific)
    load_cryptoauthlib()

    print("\n Basic Read/Write Example")

    device = input("\n Choose the device:\n1 - ECC608\n2 - ECC508\n3 - SHA204\n")
    #print(device)
    #print(type(device))
    if device in ("ECC508", "ECC608", "ecc508", "ecc608", "1", "2"):
        clear_read__write_slot = 10
        enc_read_write_slot = 8
        IO_key_slot = 4
    elif device in ("SHA204", "sha204", "3"):
        clear_read__write_slot = 8
        enc_read_write_slot = 3
        IO_key_slot = 4
    else:
        print("Device name invalid")
        exit()

    # Initialize the library
    atcab_init()

    ATCA_SUCCESS = 0x00

    # Reading device serial number
    print("\n Reading device serial number")
    serial_number = bytearray(9)
    assert atcab_read_serial_number(serial_number) == ATCA_SUCCESS
    print(" Serial number - ", binascii.hexlify(serial_number))

    # Reading device revision
    print("\n Reading device revision")
    revision = bytearray(4)
    assert atcab_info(revision) == ATCA_SUCCESS
    print(" Revision - ", binascii.hexlify(revision))

    # Writing a key to slot
    print("\n Write command:")
    print(" Generaing a key using RAND command")
    slotkey = bytearray(32)
    # Generating a random number, using that as the slot 10 key
    assert atcab_random(slotkey) == ATCA_SUCCESS
    print(" Generated key - ", binascii.hexlify(slotkey))
    print(" Writing generated key to slot ", clear_read__write_slot)
    assert atcab_write_zone(2, clear_read__write_slot, 0, 0, slotkey, 32) == ATCA_SUCCESS
    print(" Write Success")

    # Reading the key in plain text from slot
    print("\n Read command:")
    print(" Reading key stored in slot ", clear_read__write_slot)
    key = bytearray(32)
    assert atcab_read_zone(2, clear_read__write_slot, 0, 0, key, 32) == ATCA_SUCCESS
    print(" Slot key - ", binascii.hexlify(key))

    # Writing IO protection key. This key is used as IO encryption key.
    assert atcab_write_zone(2, IO_key_slot, 0, 0, ENC_KEY, 32) == ATCA_SUCCESS

    # Writing a key to slot '1' through encrypted write
    print("\n Encrypted Write:")
    print(" Generaing a key using RAND command")
    slotkey = bytearray(32)
    # Generating a random number, using that as the slot 8 key
    assert atcab_random(slotkey) == ATCA_SUCCESS
    print(" Generated key - ", binascii.hexlify(slotkey))
    print(" Writing generated key to slot '8' through encrypted write command")
    assert atcab_write_enc(enc_read_write_slot, 0, slotkey, ENC_KEY, IO_key_slot) == ATCA_SUCCESS

    # Reading the key in plain text from slot '10'
    print("\n Encrypted Read :")
    print(" Reading key stored in slot '8' through encrypted read command")
    key = bytearray(32)
    assert atcab_read_enc(enc_read_write_slot, 0, key, ENC_KEY, IO_key_slot) == ATCA_SUCCESS
    print(" Slot 8 key - ", binascii.hexlify(key))

    # Free the library
    atcab_release()

if __name__ == '__main__':
    parser = setup_example_runner(__file__)
    args = parser.parse_args()

    read_write()
