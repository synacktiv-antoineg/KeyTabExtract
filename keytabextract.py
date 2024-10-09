#!/usr/bin/env python3
import binascii,sys,datetime

# Take argument 1 as keytab file, import and decode the hex
ktfile = sys.argv[1]
f = open(ktfile, 'rb').read()
hex_encoded = binascii.hexlify(f).decode('utf-8')

TYPES = {"0017":"NTLM", "0011":"AES-128", "0012":"AES-256"}
all_data = dict()


def displayhelp():
    print("KeyTabExtract. Extract NTLM Hashes from KeyTab files where RC4-HMAC encryption has been used.")
    print("Usage : ./keytabextract.py [keytabfile]")
    print("Example : ./keytabextract.py service.keytab")

def entryextract(pointer):
    # Number of counted octet strings representing the realm of the principal
    num_components = int(hex_encoded[pointer:pointer+4], 16)

    # convert the 
    num_realm = int(hex_encoded[pointer+4:pointer+8], 16)

    # calculate the offset for the realm
    realm_jump = pointer+8 + (num_realm * 2)

    # Determine the realm for the keytab file
    realm = hex_encoded[pointer+8:realm_jump]
    realm = bytes.fromhex(realm).decode('utf-8')
    
    components = []
    comp_start = realm_jump
    comp_end = comp_start
    for _ in range(num_components):
        # Calculate the number of bytes for the realm of components
        comp_len = int(hex_encoded[comp_start:comp_start+4], 16)

        # Calculates the realm component (HTTP)
        comp_end = comp_start+4 + (comp_len * 2)
        components.append(hex_encoded[comp_start+4:comp_end])
        comp_start = comp_end

    components = [bytes.fromhex(x).decode('utf-8') for x in components]
    sp = "/".join(components)
    
    # Calculate typename - 32 bits from previous value
    typename_offset = comp_end + 8
    typename = hex_encoded[comp_end:typename_offset]

    # Calculate Timestamp - 32 bit from typename value
    timestamp_offset = typename_offset + 8
    timestamp = int(hex_encoded[typename_offset:timestamp_offset], 16)
    timestamp_str = datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M")

    # Calcualte 8 bit VNO Field
    vno_offset = timestamp_offset + 2
    vno = hex_encoded[timestamp_offset:vno_offset]
    #print("\tVersion No : " + vno)

    # Calculate KeyType - 16 bit value
    keytype_offset = vno_offset + 4
    keytype_hex = hex_encoded[vno_offset:keytype_offset]
    keytype_dec = int(keytype_hex, 16)

    # Calculate Length of Key Value - 16 bit value
    key_val_offset = keytype_offset + 4
    key_val_len = int(hex_encoded[keytype_offset:key_val_offset], 16)

    # Extract Key Value
    key_val_start = key_val_offset
    key_val_finish = key_val_start + (key_val_len * 2)
    key_val = hex_encoded[key_val_start:key_val_finish]
    
    ignore_bytes = int(hex_encoded[key_val_finish:key_val_finish + 8], 16)

    if not realm in all_data:
        all_data[realm] = dict()
    if not sp in all_data[realm]:
        all_data[realm][sp] = dict()
    if not timestamp_str in all_data[realm][sp]:
        all_data[realm][sp][timestamp_str] = dict()
    if not keytype_hex in all_data[realm][sp][timestamp_str]:
        all_data[realm][sp][timestamp_str][keytype_hex] = key_val
    
    # Direty hack, if you have a better solution please contribute
    next_entry = key_val_finish + 8
    if hex_encoded[next_entry:next_entry+4] == "ffff":
        next_entry += 8
    while hex_encoded[next_entry:next_entry+2] == "00":
        next_entry += 2
        if hex_encoded[next_entry:next_entry+4] == "ffff":
            next_entry += 8

    return next_entry + 2

def ktextract():
    rc4hmac = False
    aes128 = False
    aes256 = False 
    
    if '00170010' in hex_encoded:
        print("[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.")
        rc4hmac = True
    else:
        print("[!] No RC4-HMAC located. Unable to extract NTLM hashes.")
        
    if '00120020' in hex_encoded:
        print("[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.")
        aes256 = True
    else:
        print("[!] Unable to identify any AES256-CTS-HMAC-SHA1 hashes.")

    if '00110010' in hex_encoded:
        print("[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.")
        aes128 = True
    else:
        print("[!] Unable to identify any AES128-CTS-HMAC-SHA1 hashes.")

    #if proceed != True:
    if all( [ rc4hmac != True, aes256 != True, aes128 != True]):
        print("Unable to find any useful hashes.\nExiting...")
        sys.exit

    # First 16 bits are dedicated to stating the version of Keytab File
    ktversion = hex_encoded[:4]
    if ktversion == '0502':
        print("[+] Keytab File successfully imported.")
    else:
        print("[!] Only Keytab versions 0502 are supported.\nExiting...")

    # 32 bits indicating the size of the array 
    arrLen = int(hex_encoded[4:12], 16)

    pointer = 12

    while pointer < len(hex_encoded):
        pointer = entryextract(pointer)

def pretty_print():
    for realm in all_data:
        print(f"- Realm: {realm}")
        for sp in all_data[realm]:
            print(f"\t- Service Principal: {sp}")
            for timestamp in sorted(all_data[realm][sp].keys())[::-1]:
                print(f"\t\t- Timestamp: {timestamp}")
                for enctype in sorted(all_data[realm][sp][timestamp].keys()):
                    print(f"\t\t\t{TYPES[enctype]}: {all_data[realm][sp][timestamp][enctype]}")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        displayhelp()
        sys.exit()
    else:
        ktextract()
        pretty_print()
