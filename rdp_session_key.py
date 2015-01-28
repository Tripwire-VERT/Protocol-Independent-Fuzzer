from hashlib import md5
from hashlib import sha1 as sha
import Crypto.Cipher.ARC4 as arc4
from Crypto.Cipher import DES3
import struct
import hmac as hmacs

    
class RDPSessionKey(object):
    
    def __init__ (self, *args, **kwargs):
        self.client_random = kwargs.get('client_random', '')
        self.server_random = kwargs.get('server_random', '')
        self.lookup_table = RDPSessionKey.lookup_table

    def get_premaster_secret (self):
        return self.client_random[0:24] + self.server_random[0:24]
    
    def get_master_secret(self):
        return self.get_premaster_hash('\x41') + self.get_premaster_hash('\x42\x42') + self.get_premaster_hash('\x43\x43\x43')

    def get_premaster_hash(self, i):
        return self.get_salted_hash(self.get_premaster_secret(), i)

    def get_salted_hash(self, premaster_secret, i):
        return md5(premaster_secret + sha(i + premaster_secret + self.client_random + self.server_random).digest()).digest()
        
    def get_session_key_blob(self):
        return self.get_master_hash('\x58') + self.get_master_hash('\x59\x59') + self.get_master_hash('\x5A\x5A\x5A')

    def get_master_hash(self, i):
        return self.get_salted_hash(self.get_master_secret(), i)

    def get_final_hash(self, k):
        return md5(k + self.client_random + self.server_random).digest()

    def get_mac_key128(self):
        self.initial_mac_key128 = self.get_session_key_blob()[0:16]
        return self.initial_mac_key128

    def get_initial_server_encrypt_key128(self):
        self.initial_server_encrypt_key128 = self.get_final_hash(self.get_session_key_blob()[16:32])
        return self.initial_server_encrypt_key128

    def get_initial_server_decrypt_key128(self):
        self.initial_server_decrypt_key128 = self.get_final_hash(self.get_session_key_blob()[32:48])
        return self.initial_server_decrypt_key128

    def get_initial_client_encrypt_key128(self):
        self.initial_client_encrypt_key128 = self.get_initial_server_decrypt_key128()
        return self.initial_client_encrypt_key128

    def get_initial_client_decrypt_key128(self):
        self.initial_client_decrypt_key128 = self.get_initial_server_encrypt_key128()
        return self.initial_client_decrypt_key128

    def get_mac_key40(self):
        self.initial_mac_key40 = '\xD1\x26\x9E' + self.get_mac_key128()[3:8]
        return self.initial_mac_key40

    def get_initial_server_encrypt_key40(self):
        self.initial_server_encrypt_key40 = '\xD1\x26\x9E' + self.get_initial_server_encrypt_key128()[3:8]
        return self.initial_server_encrypt_key40

    def get_initial_server_decrypt_key40(self):
        self.initial_server_decrypt_key40 = '\xD1\x26\x9E' + self.get_initial_server_decrypt_key128()[3:8]
        return self.initial_server_decrypt_key40

    def get_initial_client_encrypt_key40(self):
        self.initial_client_encrypt_key40 = self.get_initial_server_decrypt_key40()
        return self.initial_client_encrypt_key40
        
    def get_initial_client_decrypt_key40(self):
        self.initial_client_decrypt_key40 = self.get_initial_server_encrypt_key40()
        return self.initial_client_decrypt_key40

    def get_mac_key56(self):
        self.initial_mac_key56 =  '\xD1' + self.get_mac_key128()[1:8] 
        return self.initial_mac_key56

    def get_initial_server_encrypt_key56(self):
        self.initial_server_encrypt_key56 = '\xD1' + self.get_initial_server_encrypt_key128()[1:8]
        return self.initial_server_encrypt_key56

    def get_initial_server_decrypt_key56(self):
        self.get_initial_server_decrypt_key56 = '\xD1' + self.get_initial_server_decrypt_key128()[1:8]
        return self.get_initial_server_decrypt_key56

    def get_initial_client_encrypt_key56(self):
        self.initial_client_encrypt_key56 = self.get_initial_server_decrypt_key56()
        return self.initial_client_encrypt_key56
    
    def get_initial_client_decrypt_key56(self):
        self.initial_client_decrypt_key56 = self.get_initial_server_encrypt_key56()
        return self.initial_client_decrypt_key56
    
    def update_session_keys(self, current_encrypt_key = None, current_decrypt_key = None, key_length = 128, enc_type = 'client'):
        initial_encrypt_key = vars(self)['initial_%s_encrypt_key%d' % (enc_type, key_length)]
        initial_decrypt_key = vars(self)['initial_%s_decrypt_key%d' % (enc_type, key_length)]
        if not current_encrypt_key:
            current_encrypt_key = initial_encrypt_key
        if not current_decrypt_key:
            current_decrypt_key = initial_decrypt_key
        if key_length == 128:
            encrypt_tempkey128 = self.get_update_session_key_tempkey128(initial_encrypt_key, current_encrypt_key)
            decrypt_tempkey128 = self.get_update_session_key_tempkey128(initial_decrypt_key, current_decrypt_key)
            self.encrypt_secret = self.crypto(encrypt_tempkey128, encrypt_tempkey128)
            self.decrypt_secret = self.crypto(decrypt_tempkey128, decrypt_tempkey128)
        else:
            encrypt_tempkey64 = self.get_update_session_key_tempkey128(initial_encrypt_key[0:8], current_encrypt_key[0:8])[0:8]
            decrypt_tempkey64 = self.get_update_session_key_tempkey128(initial_decrypt_key[0:8], current_decrypt_key[0:8])[0:8]
            if key_length == 56:
                self.encrypt_secret = '\xD1' + self.crypto(encrypt_tempkey64, encrypt_tempkey64)
                self.decrypt_secret = '\xD1' + self.crypto(decrypt_tempkey64, decrypt_tempkey64)
            elif key_length == 40:
                self.encrypt_secret = '\xD1269E' + self.crypto(encrypt_tempkey64, encrypt_tempkey64)
                self.decrypt_secret = '\xD1269E' + self.crypto(decrypt_tempkey64, decrypt_tempkey64)
        return
    
    def crypto(self, secret, data):
        new_arc4 = arc4.new(secret)
        return new_arc4.encrypt(data)
            
    def get_update_session_key_tempkey128( self, initial_key, current_key):
        pad1 = '\x36' * 40
        pad2 = '\x5C' * 48
        SHA_component = sha(initial_key + pad1 + current_key).digest()
        return md5(initial_key + pad2 + SHA_component).digest()
    
    #added for fips
    lookup_table = {0: 0, 1: 128, 2: 64, 3: 192, 4: 32, 5: 160, 6: 96, 7: 224, 8: 16, 9: 144, 10: 80, 11: 208, 12: 48, 13: 176, 14: 112, 15: 240, 16: 8, 17: 136, 18: 72, 19: 200, 20: 40, 21: 168, 22: 104, 23: 232, 24: 24, 25: 152, 26: 88, 27: 216, 28: 56, 29: 184, 30: 120, 31: 248, 32: 4, 33: 132, 34: 68, 35: 196, 36: 36, 37: 164, 38: 100, 39: 228, 40: 20, 41: 148, 42: 84, 43: 212, 44: 52, 45: 180, 46: 116, 47: 244, 48: 12, 49: 140, 50: 76, 51: 204, 52: 44, 53: 172, 54: 108, 55: 236, 56: 28, 57: 156, 58: 92, 59: 220, 60: 60, 61: 188, 62: 124, 63: 252, 64: 2, 65: 130, 66: 66, 67: 194, 68: 34, 69: 162, 70: 98, 71: 226, 72: 18, 73: 146, 74: 82, 75: 210, 76: 50, 77: 178, 78: 114, 79: 242, 80: 10, 81: 138, 82: 74, 83: 202, 84: 42, 85: 170, 86: 106, 87: 234, 88: 26, 89: 154, 90: 90, 91: 218, 92: 58, 93: 186, 94: 122, 95: 250, 96: 6, 97: 134, 98: 70, 99: 198, 100: 38, 101: 166, 102: 102, 103: 230, 104: 22, 105: 150, 106: 86, 107: 214, 108: 54, 109: 182, 110: 118, 111: 246, 112: 14, 113: 142, 114: 78, 115: 206, 116: 46, 117: 174, 118: 110, 119: 238, 120: 30, 121: 158, 122: 94, 123: 222, 124: 62, 125: 190, 126: 126, 127: 254, 128: 1, 129: 129, 130: 65, 131: 193, 132: 33, 133: 161, 134: 97, 135: 225, 136: 17, 137: 145, 138: 81, 139: 209, 140: 49, 141: 177, 142: 113, 143: 241, 144: 9, 145: 137, 146: 73, 147: 201, 148: 41, 149: 169, 150: 105, 151: 233, 152: 25, 153: 153, 154: 89, 155: 217, 156: 57, 157: 185, 158: 121, 159: 249, 160: 5, 161: 133, 162: 69, 163: 197, 164: 37, 165: 165, 166: 101, 167: 229, 168: 21, 169: 149, 170: 85, 171: 213, 172: 53, 173: 181, 174: 117, 175: 245, 176: 13, 177: 141, 178: 77, 179: 205, 180: 45, 181: 173, 182: 109, 183: 237, 184: 29, 185: 157, 186: 93, 187: 221, 188: 61, 189: 189, 190: 125, 191: 253, 192: 3, 193: 131, 194: 67, 195: 195, 196: 35, 197: 163, 198: 99, 199: 227, 200: 19, 201: 147, 202: 83, 203: 211, 204: 51, 205: 179, 206: 115, 207: 243, 208: 11, 209: 139, 210: 75, 211: 203, 212: 43, 213: 171, 214: 107, 215: 235, 216: 27, 217: 155, 218: 91, 219: 219, 220: 59, 221: 187, 222: 123, 223: 251, 224: 7, 225: 135, 226: 71, 227: 199, 228: 39, 229: 167, 230: 103, 231: 231, 232: 23, 233: 151, 234: 87, 235: 215, 236: 55, 237: 183, 238: 119, 239: 247, 240: 15, 241: 143, 242: 79, 243: 207, 244: 47, 245: 175, 246: 111, 247: 239, 248: 31, 249: 159, 250: 95, 251: 223, 252: 63, 253: 191, 254: 127, 255: 255}
    
    def get_client_encrypt_keyt(self):
        self.client_encrypt_keyt = sha(self.client_random[16:] + self.server_random[16:]).digest()
        return self.client_encrypt_keyt
    
    def get_client_decrypt_keyt(self):
        self.client_decrypt_keyt = sha(self.client_random[:16] + self.server_random[:16]).digest()
        return self.client_decrypt_keyt
        
    def get_server_decrypt_keyt(self):
        self.server_decrypt_keyt = sha(self.client_random[16:] + self.server_random[16:]).digest()
        return self.server_decrypt_keyt
    
    def get_server_encrypt_keyt(self):
        self.server_encrypt_keyt = sha(self.client_random[:16] + self.server_random[:16]).digest()
        return self.server_encrypt_keyt
        
    def get_client_encrypt_key(self):
        self.client_encrypt_key = self.convert_bytes(self.get_client_encrypt_keyt() + self.get_client_encrypt_keyt()[:1])
        return self.client_encrypt_key
    
    def get_client_decrypt_key(self):
        self.client_decrypt_key = self.convert_bytes(self.get_client_decrypt_keyt() + self.get_client_decrypt_keyt()[:1])
        return self.client_decrypt_key
    
    def get_server_decrypt_key(self):
        self.server_decrypt_key = self.convert_bytes(self.get_server_decrypt_keyt() + self.get_server_decrypt_keyt()[:1])
        return self.server_decrypt_key
    
    def get_server_encrypt_key(self):
        self.server_encrypt_key = self.convert_bytes(self.get_server_encrypt_keyt() + self.get_server_encrypt_keyt()[:1])
        return self.server_encrypt_key
    
    def get_client_hmac_key(self):
        self.client_hmac_key = sha(self.get_client_decrypt_keyt() + self.get_client_encrypt_keyt()).digest()
        return self.client_hmac_key
    
    def get_server_hmac_key(self):
        self.server_hmac_key = sha(self.get_server_encrypt_keyt() + self.get_server_decrypt_keyt()).digest()
        return self.server_hmac_key
    
    def own_bin(self, data):
        if data==0:
            return '0'
        else:
            return (self.own_bin(data/2)+str(data%2)).lstrip('0') or '0'
            
    def pad_bin(self, data):
        return self.own_bin(data).zfill(8)
        
    def reverse_bytes(self, data):
        output = ''
        for i in range(0, len(data)):
            output += chr(self.lookup_table[ord(data[i])])
        return output
        
    def make_binary_string(self, data):
        output = ''
        for char in data:
            output += self.pad_bin(ord(char))
        return output
    
    def make_byte_string(self, data):
        output = ''
        for i in range(len(data) / 8):
            output += chr(int(data[0:8], 2))
            data = data[8:]
        return output

    def convert_bytes(self, bytes):
        result = ''
        bytes = self.reverse_bytes(bytes)
        new_bytes = self.make_binary_string(bytes)
        for i in range(1, 25):
            new_bytes = new_bytes[:7*i+(i-1)] + '0' + new_bytes[7*i+(i-1):]
        return self.odd_parity(self.reverse_bytes(self.make_byte_string(new_bytes)))

    # not used as the lookup table was made static
    def get_lookup_table(self):
        self.lookup_table = {}
        for i in range(1, 256):
            bin_val = self.pad_bin(i)
            while len(bin_val) < 8:
                bin_val = '0' + bin_val
            self.lookup_table[i] = int(bin_val[::-1], 2)
        return self.lookup_table
    
    def odd_parity(self, bytes):
        new_bytes = ''
        for byte in bytes:
            int_byte = ord(byte)
            count = 0
            for i in range (0, 8):
                if int_byte & 2**i != 0:
                    count += 1
            if count % 2 == 0:
                if int_byte & 1 == 1:
                    result = int_byte - 1
                else:
                    result = int_byte + 1
                new_bytes += chr(result)
            else:
                new_bytes += byte   
        return new_bytes

class RDPCrypto(RDPSessionKey):
    def __init__(self, *args, **kwargs):
        super(RDPCrypto, self).__init__(*args, **kwargs)
        self.key_length = kwargs.get('key_length', 128)
        key_length = self.key_length
        if self.key_length == 'fips':
            self.iv = '\x12\x34\x56\x78\x90\xAB\xCD\xEF'
            self.encryption_count = 0

    def mac_signature(self, data):
        if self.key_length == 'fips':
            return self.mac_signature_fips(data)
        else:
            return self.mac_signature_non_fips(data)
    
    def encrypt(self, data):
        if self.key_length == 'fips':
            return self.encrypt_fips(data)
        else:
            return self.encrypt_non_fips(data)
            
    def decrypt(self, data):
        if self.key_length == 'fips':
            return self.decrypt_fips(data)
        else:
            return self.decrypt_non_fips(data)

    def setup_fips(self, encrypt_key, decrypt_key):
        self.des3_encrypt = DES3.new(self.encrypt_key, mode = DES3.MODE_CBC, IV = self.iv)
        self.des3_decrypt = DES3.new(self.decrypt_key, mode = DES3.MODE_CBC, IV = self.iv)
     
    def mac_signature_fips(self, data):
        count = struct.pack('<L', self.encryption_count)
        signature = hmacs.new(self.hmac, data + count, sha).digest()[:8]
        return signature

    def encrypt_fips(self, data):
        self.encryption_count += 1
        return self.des3_encrypt.encrypt(data)

    def decrypt_fips(self, data):
        return self.des3_decrypt.decrypt(data)
        
    def setup_non_fips(self, encrypt_secret, decrypt_secret):
        self.rc4_encrypt = arc4.new(encrypt_secret)
        self.rc4_decrypt = arc4.new(decrypt_secret)
    
    def mac_signature_non_fips(self, data):
        length = len(data) 
        length =  struct.pack( '=L', length )
        mac = self.mac
        pad1 = '\x36'*40
        pad2 = '\x5c'*48
        sha_component = sha(mac + pad1 + length + data).digest()
        return md5(mac + pad2 + sha_component).digest()[:8]
    
    def encrypt_non_fips(self, data):
        return self.rc4_encrypt.encrypt(data)
    
    def decrypt_non_fips(self, data):
        return self.rc4_decrypt.decrypt(data)

class RDPClientCrypto(RDPCrypto):

    def __init__(self, *args, **kwargs):
        super(RDPClientCrypto, self).__init__(*args,**kwargs)
        if self.key_length != 'fips':
            if self.key_length == 128:
                self.encrypt_secret = self.get_initial_client_encrypt_key128()
                self.decrypt_secret = self.get_initial_client_decrypt_key128()
                self.mac = self.get_mac_key128()
            elif self.key_length == 56:
                self.encrypt_secret = self.get_initial_client_encrypt_key56()
                self.decrypt_secret = self.get_initial_client_decrypt_key56()
                self.mac = self.get_mac_key56()
            elif self.key_length == 40:
                self.encrypt_secret = self.get_initial_client_encrypt_key40()
                self.decrypt_secret = self.get_initial_client_decrypt_key40()
                self.mac = self.get_mac_key40()
            self.setup_non_fips(self.encrypt_secret, self.decrypt_secret)
        elif self.key_length == 'fips':
            self.encrypt_key = self.get_client_encrypt_key()
            self.decrypt_key = self.get_client_decrypt_key()
            self.hmac = self.get_client_hmac_key()
            self.setup_fips(self.encrypt_key, self.decrypt_key)
            
class RDPServerCrypto(RDPCrypto):

    def __init__(self, *args, **kwargs):
        super(RDPServerCrypto, self).__init__(*args,**kwargs)
        if self.key_length != 'fips':
            if self.key_length == 128:
                self.encrypt_secret = self.get_initial_server_encrypt_key128()
                self.decrypt_secret = self.get_initial_server_decrypt_key128()
                self.mac = self.get_mac_key128()
            elif self.key_length == 56:
                self.encrypt_secret = self.get_initial_server_encrypt_key56()
                self.decrypt_secret = self.get_initial_server_decrypt_key56()
                self.mac = self.get_mac_key56()
            elif self.key_length == 40:
                self.encrypt_secret = self.get_initial_server_encrypt_key40()
                self.decrypt_secret = self.get_initial_server_decrypt_key40()
                self.mac = self.get_mac_key40()
            self.setup_non_fips(self.encrypt_secret, self.decrypt_secret)
        elif self.key_length == 'fips':
            self.encrypt_key = self.get_server_encrypt_key()
            self.decrypt_key = self.get_server_decrypt_key()
            self.hmac = self.get_server_hmac_key()
            self.setup_fips(self.encrypt_key, self.decrypt_key)