import struct
from Crypto.PublicKey import RSA
import binascii 
import rdp_session_key
import rdp_error

#encryption types
FOURTY_BIT           = 1
ONE_TWENTY_EIGHT_BIT = 2
FIFTY_SIX_BIT        = 8
FIPS                 = 16

#protocols
DEFAULT = 0
TLS     = 1
CredSSP = 2

#other
COTP_DATA = '\x02\xf0\x80'

class RDP( object ):
    
    def __init__(self):
        pass
    
    def build_tpkt_header(self, length):
        # the tpkt header is always going to be 4
        length                      += 4
        tpkt_ver                    = '\x03'
        tpkt_resverved              = '\x00'
        tpkt_length                 = struct.pack('!h', length)
        tpkt                        = tpkt_ver + tpkt_resverved + tpkt_length
        return tpkt
    
    
    
    def createClientInfo(self, crypto, encryption):
        header = '\x48\x00\x00\x00'
        client_info_packet                      = self.template.createClientInfo()
        if encryption == 'fips':
            padding = '\x00' * (8 - len(client_info_packet) % 8)
            header += '\x10\x00\x01' + struct.pack('b', len(padding))
        else:
            padding = ''
        macSignature = self.template.macSignature(crypto, client_info_packet)
        #macSignature = crypto.mac_signature(client_info_packet)
        #MS14-030
        #macSignature = 'tripwire'
        client_info_packet += padding
        encryptedClientInfo = self.encrypt(crypto, client_info_packet)
        data = header  + macSignature + encryptedClientInfo
        length = struct.pack('!h', -32768+len(data))
        client_info_packet = COTP_DATA + '\x64\x00\x03\x03\xeb\x70' + length + data
        client_info_packet = self.build_tpkt_header(len(client_info_packet)) + client_info_packet
        return client_info_packet
    
    def confirmActive(self, crypto, encryption):
        header = '\x38\x00\x00\x00'
        client_confirm_active                       = self.template.confirmActive()
        
        if encryption == 'fips':
            padding = '\x00' * (8 - len(client_confirm_active) % 8)
            header += '\x10\x00\x01' + struct.pack('b', len(padding))
            paddedData = client_confirm_active + padding
        else:
            paddedData = client_confirm_active
        client_confirm_active = header + crypto.mac_signature(client_confirm_active) + self.encrypt(crypto, paddedData)
        client_confirm_active = '\x64\x00\x03\x03\xeb\x70%s' % (struct.pack('!h', -32768+len(client_confirm_active))) + client_confirm_active
        encryptedData = COTP_DATA + client_confirm_active
        return self.build_tpkt_header(len(encryptedData)) + encryptedData
    
    
    def processResponse(self, type, response, mscSecType = ''):
        if type == 1:   #X224 Connection Response
            return self.processX224Response(response)            
        elif type == 2:     #MCS Connect Confirm
            return self.processMCSResponse(response, mscSecType)
        else: return None    
        
    def processX224Response(self, response):
        if len(response) > 0:
            length = struct.unpack('!B', response[4:5])[0]
            selectedProtocol = struct.unpack('!B', response[-4:-3])[0]
            return selectedProtocol
        return None
    
    def processMCSResponse(self, response, mscSecType):
        if len(response) >= 75:
            baseOffset = 75
            offset = baseOffset + struct.unpack('!B', response[baseOffset:baseOffset+1])[0] + 18
            encryptionMethod = struct.unpack('!B', response[offset:offset+1])[0]
            encryptionLevel = struct.unpack('!B', response[offset+4:offset+5])[0]
            if mscSecType.lower() == 'method':
                return encryptionMethod
            elif mscSecType.lower() == 'level':
                return encryptionLevel
        return None
        
    #some functions  won't work if Network Level Authentication is required and can save time by not attempting further requests
    def requiresNetworkLevelAuthentication(self, buffer):
        if self.processResponse(1, buffer) == 5:
            return True
        else: return False


    
    def parseRuleDotBuffer(self, s, crypto, encryption, count = 1):
        packetList = []
        packets = s.limited_stream(counter = count)
        length = 0
        while True:
            if packets.startswith('\x03\x00'):
                length = struct.unpack('!h', packets[2:4])[0]
                if length > len(packets) or len(packets) == 0:
                    break
                else:
                    packetList.append(self.decrypt(crypto, packets[:length], encryption))
                    packets = packets[length:]
            elif packets.startswith('\xc0'):
                if packets.find('\x10\x00\x01') == 2:
                    length = struct.unpack('b', packets[1:2])[0]
                else:
                    length = struct.unpack('!h', packets[1:3])[0] - (-32768)
                if length > len(packets) or len(packets) == 0:
                    break
                else:
                    packetList.append(self.decrypt(crypto, packets[:length], encryption))
                    packets = packets[length:]
            else:
                break
        for x in packetList:
            # check packet for error
            rdp_error.check_error(x)
        if packetList != []:
            return packetList
        return None
    
    def sendChannelRequest(self, s, channel):
        self.template.channelJoinRequest(channel)
        channelRequest = '\x03\x00\x00\x0c\x02\xf0\x80' + self.template.channelJoinRequest(channel)
        s.send(channelRequest)
        return self.checkChannelConfirm(channel, s.read())
    
    def checkChannelConfirm(self, channel, response):
        if len(response) == 15:
            confirmChannel = struct.unpack('!h', response[13:])[0]
            if channel == confirmChannel:
                return True
        elif len(response) == 13:
            confirmChannel = struct.unpack('!h', response[11:])[0]
            if channel == confirmChannel:
                return True
        return False
    
    def sendChannelRequests(self, s):
            # this will verify that the channels are set up correctly and then return none
            if self.sendChannelRequest(s, 1004) == False:
                return None
            if self.sendChannelRequest(s, 1003) == False:
                return None
            return True
    
    def parseServerRandom(self, data):
        # looking for '\xEB\x03' as it is the I/O Channel and will always be there
        serverRandomStart = data.find('\x52\x53\x41\x31') - 48
        serverRandomEnd = serverRandomStart + 32
        
        serverRandom = data[serverRandomStart:serverRandomEnd]
        return serverRandom
        
    def parseEncryptionLevel(self, data):
        encryptionLevelStart = data.find('\x52\x53\x41\x31') - 64
        encryptionLevelEnd = encryptionLevelStart + 4
        
        encryptionLevel = data[encryptionLevelStart:encryptionLevelEnd]
        return encryptionLevel
        
    
    def parsePublicKey(self, publicKey):
        if len(publicKey) > 0:
            #look for '\x52\x53\x41\x31' as it will not change as it is the magic 'RSA1'
            keyStart = publicKey.find('\x52\x53\x41\x31')
            kenLen = publicKey[keyStart-2:keyStart]
            kenLen = struct.unpack('h', kenLen)[0] + keyStart
            key = publicKey[keyStart:kenLen]
            return key
        return None
    
    '''
    def encryptClientRandom(self, publicKey, client_data):
        random_data = publicKey[:20]
        modulus_data = publicKey[20:]
        reverse_client_data = client_data[::-1]
        modulus = int(bin2int(modulus_data[::-1]))
        magic, keylen, bitlen, datalen, pubExp = struct.unpack('<LLLLL', random_data)
        rsa = RSA.RSAobj()
        rsa.n = modulus
        rsa.e = pubExp
        ciphertext = rsa.encrypt(reverse_client_data, '')
        return ciphertext[0][::-1]
    '''
    
    def encryptClientRandom(self, publicKey, client_data):
        random_data = publicKey[:20]
        modulus_data = publicKey[20:]
        reverse_client_data = client_data[::-1]
        modulus = int(bin2int(modulus_data[::-1]))
        magic, keylen, bitlen, datalen, pubExp = struct.unpack('<LLLLL', random_data)
        rsa_impl = RSA.RSAImplementation()
        rsa = rsa_impl.construct((modulus, long(pubExp)))
        ciphertext = rsa.encrypt(reverse_client_data, '')
        return ciphertext[0][::-1]
        rsa = RSA.importKey(publicKey)
        ciphertext = rsa.encrypt(reverse_client_data, '')
        return ciphertext[0][::-1]
    
    def buildEncryptedClientRandom(self, clientRandom):
        clientRandom = clientRandom + '\x00\x00\x00\x00\x00\x00\x00\x00'
        clientRandomLen = len(clientRandom)
        userDataLen = clientRandomLen + 8
        secLen = struct.pack('=L', clientRandomLen)
        combined = '\x02\xf0\x80\x64\x00\x03\x03\xeb\x70' + struct.pack('!h', -32768+userDataLen) + '\x01\x00\x00\x00' + secLen + clientRandom
        secPacket = self.build_tpkt_header(len(combined)) + combined
        return secPacket
    
    def encrypt(self, crypto, unencrypted):
        return crypto.encrypt(unencrypted)
    
    def decrypt(self, crypto, packet, encryption):
        if 10 < packet.find('\x10\x00\x01') < 20 or 0 < packet.find('\x10\x00\x01') < 4 :
            location = packet.find('\x10\x00\x01') + 12
        elif packet.find('\x08\x08\x00\x00') > 13:
            location = packet.find('\x08\x08\x00\x00') + 12
        elif packet.find('\x08\x00') > 13 and packet.find('\x08\x00') < 17:
            location = packet.find('\x08\x00') + 12
        elif packet.find('\x88\x02') > 13 and packet.find('\x88\x02') < 17:
            location = packet.find('\x88\x02')
        elif packet.startswith('\xC0'):
            location = 3
        else:
            #Not Encrypted
            return packet
        encryptedData = packet[location:]
        # need to decrypt the data
        return crypto.decrypt(encryptedData)
    
    def constructPackets(self, crypto, encryption, data):
        header = '\x08\x00\x00\x00'
        if encryption == 'fips':
            padding = '\x00' * (8 - len(data) % 8)
            header += '\x10\x00\x01' + struct.pack('b', len(padding))
            paddedData = data + padding
        else:
            paddedData = data
        data = header + crypto.mac_signature(data) + self.encrypt(crypto, paddedData)
        data = '\x64\x00\x03\x03\xeb\x70%s' % (struct.pack('!h', -32768+len(data))) + data
        encryptedData = COTP_DATA + data
        return self.build_tpkt_header(len(encryptedData)) + encryptedData
    
    def packet_without_tpkt(self, crypto, header, data):
        padding = '\x00' * (8 - len(data) % 8)
        return header % (crypto.mac_signature(data) + self.encrypt(crypto, data + padding))
    
    def start(self, s, template, encrypt = FOURTY_BIT + FIFTY_SIX_BIT + ONE_TWENTY_EIGHT_BIT + FIPS):
        self.template = template
        s.send(self.build_tpkt_header(len(self.template.generateX224Request())) + self.template.generateX224Request())
        
        temp_buffer = s.read()
        
        
        if self.processResponse(1, temp_buffer) == None:
            return False
        
        if self.requiresNetworkLevelAuthentication(temp_buffer):
            raise rdp_error.RDPError(0x0000, 'NLAEnabled', 'This host has NLA enabled, the connection cannot proceed further')    
        
        
        s.send(self.build_tpkt_header(len(self.template.generateMCSRequest())) + self.template.generateMCSRequest())
        
        recv_buffer = s.read()
        
        publicKey = self.parsePublicKey(recv_buffer)
        if publicKey == None:
            return False
        
        
        serverRandom = self.parseServerRandom(recv_buffer)
        
        encryptionLevel = self.parseEncryptionLevel(recv_buffer)
        if encryptionLevel == '\x02\x00\x00\x00':
            encryption = 128
        elif encryptionLevel == '\x08\x00\x00\x00':
            encryption = 56
        elif encryptionLevel == '\x01\x00\x00\x00':
            encryption = 40
        elif encryptionLevel == '\x10\x00\x00\x00':
            encryption = 'fips'
        else:
            return False
        
        # erect DomainRequest
        s.send(self.build_tpkt_header(len(self.template.generateErectDomain()+COTP_DATA)) + COTP_DATA + self.template.generateErectDomain())
        # Attach User Request
        s.send(self.build_tpkt_header(len(self.template.generateMCSAttachUser()+COTP_DATA)) + COTP_DATA + self.template.generateMCSAttachUser())
        # send channel request if the attach user was successful.
        buffer = s.read()
        if buffer.startswith('\x03\x00\x00\x0b\x02\xf0\x80\x2e\x00\x00'):
            if self.sendChannelRequests(s) == None:
                return False
        
        # We are just going to create a static clientRandom 
        # as it is easier to decrypt the data if we need.
        clientRandom = '\xfd\x5c\x6c\xd7\x57\x78\xb9\xa2\x3e\x31\xff\x37\xf4\xa7\x06\x33\x54\x34\xa2\x54\xd6\x84\x32\x68\x5c\xc1\x16\xbf\xfc\x83\x53\xff'
    
        # send the encrypted client_random to the server.
        s.send(self.buildEncryptedClientRandom(self.encryptClientRandom(publicKey, clientRandom)))
        crypto = rdp_session_key.RDPClientCrypto(client_random = clientRandom, server_random = serverRandom, key_length = encryption)
        
        # send the client info packet
        s.send(self.createClientInfo(crypto, encryption))
    
        packets = self.parseRuleDotBuffer(s, crypto, encryption, 2)
        if packets == None:
            return False
        
        if len(packets) > 1 and 'RDP' in packets[1]:
            s.send(self.confirmActive(crypto, encryption))
            if encryption == 'fips':
                packet = self.constructPackets(crypto, encryption, '\x16\x00\x17\x00\xec\x03\xea\x03\x01\x00\x00\x01\x08\x00\x1f\x00\x00\x00\x01\x00\xea\x03')
                s.send(packet)
                packet = self.constructPackets(crypto, encryption, '\x1a\x00\x17\x00\xec\x03\xea\x03\x01\x00\x00\x01\x0c\x00\x14\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00')
                s.send(packet)
                packet = self.constructPackets(crypto, encryption, '\x1a\x00\x17\x00\xec\x03\xea\x03\x01\x00\x00\x01\x0c\x00\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00')
                s.send(packet)
                packet = self.packet_without_tpkt(crypto, '\x90\x1e\x21\x8b\x62\x04%s', '\x01\x0fb\x01\x0f \x00\x08\x08\x02\xe2\x00')
                s.send(packet)
                packet = self.constructPackets(crypto, encryption, '*\x00\x17\x00\xec\x03\xea\x03\x01\x00\x00\x01\x00\x00+\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00')
                s.send(packet)
                packet = self.constructPackets(crypto, encryption, "\x1a\x00\x17\x00\xec\x03\xea\x03\x01\x00\x00\x01_\x03'\x00\x00\x00\x00\x00\x00\x00\x03\x002\x00")
                s.send(packet)
            
                packet = self.packet_without_tpkt(crypto, '\xd0\x1e\x00\x00\x00\x04%s', '\x01\x0fb\x01\x0f \x00\x08\x0c\x02\xf9\x00')
                s.send(packet)
                
                packet = self.packet_without_tpkt(crypto, '\xcc\x16\x36\xca\x69\x03%s', '\x01\x0fb\x01\x0f')
                s.send(packet)
                
                packets = self.parseRuleDotBuffer(s, crypto, encryption, 5)
            else:
                packet = self.constructPackets(crypto, encryption,  '\x16\x00\x17\x00\xec\x03\xea\x03\x01\x00\x00\x01\x08\x00\x1f\x00\x00\x00\x01\x00\xea\x03')
                s.send(packet)
                packet = self.constructPackets(crypto, encryption, '\x1a\x00\x17\x00\xec\x03\xea\x03\x01\x00\x00\x01\x0c\x00\x14\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00')
                s.send(packet)
                packet = self.constructPackets(crypto, encryption, '\x1a\x00\x17\x00\xec\x03\xea\x03\x01\x00\x00\x01\x0c\x00\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00')
                s.send(packet)
                self.parseRuleDotBuffer(s, crypto, 3)
                packet = self.constructPackets(crypto, encryption, '\x22\x00\x17\x00\xec\x03\xea\x03\x01\x00\x00\x01\x14\x00\x1c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
                s.send(packet)
                packet = self.constructPackets(crypto, encryption, '\x1a\x00\x17\x00\xec\x03\xea\x03\x01\x00\x00\x01\x0c\x00\x27\x00\x00\x00\x00\x00\x00\x00\x01\x00\x32\x00')
                s.send(packet)
                packet = self.constructPackets(crypto, encryption, '\x1a\x00\x17\x00\xec\x03\xea\x03\x01\x00\x00\x01\x0c\x00\x27\x00\x00\x00\x00\x00\x00\x00\x02\x00\x32\x00')
                s.send(packet)
                
                packets = self.parseRuleDotBuffer(s, crypto, encryption, 5)
        return False


# added to convert to hex and convert hex strings to ints
def bin2hex( data ):
    return binascii.b2a_hex( str(data) )

def bin2int( data ):
    return int(bin2hex( data ), 16)

def hex2int( data ):
    return int( data , 16)


