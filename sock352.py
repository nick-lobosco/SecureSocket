#main libraries
import binascii
import socket as syssock
import struct
import sys
import random
import time

#encryption libraries
import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box

# the public and private keychains in hex format 
global publicKeysHex
global privateKeysHex

# the public and private keychains in binary format 
global publicKeys
global privateKeys

# the encryption flag 
global ENCRYPT

publicKeysHex = {} 
privateKeysHex = {} 
publicKeys = {} 
privateKeys = {}

# this is 0xEC 
ENCRYPT = 236 

# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from
Socket = None
portTx = 27182 #default port #s
portRx = 27182
def init(UDPportTx,UDPportRx):   # initialize your UDP socket here
    global Socket
    global portRx
    global portTx
    Socket = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM) #create new socket
    if int(UDPportRx) != 0:
        portRx = int(UDPportRx)
    Socket.bind(('', portRx))
    if int(UDPportTx) != 0:
        portTx = int(UDPportTx)


# read the keyfile. The result should be a private key and a keychain of
# public keys
def readKeyChain(filename):
    global publicKeysHex
    global privateKeysHex 
    global publicKeys
    global privateKeys 
    
    if (filename):
        try:
            keyfile_fd = open(filename,"r")
            for line in keyfile_fd:
                words = line.split()
                # check if a comment
                # more than 2 words, and the first word does not have a
                # hash, we may have a valid host/key pair in the keychain
                if ( (len(words) >= 4) and (words[0].find("#") == -1)):
                    host = words[1]
                    port = words[2]
                    keyInHex = words[3]
                    if (words[0] == "private"):
                        privateKeysHex[(host,port)] = keyInHex
                        privateKeys[(host,port)] = nacl.public.PrivateKey(keyInHex, nacl.encoding.HexEncoder)
                    elif (words[0] == "public"):
                        publicKeysHex[(host,port)] = keyInHex
                        publicKeys[(host,port)] = nacl.public.PublicKey(keyInHex, nacl.encoding.HexEncoder)
        except Exception,e:
            print ( "error: opening keychain file: %s %s" % (filename,repr(e)))
    else:
            print ("error: No filename presented")             

    return (publicKeys,privateKeys)

class socket:

    def __init__(self):  # fill in your code here
       global portTx
    #list of connections 
       self.connections = list()
    #define header struct 
       self.hdr_data = struct.Struct('!BBBHQQLL')
    #sequence numbers
       self.outbound_seq_no = random.randint(0, 2**64)
       self.inbound_seq_no = 0
    #address of server 
       self.Address = ("localhost", portTx)
    #own address
       self.selfaddress = ("localhost", portRx)
    #encryption boolean
       self.encrypt = False
    #nonce
       self.nonce = nacl.utils.random(Box.NONCE_SIZE)
    #options
       self.opt = 0
    #keys
       self.privatekey = 0
       self.publickey = 0
       self.box = 0

       self.W = 32768
       self.Q = ""
       self.Qsize = 32768
       self.closed = False
       return
    
    def bind(self,address): #null for part 1
        return 

    def listen(self,backlog): #null for part 1
        return

    #def connect(self,address):  #performs TCP handshake and establishes connection with server
    def connect(self, *args):
        global portTx
        global ENCRYPT
        if (len(args) >= 1):
            self.Address = (args[0][0], portTx) #makes UDP address tuple from 352 address abstraction
        if (len(args) >= 2): 
            if (args[1] == ENCRYPT):
                self.encrypt = True
                self.opt = 1
                if (self.selfaddress[0], str(self.selfaddress[1])) in privateKeys:
                    self.privatekey = privateKeys[(self.selfaddress[0], str(self.selfaddress[1]))]
                else:
                    try:
                        self.privatekey = privateKeys[("*", "*")]
                    except Exception as e:
                        print "private key not found"
                if (self.Address[0], str(self.Address[1])) in publicKeys:
                    self.publickey = publicKeys[(self.Address[0], str(self.Address[1]))]            
                else:
                    try:
                        self.publickey = publicKeys[("*", "*")]
                    except Exception as e:
                        print "public key not found"    
                self.box = Box(self.privatekey, self.publickey)
        header = self.makepacketheader(1, 1, self.opt, 29, self.outbound_seq_no, 0, self.W, 0) #makes SYN
        while 1: #sends SYN and waits for SYNACK
            Socket.sendto(header, self.Address) 
            Socket.settimeout(.2)
            try:
                packet, serveraddress = Socket.recvfrom(2048)
                break
            except syssock.timeout:
                pass
        version, flags, opt, header_len, sequence_no, ack_no, W, payload_len = self.hdr_data.unpack(packet)
        self.inbound_seq_no = sequence_no #sets servers sequence number
        return 

    def accept(self, *args): #creates new TCP connection for data to be sent/received
        global ENCRYPT
        if (len(args) >= 1):
            if (args[0] == ENCRYPT):
                self.encryption = True
                self.opt = 1
                print self.Address
                if (self.selfaddress[0], str(self.selfaddress[1])) in privateKeys:
                    self.privatekey = privateKeys[(self.selfaddress[0], str(self.selfaddress[1]))]
                else:
                    try:
                        self.privatekey = privateKeys[("*", "*")]
                    except Exception as e:
                        print "private key not found"
                if (self.Address[0], str(self.Address[1])) in publicKeys:
                    self.publickey = publicKeys[(self.Address[0], str(self.Address[1]))]            
                else:
                    try:
                        self.publickey = publicKeys[("*", "*")]
                    except Exception as e:
                        print "public key not found"
                self.box = Box(self.privatekey, self.publickey) 
        packet, self.Address = Socket.recvfrom(2048) #waits for SYN
        version, flags, opt, header_len, sequence_no, ack_no, W, payload_len = self.hdr_data.unpack(packet)
        self.inbound_seq_no = sequence_no #sets client's sequence number
        self.outbound_seq_no = random.randint(0, 2**64) #create random outgoing sequence number
        if len(self.connections) == 0: #make sure there are no connections established already
            #create and send SYN back to client
            SYN = self.makepacketheader(1, 1, self.opt, 29, self.outbound_seq_no, self.inbound_seq_no + 1,self.W, 0) 
            Socket.sendto(SYN, self.Address) 
            #create new connection socket
            clientsocket = socket()
            clientsocket.Address = self.Address
            clientsocket.inbound_seq_no = self.inbound_seq_no
            clientsocket.outbound_seq_no = self.outbound_seq_no
            clientsocket.box = self.box
            self.connections.append(clientsocket)
        else: #already connection established
            #send reset packet
            RST = self.makepacketheader(1,8, self.opt, 29, 0, self.inbound_seq_no + 1,self.W, 0)
            Socket.sendto(RST, self.Address)
        return (clientsocket, self.Address)
    
    def close(self):   #closes connection, performs handshake
        FIN = self.makepacketheader(1, 2, self.opt, 29, self.outbound_seq_no, 0,self.W, 0)
        Socket.sendto(FIN, self.Address)
        Socket.close()
        return

    def send(self,buffer):
        totalsent = 0
        while totalsent < len(buffer):
            if self.encrypt == True:
                packet = self.makepacketheader(1, 0, self.opt, 29, self.outbound_seq_no, 0,self.W, len(buffer[totalsent:totalsent+self.W])) + self.box.encrypt(buffer[totalsent:totalsent+self.W], self.nonce) 
            else:
                packet = self.makepacketheader(1, 0, self.opt, 29, self.outbound_seq_no, 0, self.W, len(buffer[totalsent:totalsent+self.W])) + buffer[totalsent:totalsent+self.W]
            while 1: #sends data and waits for ACK back
                Socket.sendto(packet, self.Address)
                Socket.settimeout(.2)    
                try:
                    ACK, serveraddress = Socket.recvfrom(2048)
                    version, flags, opt, header_len, sequence_no, ack_no, self.W, payload_len = self.hdr_data.unpack(ACK)
                    break
                except syssock.timeout:
                    print "timeout"
                    pass
            datasent = ack_no - self.outbound_seq_no
            self.outbound_seq_no = ack_no + 1
            totalsent += datasent
        return datasent

    def recv(self, nbytes):
        if self.closed == False:
            if len(self.Q) >= nbytes:
                retdata = self.Q[:nbytes]
                self.Q = self.Q[nbytes:]
                self.W += len(retdata)
            else:
                packet,address = Socket.recvfrom(65536)#16384
                header = packet[:29]
                version, flags, opt, header_len, sequence_no, ack_no, W, payload_len = self.hdr_data.unpack(header)
                if flags == 2:
                    self.closed = True
                    return ""
                if sequence_no == self.inbound_seq_no:
                    if opt == 1:
                        data = self.box.decrypt(packet[29:])#self.W + 29])
                    else:
                        data = packet[29:]#self.W + 29]
                    self.Q += data
                    self.W -= len(data)
                    self.inbound_seq_no += (len(data) + 1) 
                    retdata = self.Q[:nbytes]
                    self.Q = self.Q[nbytes:]
                    self.W += len(retdata)
                    ACK = self.makepacketheader(1,4, self.opt, 29, 0, self.inbound_seq_no - 1, self.W, 0)
                    Socket.sendto(ACK, self.Address)
                else:
                    retdata = self.Q[:nbytes]
                    self.Q = self.Q[nbytes:]
                    self.W += len(retdata)
        else:
            retdata = self.Q[:nbytes]
            self.Q = self.Q[nbytes:]
            self.W += len(retdata)
        return retdata

    def makepacketheader(self, version, flags, opt, header_len, sequence_no, ack_no, W, payload_len):
        return self.hdr_data.pack(version, flags, opt, header_len, sequence_no, ack_no, W, payload_len)
