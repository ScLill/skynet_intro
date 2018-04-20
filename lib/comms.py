import struct

from Crypto.Cipher import XOR, AES
from Crypto import Random

from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.iv = None
        self.shared_hash = None

        self.initiate_session()


    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret 
        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the clientasdsad

        if self.server or self.client:

            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv_public_key())
            # Obtain our shared secret
            self.shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(self.shared_hash))

            self.shared_hash = bytes.fromhex(calculate_dh_secret(their_public_key, my_private_key))


        self.iv = Random.new().read(AES.block_size)
        self.cipher = AES.new(self.shared_hash, AES.MODE_CBC, self.iv) #XOR.new(shared_hash[:4])


    def send(self, data):

        if self.cipher:

            length = AES.block_size - (len(data) % AES.block_size) 
            padding = bytes([length])*length
            
            data += padding
            encrypted_data = self.iv + self.cipher.encrypt(data)

            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)


    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)

        self.iv = encrypted_data[:AES.block_size]        
        self.cipher = AES.new(self.shared_hash, AES.MODE_CBC, self.iv)

        if self.cipher:

            data = self.cipher.decrypt(encrypted_data)
            data = data[:-data[-1]][len(self.iv):]
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data


    def recv_public_key(self):
        
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]
        public_key = self.conn.recv(pkt_len)

        return public_key


    def close(self):
        self.conn.close()


