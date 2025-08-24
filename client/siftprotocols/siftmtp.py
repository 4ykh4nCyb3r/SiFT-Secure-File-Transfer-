# python3

import socket
import os
import struct
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

from Crypto.PublicKey import ECC
from Crypto.Hash import SHAKE128
from Crypto.Protocol.DH import key_agreement

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes

class SiFT_MTP_Error(Exception):
    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
    def __init__(self, peer_socket):
        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.version_major = 1
        self.version_minor = 1
        self.msg_hdr_ver = b'\x01\x01'
        self.size_msg_hdr = 16
        self.size_msg_hdr_ver = 2
        self.size_msg_hdr_typ = 2
        self.size_msg_hdr_len = 2
        self.size_msg_hdr_sqn = 2
        self.size_msg_hdr_rnd = 6
        self.size_msg_hdr_rsv = 2
        self.size_mac = 12
        self.size_skey = 32 #session key size
        self.size_ecdh_public_key = 91 #size of public key in bytes
        self.type_login_req = b'\x00\x00'
        self.type_login_res = b'\x00\x10'
        self.type_command_req = b'\x01\x00'
        self.type_command_res = b'\x01\x10'
        self.type_upload_req_0 = b'\x02\x00'
        self.type_upload_req_1 = b'\x02\x01'
        self.type_upload_res = b'\x02\x10'
        self.type_dnload_req = b'\x03\x00'
        self.type_dnload_res_0 = b'\x03\x10'
        self.type_dnload_res_1 = b'\x03\x11'
        self.msg_types = (
            self.type_login_req, self.type_login_res,
            self.type_command_req, self.type_command_res,
            self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
            self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1
        )
        # --------- STATE ------------
        self.peer_socket = peer_socket
        self.send_sqn = 0
        self.recv_sqn = 0
        #self.temp_key = None
        self.session_key = None
        # Load ECCDH keys
        try:
            with open('ecdh-client-private_key.pem', 'r') as f:
                self.ecc_private_key = ECC.import_key(f.read())
            self.is_client = True
        except FileNotFoundError: #If private key if server is not found, then it is a client
            try:
                with open('ecdh-server-private_key.pem', 'r') as f:
                    self.ecc_private_key = ECC.import_key(f.read())
                self.is_client = False
            except FileNotFoundError:
                raise SiFT_MTP_Error('ECDH key file not found')
        # Load respective public keys
        if self.is_client:
            with open('ecdh-client-public_key.pem', 'r') as f:
                self.ecc_public_key = ECC.import_key(f.read())
            with open('ecdh-server-public_key.pem', 'r') as f:
                self.peer_ecc_public_key = ECC.import_key(f.read())
        else:
            self.peer_ecc_public_key = None #client will send its public key

    def parse_msg_header(self, msg_hdr):
        parsed_msg_hdr = {}
        parsed_msg_hdr['ver'] = msg_hdr[0:2]
        parsed_msg_hdr['typ'] = msg_hdr[2:4]
        parsed_msg_hdr['len'] = msg_hdr[4:6]
        parsed_msg_hdr['sqn'] = msg_hdr[6:8]
        parsed_msg_hdr['rnd'] = msg_hdr[8:14]
        parsed_msg_hdr['rsv'] = msg_hdr[14:16]
        return parsed_msg_hdr

    def build_msg_header(self, msg_type, msg_len, sqn, rnd):
        return (self.msg_hdr_ver + msg_type +
                msg_len.to_bytes(2, 'big') +
                sqn.to_bytes(2, 'big') +
                rnd + b'\x00\x00')

    def receive_bytes(self, n):
        bytes_received = b''
        bytes_count = 0
        while bytes_count < n:
            try:
                chunk = self.peer_socket.recv(n - bytes_count)
            except:
                raise SiFT_MTP_Error('Unable to receive via peer socket')
            if not chunk:
                raise SiFT_MTP_Error('Connection with peer is broken')
            bytes_received += chunk
            bytes_count += len(chunk)
        return bytes_received

    def kdf(self, x):
        return SHAKE128.new(x).read(32)
    
    def generate_session_key(self, peer_ecc_public_key, id=None):
        shared_secret = key_agreement(static_priv=self.ecc_private_key, static_pub=peer_ecc_public_key, kdf=self.kdf)
        if self.is_client:
            # Generate a random session identifier
            session_id = get_random_bytes(16)
            self.session_id = session_id
        else:
            if id is None:
                raise SiFT_MTP_Error('Session ID must be provided by server')
            session_id = id
        
        #combine the shared secret with the session identifier
        combined_input = shared_secret + session_id
        self.session_key = self.kdf(combined_input) # derive the session key using the combined input


    def encrypt_payload(self, msg_type, header, payload, sqn, rnd):
        if msg_type == self.type_login_req:
            self.generate_session_key(self.peer_ecc_public_key)
            key = self.session_key
        else:
            key = self.session_key
        if not key:
            raise SiFT_MTP_Error(f'No encryption key available for msg_type {msg_type.hex()}')
        if self.DEBUG:
            print(f'Encrypting with key: {key.hex()}')
        nonce = sqn.to_bytes(2, 'big') + rnd
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        return ciphertext, tag

    def decrypt_payload(self, msg_type, header, ciphertext, tag, sqn, rnd):
        key = self.session_key
        if not key:
            raise SiFT_MTP_Error(f'No decryption key available for msg_type {msg_type.hex()}')
        if self.DEBUG:
            print(f'Decryption key: {key.hex()}')
        nonce = sqn.to_bytes(2, 'big') + rnd
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        cipher.update(header)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise SiFT_MTP_Error('Decryption or authentication failed')
        return plaintext

    def receive_msg(self):
        if self.DEBUG:
            print(f'Receiving on {"client" if self.is_client else "server"} side')
        try:
            msg_hdr = self.receive_bytes(self.size_msg_hdr)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

        if len(msg_hdr) != self.size_msg_hdr:
            raise SiFT_MTP_Error('Incomplete message header received')

        parsed_msg_hdr = self.parse_msg_header(msg_hdr)

        if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
            raise SiFT_MTP_Error('Unsupported version found in message header')

        if parsed_msg_hdr['typ'] not in self.msg_types:
            raise SiFT_MTP_Error('Unknown message type found in message header')

        msg_len = int.from_bytes(parsed_msg_hdr['len'], 'big')
        sqn = int.from_bytes(parsed_msg_hdr['sqn'], 'big')
        # --DEBUG ----
        if self.DEBUG:
            print(f"Message header: ", msg_hdr.hex())
            print(f"message length: {msg_len}")
            print(f"message sequence number: {sqn}")
        # -----
        rnd = parsed_msg_hdr['rnd']

        if sqn <= self.recv_sqn:
            raise SiFT_MTP_Error('Invalid sequence number')

        try:
            if parsed_msg_hdr['typ'] == self.type_login_req:
                msg_body = self.receive_bytes(msg_len - self.size_msg_hdr - self.size_ecdh_public_key - 16)
                pub_bytes = self.receive_bytes(self.size_ecdh_public_key)
                session_id = self.receive_bytes(16)  # Receive the session identifier
                if self.DEBUG:
                    print(f'Public key received ({len(pub_bytes)}): {pub_bytes.hex()}')
                    print(f'Session ID received ({len(session_id)}): {session_id.hex()}')
                self.peer_ecc_public_key = ECC.import_key(pub_bytes)
                self.session_id = session_id  # Store the session identifier
                if not self.is_client:
                    try:
                        self.generate_session_key(self.peer_ecc_public_key, session_id)
                    except ValueError as e:
                        raise SiFT_MTP_Error(f'Failed to generate session key: {str(e)}')
            else:
                msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		
        ciphertext = msg_body[:-self.size_mac]
        tag = msg_body[-self.size_mac:]
    
        try:
            payload = self.decrypt_payload(parsed_msg_hdr['typ'], msg_hdr, ciphertext, tag, sqn, rnd)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error('Payload decryption failed --> ' + e.err_msg)

        self.recv_sqn = sqn
         # --- mine ----
        if self.DEBUG:
            print()
            print("Encrypted message received: ")
            print(f'MTP message received: {msg_len}')
            print(f'HDR ({len(msg_hdr)}): {msg_hdr.hex()}')
            print(f'BDY ({len(ciphertext)}): {ciphertext.hex()}')
            print(f'TAG ({len(tag)}): {tag.hex()}')
            #print(f'(Client public key) ({len(pub_bytes)}): {pub_bytes.hex()}')
            print()
        # ----------

        if self.DEBUG:
            print("Decrypted message: ")
            print(f'MTP message received ({msg_len}):')
            print(f'HDR ({len(msg_hdr)}): {msg_hdr.hex()}')
            print(f'BDY ({len(payload)}): {payload.hex()}')
            if parsed_msg_hdr['typ'] == self.type_login_req:
                print(f'Public key  ({len(pub_bytes)}): {pub_bytes.hex()}')
            print('------------------------------------------')

        return parsed_msg_hdr['typ'], payload

    def send_msg(self, msg_type, msg_payload):
        if self.DEBUG:
            print(f'Sending message from {"client" if self.is_client else "server"}')
            print(f'payload length: {len(msg_payload)}')
            print(f'Sent sequence number: {self.send_sqn}')
            print(f'Received sequence number: {self.recv_sqn}')
        
        # ----- mine ----
        if msg_type != self.type_login_req:
            msg_size = self.size_msg_hdr + len(msg_payload) + self.size_mac
        else:
            msg_size = self.size_msg_hdr + len(msg_payload) + self.size_mac + self.size_ecdh_public_key + 16
        # ---------
        
        
		#build message
        self.send_sqn += 1
        rnd = get_random_bytes(6)
        msg_hdr = self.build_msg_header(msg_type, msg_size, self.send_sqn, rnd)
        ciphertext, tag = self.encrypt_payload(msg_type, msg_hdr, msg_payload, self.send_sqn, rnd)

        if msg_type == self.type_login_req:
            try:
                public_key = self.ecc_public_key.export_key(format='DER')
            except ValueError as e:
                raise SiFT_MTP_Error(f'Own public key not found: {str(e)}')
            
            # Include the session identifier in the login request payload
            #here self.session_id is already initialized in the encrypt_payload function when the session key is generated
            msg_body = ciphertext + tag + public_key + self.session_id
        else:
            msg_body = ciphertext + tag

        msg_size = self.size_msg_hdr + len(msg_body)

        

        if self.DEBUG:
            print()
            print(f'MTP message to send ({msg_size}):')
            print(f'HDR ({len(msg_hdr)}): {msg_hdr.hex()}')
            print(f'Body length: {len(msg_body)}')
            print(f'BDY ({len(ciphertext)}): {ciphertext.hex()}')
            print(f'TAG ({len(tag)}): {tag.hex()}')
            print(f'Session ID ({len(self.session_id)}): {self.session_id.hex()}')
            if msg_type == self.type_login_req:
                print(f'Public key  ({len(public_key)}): {public_key.hex()}')
            #print(f'Public key  ({len(public_key)}): {public_key.hex()}')
            print('------------------------------------------')
            print('------------------------------------------')

        try:
            self.peer_socket.sendall(msg_hdr + msg_body)
        except:
            raise SiFT_MTP_Error('Unable to send message to peer')