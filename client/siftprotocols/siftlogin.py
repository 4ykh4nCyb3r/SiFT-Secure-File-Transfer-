# python3

import time
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Random import get_random_bytes
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error

class SiFT_LOGIN_Error(Exception):
    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_LOGIN:
    def __init__(self, mtp):

        self.DEBUG = True
        # ---------- Constants ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
        self.acceptance_window = 2  # seconds
        # ---------- State ------------
        self.mtp = mtp
        self.server_users = None

    def set_server_users(self, users):
        self.server_users = users

    def build_login_req(self, login_req_struct):
        # Generate a timestamp and a random client nonce
        timestamp = str(int(time.time() * 1_000_000_000))
        #client_random = get_random_bytes(16).hex()

        #login_req_struct['client_random'] = client_random  # Store for key derivation
        login_req_str = (timestamp + self.delimiter +
                         login_req_struct['username'] + self.delimiter +
                         login_req_struct['password'] )
        return login_req_str.encode(self.coding)

    def parse_login_req(self, login_req):
        login_req_fields = login_req.decode(self.coding).split(self.delimiter)
        if len(login_req_fields) != 3:
            raise SiFT_LOGIN_Error('Invalid login request format')
        login_req_struct = {
            'timestamp': login_req_fields[0],
            'username': login_req_fields[1],
            'password': login_req_fields[2],
        }
        return login_req_struct

    def build_login_res(self, login_res_struct):
        login_res_str = (login_res_struct['request_hash'].hex())
        return login_res_str.encode(self.coding)

    def parse_login_res(self, login_res):
        login_res_fields = login_res.decode(self.coding).split(self.delimiter)
        if len(login_res_fields) != 1:
            raise SiFT_LOGIN_Error('Invalid login response format')
        login_res_struct = {
            'request_hash': bytes.fromhex(login_res_fields[0])
        }
        return login_res_struct

    def check_password(self, pwd, usr_struct):
        pwdhash = PBKDF2(pwd.encode(self.coding), usr_struct['salt'],
                         len(usr_struct['pwdhash']), count=usr_struct['icount'],
                         hmac_hash_module=SHA256)
        return pwdhash == usr_struct['pwdhash']

    def handle_login_server(self):
        if not self.server_users:
            raise SiFT_LOGIN_Error('User database is required for handling login at server')

        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login request --> ' + e.err_msg)

        if self.DEBUG:
            print(f'Incoming payload ({len(msg_payload)}):')
            print(msg_payload.decode('utf-8', errors='ignore')[:512])
            print('------------------------------------------')

        if msg_type != self.mtp.type_login_req:
            raise SiFT_LOGIN_Error('Login request expected, but received something else')

        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        login_req_struct = self.parse_login_req(msg_payload)

        try:
            timestamp = int(login_req_struct['timestamp'])
            current_time_ns = int(time.time() * 1_000_000_000)
            if not (current_time_ns - 1_000_000_000 * self.acceptance_window <
                    timestamp <
                    current_time_ns + 1_000_000_000 * self.acceptance_window):
                raise SiFT_LOGIN_Error('Timestamp outside acceptance window')
        except ValueError:
            raise SiFT_LOGIN_Error('Invalid timestamp format')

        if login_req_struct['username'] not in self.server_users:
            raise SiFT_LOGIN_Error('Unknown user attempted to log in')

        if not self.check_password(login_req_struct['password'], self.server_users[login_req_struct['username']]):
            raise SiFT_LOGIN_Error('Password verification failed')

        #server_random = get_random_bytes(16)
        login_res_struct = {
            'request_hash': request_hash
        }
        msg_payload = self.build_login_res(login_res_struct)

        if self.DEBUG:
            print(f'Outgoing payload ({len(msg_payload)}):')
            print(msg_payload.decode('utf-8', errors='ignore')[:512])
            print('------------------------------------------')

        try:
            self.mtp.send_msg(self.mtp.type_login_res, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login response --> ' + e.err_msg)

        if self.DEBUG:
            print(f'User {login_req_struct["username"]} logged in')
        return login_req_struct['username']

    def handle_login_client(self, username, password):

        # building login request
        login_req_struct = {
            'username': username,
            'password': password
        }
        msg_payload = self.build_login_req(login_req_struct)
        #print(f"login request payload: {msg_payload.hex()}")

        if self.DEBUG:
            print(f'Outgoing payload ({len(msg_payload)}):')
            print(msg_payload.decode('utf-8', errors='ignore')[:512])
            print('------------------------------------------,')
            print('------------------------------------------')
        
        # trying to send login request
        try:
            self.mtp.send_msg(self.mtp.type_login_req, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login request --> ' + e.err_msg)

        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login response --> ' + e.err_msg)

        if self.DEBUG:
            print(f'Incoming payload ({len(msg_payload)}):')
            print(msg_payload.decode('utf-8', errors='ignore')[:512])
            print('------------------------------------------')

        if msg_type != self.mtp.type_login_res:
            raise SiFT_LOGIN_Error('Login response expected, but received something else')

        login_res_struct = self.parse_login_res(msg_payload)

        if login_res_struct['request_hash'] != request_hash:
            raise SiFT_LOGIN_Error('Verification of login response failed')
