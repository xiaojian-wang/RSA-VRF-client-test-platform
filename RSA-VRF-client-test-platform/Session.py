# Session.py
# other file can import this file to get the session object and update it
import json
import time
# from pairing import Element
import base64
# from charm.toolbox.pairinggroup import PairingGroup
import hashlib

import sys
sys.path.append('../../../VRF/')
from RSA_VRF import *

import codecs

class Session:
    def __init__(self):
        self.session_id = None
        self.variables = {}
        self.task_info = {} # (task_type, task_hash)
        self.start_time = None
        self.duration = None
        # self.group = PairingGroup('SS512')
        self.k = 0 # for the RSA key's k

    def next_session(self, session_id, duration):
        if self.session_id:
            self.save_session_data()
        self.session_id = session_id
        self.variables = {}
        self.task_info = {}
        self.start_time = time.time()
        self.duration = duration

    def is_session_expired(self):
        if self.start_time is None or self.duration is None:
            return False
        current_time = time.time()
        elapsed_time = current_time - self.start_time
        return elapsed_time >= self.duration

    def get_variable(self, ip_address):
        return self.variables.get(ip_address)

    def set_variable(self, ip_address, pk, output, proof,k):
        variable = {
            'pk': pk,
            'output': output,
            'proof': proof,
            'k': int(k)
        }
        self.variables[ip_address] = variable

    def get_task_info(self):
        return self.task_info

    def set_task_info(self, task_type, task_hash):
        self.task_info = (task_type, task_hash)

    def find_min_output_variable(self):
        min_output = float('inf')
        # min_output = None
        min_ip_address = None
        min_pk = None
        min_proof = None
        min_k = None

        for ip_address, variable in self.variables.items():
            output = variable['output']
            # output_string = base64.b64encode(self.group.serialize(output)).decode('utf-8')
            # output_hash_value = hashlib.sha256(output_string.encode()).hexdigest()
            output_hash_value = hashlib.sha256(str(output).encode()).hexdigest()
            # output_bytes = output.export()
            output_value = float(int(output_hash_value, 16))
            returned_output = None
            if output_value < min_output:
                min_output = output_value
                min_ip_address = ip_address
                min_pk = variable['pk']
                min_proof = variable['proof'] 
                min_k = variable['k']
                returned_output = output

        return min_ip_address, min_pk,returned_output, min_proof, min_k


    def find_second_min_output_variable(self):
        min_output = float('inf')
        second_min_output = float('inf')
        min_ip_address = None
        min_pk = None
        min_proof = None
        min_k = None
        second_min_ip_address = None
        second_min_pk = None
        second_min_proof = None
        second_min_k = None

        for ip_address, variable in self.variables.items():
            output = variable['output']
            output_hash_value = hashlib.sha256(str(output).encode()).hexdigest()
            output_value = float(int(output_hash_value, 16))
            returned_output = None

            if output_value < min_output:
                second_min_output = min_output
                second_min_ip_address = min_ip_address
                second_min_pk = min_pk
                second_min_proof = min_proof
                second_min_k = min_k

                min_output = output_value
                min_ip_address = ip_address
                min_pk = variable['pk']
                min_proof = variable['proof']
                min_k = variable['k']
                returned_output = output
            elif min_output < output_value < second_min_output:
                second_min_output = output_value
                second_min_ip_address = ip_address
                second_min_pk = variable['pk']
                second_min_proof = variable['proof']
                second_min_k = variable['k']

        return second_min_ip_address, second_min_pk, returned_output, second_min_proof, second_min_k



    def save_session_data(self):
        if self.session_id:
            file_name = f"{self.session_id}.json"
            data = {
                'session_id': self.session_id,
                'variables': self.variables,
                'start_time': self.start_time,
                'duration': self.duration
            }
            with open(file_name, 'w') as f:
                json.dump(data, f)

    def load_session_data(self):
        if self.session_id:
            file_name = f"{self.session_id}.json"
            try:
                with open(file_name, 'r') as f:
                    data = json.load(f)
                self.session_id = data['session_id']
                self.variables = data['variables']
                self.start_time = data['start_time']
                self.duration = data['duration']
            except FileNotFoundError:
                self.variables = {}
                self.start_time = None
                self.duration = None

    def get_session_id(self):
        return self.session_id
    
    def get_session_duration(self):
        return self.duration
    


    def read_session_file(self, session_file_path):
        file_name = session_file_path
        try:
            with open(file_name, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    line = line.strip()
                    # print("line: ", line)
                    ip_address, vrf_pk_str, y_str, pi_str, k_str = line.split('||')


                    def reconstruct_public_key(public_key_string):
                        n_start = public_key_string.find("n: ") + 3
                        n_end = public_key_string.find(" ", n_start)
                        n = int(public_key_string[n_start:n_end])

                        e_start = public_key_string.find("e: ") + 3
                        e_end = public_key_string.find(" ", e_start)
                        e = int(public_key_string[e_start:e_end])

                        # bit_size_start = public_key_string.find("bit_size: ") + 10
                        # bit_size_end = public_key_string.find(" ", bit_size_start)
                        # bit_size = int(public_key_string[bit_size_start:bit_size_end])

                        # byte_size_start = public_key_string.find("byte_size: ") + 11
                        # byte_size_end = public_key_string.find(">", byte_size_start)
                        # byte_size = int(public_key_string[byte_size_start:byte_size_end])

                        public_key = RSA_PublicKey(n, e)
                        
                        return public_key
                    # change vrf_pk_str to bytes
                    # vrf_pk_bytes = base64.b64decode(vrf_pk_str.encode('utf-8'))
                    vrf_pk = reconstruct_public_key(vrf_pk_str)

                    # Restore pairing.Element objects
                    # print("ip_address: ", ip_address)
                    # print("vrf_pk_str: ", vrf_pk_str)
                    # print("y_str: ", y_str)
                    # print("pi_str: ", pi_str)

                    # vrf_pk_bytes = base64.b64decode(vrf_pk_str.encode('utf-8'))
                    # vrf_pk = self.group.deserialize(vrf_pk_bytes)
                    # vrf_pk = get_VRFPK_from_bytes(vrf_pk_bytes)
                    # print("read out the vrf_pk: ", vrf_pk)
                    

                    # y_bytes = base64.b64decode(y_str.encode('utf-8'))
                    # y = self.group.deserialize(y_bytes)
                    # print("y_str: ", y_str)
                    # print("type of y_str: ", type(y_str))
                    # y_list = list(y_str)
                    # y = bytes(y_list)
                    # # change string to bytes
                    
                    # # (y_string.encode('latin-1')[2:-1])
                    y_tmp = y_str[2:-1]
                    # y_tmp = y_str[1:]
                    # print("y_tmp: ", y_tmp)
                    # print("type of y_tmp: ", type(y_tmp))
                    # y_tmp = y_str[1:]
                    # y = bytes(y_tmp,'raw_unicode_escape')
                    y = codecs.escape_decode(y_tmp)[0]
                    # y_tmp_2 = 'r' + y_tmp
                    # print("y_tmp: ", y_tmp)
                    # print("type of y_tmp: ", type(y_tmp))
                    # # y = bytes.fromhex(y_tmp.replace('\\x', ''))
                    # # y = y_tmp.encode('utf-8')
                    # y = bytes(y_tmp_2, 'utf-8')
                    # # y = y_tmp.encode('raw_unicode_escape')
                    # # y = y_str.encode('latin-1')[2:-1]

                    # print("type of y: ", type(y))
                    # print("y: ", y)
                    # y = bytes.fromhex(y_str)

                    # pi_bytes = base64.b64decode(pi_str.encode('utf-8'))
                    # pi = self.group.deserialize(pi_bytes)
                    pi_tmp = pi_str[2:-1]
                    # pi_tmp = pi_str[1:]
                    # pi_tmp_r = 'r' + pi_tmp
                    # print("pi_tmp: ", pi_tmp)
                    # print("type of pi_tmp: ", type(pi_tmp))
                    # pi = pi_tmp_r.encode('utf-8')
                    # pi = bytes(pi_tmp,'raw_unicode_escape')
                    pi = codecs.escape_decode(pi_tmp)[0]
                    # print("type of pi: ", type(pi))
                    # print("pi: ", pi)
                    # pi = pi_str.encode('utf-32')
                    # pi = bytes.fromhex(pi_str)


                    k = k_str
                    self.set_variable(ip_address, vrf_pk, y,pi, k)
        except FileNotFoundError:
            return None

# global session
# session = Session()