from argparse import ArgumentParser
from RSA_VRF import *

import Session
import time

def read_market_file_and_find_smallest_verifier_then_check_its_proof(session_file_path,num_sessions):
    session = Session.Session()
    time_find_verifier_start = time.time()
    session.read_session_file(session_file_path)
    min_ip_address, min_pk, min_output, min_proof, min_k = session.find_min_output_variable()
    my_session_id = "0a94d22e7f2571a34d4948c815535062880748d3cfaf5241991582a1e542d8c2d"
    x = my_session_id
    y = min_output
    pi = min_proof
    pk = min_pk
    k = min_k  
    time_find_verifier_end = time.time()
    print("time_find_verifier: ", time_find_verifier_end - time_find_verifier_start)
    print("min_output: ", y)
    find_verifier_time_file_name = "find_verifier_time_{}.txt".format(num_sessions)
    with open(find_verifier_time_file_name, 'a') as f:
        f.write(str(time_find_verifier_end - time_find_verifier_start))
        f.write('\n')

    time_check_proof_start = time.time()
    verify_result = RSA_FDH_VRF.verifying(pk,x,pi,k)
    time_check_proof_end = time.time()
    print("time_check_proof: ", time_check_proof_end - time_check_proof_start)
    check_proof_time_file_name = "check_proof_time_{}.txt".format(num_sessions)
    with open(check_proof_time_file_name, 'a') as f:
        f.write(str(time_check_proof_end - time_check_proof_start))
        f.write('\n')
    if verify_result == 'VALID':
        print("The proof is valid.")







if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-n", "--num-sessions", dest="num_sessions", type=int, default=10,
                        help="number of sessions to join in the market")

    args = parser.parse_args()
    num_sessions = args.num_sessions
    session_file_join = "Market_with_{}.txt".format(num_sessions)

    read_market_file_and_find_smallest_verifier_then_check_its_proof(session_file_join,num_sessions)