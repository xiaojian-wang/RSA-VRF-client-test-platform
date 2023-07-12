from argparse import ArgumentParser
# import sys

# sys.path.append('../VRF/')
# # from VRF import *
from RSA_VRF import *

def write_to_session_file(session_file_join):
    VRF_sk, VRF_pk, k = VRF_keygen()
    my_session_id = "0a94d22e7f2571a34d4948c815535062880748d3cfaf5241991582a1e542d8c2d"
    pi = RSA_FDH_VRF.prove(VRF_sk, my_session_id, k)
    y = RSA_FDH_VRF.proof2hash(pi)
    ip_address = 'localhost:53097'
    data = f"{ip_address}||{VRF_pk}||{y}||{pi}||{k}"
    
    with open(session_file_join, 'a') as f:
        f.write(data)
        f.write('\n')
    print("Writing to session file {}completed.".format(session_file_join))

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-n", "--num-sessions", dest="num_sessions", type=int, default=10,
                        help="number of sessions to join in the market")

    args = parser.parse_args()
    num_sessions = args.num_sessions
    session_file_join = "Market_with_{}.txt".format(num_sessions)

    write_to_session_file(session_file_join)

    print("I have joined in the market with session file:", session_file_join)