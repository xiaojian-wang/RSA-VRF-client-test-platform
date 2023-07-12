#!/bin/bash

for i in {10..50..10}; do
    find_verifier_file="find_verifier_time_$i.txt"
    check_proof_file="check_proof_time_$i.txt"
    
    if [ -f "$find_verifier_file" ]; then
        echo "Deleting existing $find_verifier_file"
        rm -f "$find_verifier_file"
    fi
    
    if [ -f "$check_proof_file" ]; then
        echo "Deleting existing $check_proof_file"
        rm -f "$check_proof_file"
    fi
    
    echo "Running python choose_verifier.py -n $i 1000 times"
    for ((j=1; j<=1000; j++)); do
        python choose_verifier.py -n $i
    done
done
