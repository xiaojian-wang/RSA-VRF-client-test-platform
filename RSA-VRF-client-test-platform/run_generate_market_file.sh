#!/bin/bash

for i in {10..50..10}; do
    file="Market_with_$i.txt"
    if [ -f "$file" ]; then
        echo "Deleting existing $file"
        rm -f "$file"
    fi

    echo "Running python generate_market_file.py -n $i"
    for ((j=1; j<=$i; j++)); do
        python generate_market_file.py -n $i
    done
done
