#!/bin/sh
# Reverses level09's encoding: out[i] = in[i] + i  =>  in[i] = out[i] - i
# Usage: ./index_shift.sh token  or  cat token | ./index_shift.sh

# "od -An -v -tu1" converts file to number, printing each byte as numbers
# -tu1: one byte at a time
# -An: drops the offset
# -v: stops od from shortening repeated lines

i=0
for byte in $(od -An -v -tu1 "$@"); do
    [ "$byte" -eq 10 ] && continue          # skip the trailing newline
    printf "\\$(printf '%03o' $((byte - i)))"
    i=$((i + 1))
done
echo
