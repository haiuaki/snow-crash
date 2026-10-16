#!/bin/sh
# Caesar cipher: shifts each letter by a given amount.
# Usage: echo "text" | ./caesar.sh <shift>

# First argument is the shift amount
shift_n=$1

# Plain alphabet
from="abcdefghijklmnopqrstuvwxyz"

# Build the shifted alphabet:
# 	- "$from$from" doubles it (52 letters so wrap-around is automatic)
# 	- `cut` grabs a 26-letter window starting at the shift offset
#	- +1 converts the 0-based shit into `cut`'s 1-based position
#	- +26 marks the end of the 26-letter window
to=$(echo "$from$from" | cut -c$((shift_n + 1))-$((shift_n + 26)))

# SET1 = all letters we might translate, lowercase then uppercase
# The inner `tr` upcases the alphabet to build the uppercase block
# e.g, abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
SET1=$from$(echo "$from" | tr 'a-z' 'A-Z')

# SET2 = the shifted equivalents, in the same order (lower then upper)
# e.g.: defghijklmnopqrstuvwxyzabcDEFGHIJKLMNOPQRSTUVWXYZABC
SET2=$to$(echo "$to" | tr 'a-z' 'A-Z')

# Translate input: each char in SET1 becomes the char at the same
# position in SET2. Letters shift, anything else passes through.
# Quotes keep each set as a single argument.
tr "$SET1" "$SET2"
