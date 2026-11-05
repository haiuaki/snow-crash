#!/bin/sh
# level13 solve: pass the getuid()==4242 gate by interposing a fake getuid()
# via LD_PRELOAD against a non-SUID copy of the binary (token is computed
# in-process, so flag13 privileges are not needed).
set -e

BIN="${1:-$HOME/level13}"

# 1. fake getuid() returning 4242
cat > /tmp/file.c <<'EOF'
#include <sys/types.h>
uid_t getuid(void) { return 4242; }
EOF

# 2. compile as a 32-bit shared library (run from a writable dir for gcc temps)
cd /tmp
gcc -m32 -fPIC -shared -o /tmp/file.so /tmp/file.c

# 3. copy the binary so the SUID bit is dropped and LD_PRELOAD is honored
cp "$BIN" /tmp/l13

# 4. run the copy with the preload -> prints the token
LD_PRELOAD=/tmp/file.so /tmp/l13
