# Level 09

## 1. Target Information
- **User:** `level09`
- **Password:** `***FLAG08***`
- **Target:** `flag09`
- **SSH Port:** `4242`

---

## 2. Reconnaissance & Discovery
Look at the home directory:

```bash
ls -la
cat token
```

**Findings:**
- A SUID executable `level09` owned by `flag09`, and a `token` file that `level09` **can** read.
- `cat token` prints garbage mixed with non-printable bytes (`<82>`, `<83>`, `<7f>`...), so the token is not stored in clear — it looks encoded.
- Passing the file to the binary does not read it: `./level09 token` just encodes the **string** `"token"`. The binary works on its argument, not on a file.

### Probing the binary with known inputs
Feed it simple, predictable strings and compare input vs output:

```bash
./level09 abc
# ace
./level09 12345
# 13579
```

| index `i` | 0 | 1 | 2 | 3 | 4 |
|-----------|---|---|---|---|---|
| input     | `a` | `b` | `c` | | |
| output    | `a` | `c` | `e` | | |
| input     | `1` | `2` | `3` | `4` | `5` |
| output    | `1` | `3` | `5` | `7` | `9` |

Each character is shifted forward by its **position** in the string (0, +1, +2, +3, ...):

```text
out[i] = in[i] + i
```

The `token` file is very likely the output of this same encoding applied to `flag09`'s password.

### Reading the raw bytes
The terminal can't display bytes above `0x7e`, so inspect the token in hex:

```bash
xxd token
```
```text
0000000: 6634 6b6d 6d36 707c 3d82 7f70 826e 8382  f4kmm6p|=..p.n..
0000010: 4442 8344 757b 7f8c 890a                 DB.Du{....
```
- Left column: offset of the line's first byte (`0x10` = 16).
- Middle: the bytes in hex, two digits per byte.
- Right: ASCII view, `.` for non-printable bytes.
- The last byte `0a` is the trailing newline, not part of the token.

Bytes like `0x82` appear because a late character plus a large index overflows the printable range (e.g. `'y'` = `0x79`, at index 9 → `0x82`).

---

## 3. Vulnerability Analysis
- **Flaw Type:** Weak, reversible "encryption" (position-dependent Caesar shift) with no key.
- **Technical Explanation:**
  - The secret is protected only by an **encoding**, not by encryption: the transformation is public (the binary is runnable) and uses no secret key.
  - Each step is trivially invertible: if `out[i] = in[i] + i`, then `in[i] = out[i] - i`.
  - Since the encoded `token` is readable by `level09`, anyone can reverse it and recover `flag09`'s password. The SUID bit on the binary is irrelevant here — the leak is the readable, reversibly encoded file.
  - **Fix:** never store a password in a reversible form. Use a proper one-way hash (bcrypt/argon2) or real encryption with a key that the attacker can't access, and don't make the file world-readable.

---

## 4. Exploitation Walkthrough

### Step 1: Copy the token to the host (from the host machine)
```bash
scp -P 4242 level09@<VM_IP>:token .
```
`scp` copies the raw bytes untouched, so the decoder sees the exact values from `xxd`.

`scp` also copies the file's **permission bits**. On the VM, `token` is readable through its *group* (`level09`), but its *owner* (`flag09`) has no read bit. On the host the copy is owned by us, so the owner bits apply and we can't read our own file:
```bash
./index_shift.sh token
# od: token: Permission denied
ls -l token
# --w-r--r--  1 <you> staff 26 ... token     <- owner has no 'r'
```
Give the owner read permission back:
```bash
chmod u+r token
```

### Step 2: Reverse the shift
Subtract each byte's index from its value:

| i | byte | − i | char |
|---|------|-----|------|
| 0 | `0x66` | `0x66` | `f` |
| 1 | `0x34` | `0x33` | `3` |
| 2 | `0x6b` | `0x69` | `i` |
| 9 | `0x82` | `0x79` | `y` |
| 14 | `0x83` | `0x75` | `u` |
| ... | | | |
| 24 | `0x89` | `0x71` | `q` |

Automated with the helper script [`index_shift.sh`](index_shift.sh):
```bash
./index_shift.sh token
# ***PASS_FLAG09***
```
Sanity check that the decoder is the exact inverse of the binary. First send the script to the VM (from the host). The home directory isn't writable by `level09`, so it goes to `/tmp`:
```bash
scp -P 4242 index_shift.sh level09@<VM_IP>:/tmp/d.sh
```
Then on the VM (the script is passed to `sh` by name, so it runs even without the execute bit):
```bash
./level09 hello > /tmp/t; sh /tmp/d.sh /tmp/t
# hello
```

### Step 3: Become flag09 and grab the flag
```bash
su flag09
# Password: ***PASS_FLAG09***
getflag
# Check flag.Here is your token: ***FLAG09***
```

---

## 5. Flag
```text
Check flag.Here is your token: ***FLAG09***
```
- **Next Level User:** `level10`
- **Password for next level:** `***FLAG09***`
