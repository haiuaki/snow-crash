# Level 01

## 1. Target Information
- **User:** `level01`
- **Password:** `***FLAG00***`
- **Target:** `flag01`
- **SSH Port:** `4242`

---

## 2. Reconnaissance & Discovery
We inspect the system user accounts in `/etc/passwd`:

```bash
cat /etc/passwd | grep -E 'level01|flag01'
```

**Findings:**
```text
level01:x:2001:2001::/home/user/level01:/bin/bash
flag01:***HASH_FLAG01***:3001:3001::/home/flag/flag01:/bin/bash
```

- In standard Linux setups, the second field contains an `x`, indicating that the hashed password is stored in `/etc/shadow` (readable only by root).
- For `flag01`, the hash `***HASH_FLAG01***` is directly stored in world-readable `/etc/passwd`.

---

## 3. Vulnerability Analysis
- **Flaw Type:** Insecure storage of sensitive credentials in world-readable file (`/etc/passwd`) using a legacy DES `crypt(3)` hash.
- **Technical Explanation:**
  - Modern systems protect hashed passwords inside `/etc/shadow`. Exposing the hash allows offline dictionary and brute-force attacks.
  - The hash format is traditional Unix DES: exactly 13 characters, where the first two characters (`42`) represent the salt, and the remaining 11 characters (`hDRfypTqqnw`) represent the encrypted text.
  - DES hashes truncate passwords to at most 8 characters, making them trivial to crack with modern hardware.

---

## 4. Exploitation Walkthrough

John the Ripper is external software, so per the subject it is run inside a dedicated container rather than installed on the host or the VM. The `Dockerfile` in this folder provides it:

```dockerfile
FROM alpine:3.23

RUN apk add --no-cache john

WORKDIR /crack

ENTRYPOINT ["john"]
```

The `ENTRYPOINT` makes the container behave like the `john` command itself: anything after the image name is passed straight to john.

### Step 1: Save the hash
Copy the `flag01` entry from the VM's `/etc/passwd` into a file. Only the `login:hash` part is needed:
```bash
echo 'flag01:***HASH_FLAG01***' > hash.txt
```

### Step 2: Build the cracking image (once)
```bash
docker build -t level01-john .
```

### Step 3: Crack the hash
The current folder is mounted at `/crack` so `hash.txt` is read in; nothing is
baked into the image:
```bash
docker run --rm -v "$PWD":/crack level01-john hash.txt
```
john prints the recovered password directly:
```text
Loaded 1 password hash (descrypt, traditional crypt(3) [DES 128/128 ASIMD])
...
***PASS_FLAG01***          (flag01)
```

No `--wordlist` flag is needed: `***PASS_FLAG01***` is present in John's default `password.lst`, so a single `john hash.txt` cracks the DES hash instantly. (`--show` is not used here: with `--rm`, each run is a fresh container and john's pot file is discarded, so the crack output above is the proof.)

The recovered password is confirmed by `su flag01` with `***PASS_FLAG01***` succeeding on the VM. The salt `42` prefixing the stored hash `***HASH_FLAG01***` confirms the traditional DES `crypt(3)` format.

### Step 4: Become flag01 and grab the flag
Back in the Snow Crash terminal:
```bash
su flag01
# Password: ***PASS_FLAG01***
getflag
# Check flag.Here is your token : ***FLAG01***
```

---

## 5. Flag
```text
***FLAG01***
```
- **Next Level User:** `level02`
- **Password for next level:** `***FLAG01***`
