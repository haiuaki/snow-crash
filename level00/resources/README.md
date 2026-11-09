# Level 00

## 1. Target Information
- **User:** `level00`
- **Password:** `level00`
- **Target:** `flag00`
- **SSH Port:** `4242`

---

## 2. Reconnaissance & Discovery
We search for files owned by user `flag00` or group `flag00`:

```bash
find / -user flag00 2>/dev/null
```

**Findings:**
- Found two paths containing the same file:
  - `/usr/sbin/john`
  - `/rofs/usr/sbin/john` (Read-only squashfs mount)
- Checking the file content:
```bash
cat /usr/sbin/john
# Output: ***ENCODED_FLAG00***
```

---

## 3. Vulnerability Analysis
- **Flaw Type:** Insecure storage of credentials with weak obfuscation (Caesar Cipher / ROT).
- **Technical Explanation:**
  - The file `/usr/sbin/john` contains an obfuscated password for `flag00`.
  - The string `***ENCODED_FLAG00***` is encrypted using a simple Caesar cipher with a shift of 15 (or ROT-11 backwards).
  - Decrypting `***ENCODED_FLAG00***` with shift 15 yields `***PASS_FLAG00***`.

---

## 4. Exploitation Walkthrough

### Step 1: Decrypt the password
Use the helper script `caesar.sh`:
```bash
echo "***ENCODED_FLAG00***" | ./caesar.sh 15
# Output: ***PASS_FLAG00***
```

### Step 2: Become flag00 and grab the flag
```bash
su flag00
# Password: ***PASS_FLAG00***
getflag
# Check flag.Here is your token : ***FLAG00***
```

---

## 5. Flag
```text
***FLAG00***
```
- **Next Level User:** `level01`
- **Password for next level:** `***FLAG00***`
