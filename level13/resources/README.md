# Level 13

## 1. Target Information
- **User:** `level13`
- **Password:** `***FLAG12***`
- **Target:** `flag13`
- **SSH Port:** `4242`

---

## 2. Reconnaissance & Discovery
Look at the home directory:

```bash
ls -la
file level13
ltrace ./level13
```

**Findings:**
- A single SUID binary `level13` owned by `flag13`:

```
-rwsr-sr-x 1 flag13 level13 ... level13
```

- Running it refuses to continue unless our UID is `4242`:

```bash
level13@SnowCrash:~$ ltrace ./level13
__libc_start_main(0x804858c, 1, 0xbffffd04, 0x80485f0, 0x8048660 <unfinished ...>
getuid()                                        = 2013
getuid()                                        = 2013
printf("UID %d started us but we we expe"..., 2013UID 2013 started us but we we expect 4242
)                                               = 42
exit(1 <unfinished ...>
+++ exited (status 1) +++
```

**Key observations:**
- The binary is **SUID flag13**, so its success path runs with flag13's privileges.
- It calls `getuid()` twice and bails with `exit(1)` unless the value is `4242`.
- The `ltrace` shows **no file open/read** before the gate — the token is computed **in-process**, not read from a flag13-owned file. This means we only need to pass the UID check; we do **not** actually need flag13's privileges to produce the token.

---

## 3. Vulnerability Analysis
- **Flaw Type:** Authorization based on `getuid()`, a library call that can be interposed.
- **Technical Explanation:**
  - The program trusts the return value of `getuid()` to decide whether the caller is allowed. We cannot change our real UID (only root can), so the direct approach is a dead end.
  - `getuid()` is resolved at runtime from libc through the PLT. With `LD_PRELOAD` we can load our own shared library first and provide a `getuid()` that returns `4242`, so the program's calls bind to ours instead of libc's.
  - Normally the loader **ignores `LD_PRELOAD` for SUID binaries** (secure-execution mode), which would block the trick. But because the token is computed in-process (no privileged file read), we do not need the SUID bit at all: copying the binary yields a non-SUID copy owned by `level13`, for which `LD_PRELOAD` is honored.
  - **Root cause / fix:** never use `getuid()` (or any interposable library call) as a security boundary for a SUID program. Identity checks must be enforced by the kernel / a non-bypassable mechanism, and secrets must not be reconstructable purely from the binary's own logic.

---

## 4. Exploitation Walkthrough

### Step 1: Write a fake `getuid()` that returns 4242
```c
// /tmp/file.c
#include <sys/types.h>
uid_t getuid(void) { return 4242; }
```

### Step 2: Compile it as a 32-bit shared library
The binary is 32-bit (addresses `0x804…`), so the `.so` must match. Compile from a writable directory so gcc can place its intermediate temp files:
```bash
cd /tmp
gcc -m32 -fPIC -shared -o /tmp/file.so /tmp/file.c
```

### Step 3: Copy the binary to drop the SUID bit
`LD_PRELOAD` is ignored for SUID binaries, so run a non-SUID copy instead (safe because the token is computed in-process):
```bash
cp ~/level13 /tmp/l13
```

### Step 4: Run the copy with the preload
```bash
LD_PRELOAD=/tmp/file.so /tmp/l13
# your token is ***FLAG13***
```

Confirm via `ltrace` if desired — `getuid()` now returns `4242` and the rejection `exit(1)` is gone:
```bash
LD_PRELOAD=/tmp/file.so ltrace /tmp/l13
# getuid() = 4242
# getuid() = 4242
# printf("your token is %s\n", "***FLAG13***")
```

*(Helper script: `resources/solve.sh` runs steps 1–4 end to end.)*

The token is printed in-process (the reason the `LD_PRELOAD` bypass needs no flag13
privileges), so `***FLAG13***` is the **level14 password** directly — no
`su flag13` / `getflag` is needed.

---

## 5. Flag
```text
***FLAG13***
```
- **Next Level User:** `level14`
- **Password for next level:** `***FLAG13***`
