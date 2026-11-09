# Level 14

## 1. Target Information
- **User:** `level14`
- **Password:** `***FLAG13***`
- **Target:** `flag14` (final flag)
- **SSH Port:** `4242`

---

## 2. Reconnaissance & Discovery
Unlike the earlier levels, there is **no challenge binary in `~level14`** to exploit.
The target *is* the scoreboard tool itself, `/bin/getflag` — the SUID-root program
we have run at the end of every level.

```bash
ls -la                      # home dir has no level14-specific SUID binary
which getflag               # /bin/getflag
ls -l /bin/getflag          # SUID root, world-readable r-x
strace getflag              # observe ptrace() + getuid(), no privileged file read
gdb /bin/getflag
(gdb) disas main            # locate the ptrace and getuid call sites
```

**Findings:**
- `getflag` is **SUID root** and **world-readable**, so its logic can be disassembled by anyone.
- Early in `main` it calls **`ptrace(PTRACE_TRACEME, …)`** as an anti-debugging check.
- It then calls **`getuid()`** and keys its output on the caller's UID: run as `flagXX`
  (UID `30XX`) it prints that flag's token. flag14's UID is **3014**.
- The token is computed **in-process** (no privileged file is opened), so producing it
  does not actually require flag14's identity at the kernel level — only that `getflag`
  *believes* the caller is UID `3014` and is *not* being traced.

**Kernel / privilege-escalation enumeration (standard recon):**
```bash
uname -a                    # Linux 3.2.0-89-generic-pae #127-Ubuntu ... i686 (built 2015-07-28)
cat /etc/issue
lsb_release -a 2>/dev/null  # Ubuntu 12.04.5 LTS (precise)
```
Part of recon is fingerprinting the kernel and checking it online against published
local-privilege-escalation exploits:
- **Dirty COW (CVE-2016-5195) — vulnerable.** The fix was not released until October 2016;
  this kernel is from July 2015, so it is unpatched. The race works on i686, and `gcc` is
  available on the box, so a 32-bit PoC (e.g. `dirtyc0w.c`) would compile and grant root,
  making every flag readable. A genuine fallback avenue.
- **overlayfs (CVE-2015-1328) — already patched.** This Ubuntu-specific bug was fixed
  mid-June 2015 (USN-2659-1); this kernel was built 2015-07-28, after that fix landed in
  precise's 3.2.0 line, so it is not usable here.

The intended, per-level path is reversing `getflag` (the route taken below), which
demonstrates the actual vulnerability this level targets.

References (kernel-LPE recon):
- https://github.com/dirtycow/dirtycow.github.io
- https://github.com/thaddeuspearson/Understanding_DirtyCOW

---

## 3. Vulnerability Analysis
- **Flaw Type:** Debugger-defeatable identity check — anti-debug (`ptrace` self-trace) +
  authorization based on `getuid()`, combined with an in-process (self-contained) token.
- **Technical Explanation:**
  - **Anti-debug:** `ptrace(PTRACE_TRACEME, 0, 0, 0)` returns `-1` when the process is
    already traced (i.e. running under gdb). `getflag` uses this to detect a debugger and
    take its reject path. Forcing the return value to `0` makes it believe it runs un-traced.
  - **Identity gate:** the program trusts `getuid()` to decide *which* flag's token to emit.
    We cannot change our real UID (only root can), but under a debugger we can overwrite the
    return value in the register before the program reads it.
  - **Self-contained secret:** because the token is derived entirely from the binary's own
    logic + the UID (no file owned only by flag14 is read), we never need flag14's real
    privileges. Convincing `getflag` that `getuid() == 3014` is sufficient to generate the token.
  - **Master-key consequence:** the same technique generates *any* flag's token — set the UID
    to `3000`–`3013` instead of `3014` and `getflag` prints that user's token. This is the
    design weakness level14 is built around.
  - **Root cause / fix:** never gate a secret on `ptrace`-based anti-debug or on an
    in-process `getuid()` check — both are trivially overridden once the attacker controls
    the process. Secrets must be stored where only the privileged identity can read them,
    enforced by the kernel, not reconstructed from the binary's own logic.

---

## 4. Exploitation Walkthrough

### Step 1: Locate the two call sites
Disassemble `main` and find the instruction **immediately after** the `ptrace` call returns
and the instruction **immediately after** the `getuid` call returns — those are where we
overwrite the return value (`eax`).

```bash
gdb /bin/getflag
(gdb) disassemble main
# ptrace return site  -> 0x0804898e
# getuid return site  -> 0x08048b02
```

### Step 2: Set breakpoints just after each call
```gdb
(gdb) break *0x0804898e     # right after ptrace() returns
(gdb) break *0x08048b02     # right after getuid() returns
(gdb) run
```

### Step 3: Defeat the anti-debug, then spoof the UID
```gdb
Breakpoint 1, 0x0804898e in main ()
(gdb) set $eax=0            # pretend ptrace succeeded (not being traced)
(gdb) continue

Breakpoint 2, 0x08048b02 in main ()
(gdb) set $eax=3014         # pretend the caller is flag14 (UID 3014)
(gdb) continue
```

### Step 4: Read the token
```text
Check flag.Here is your token : ***FLAG14***
[Inferior 1 (process 2190) exited normally]
```

---

## 5. Flag
```text
***FLAG14***
```
- **Final flag — end of SnowCrash.**
