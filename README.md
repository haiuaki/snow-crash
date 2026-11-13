# Snow Crash

Writeups and exploit scripts for **Snow Crash**, a 15-level Linux privilege-escalation
wargame.

Snow Crash is a boot2root-style challenge on a hardened Linux VM. You start as `level00`
and each level is a self-contained vulnerability you must exploit to recover the
credentials for the next, climbing from `level00` all the way to the final `flag14`.
The 15 levels span weak cryptography, password-hash cracking, network sniffing, a range
of injection and SUID flaws, a race condition, and binary reverse-engineering.

This repository documents how I approached each level: reconnaissance, root-cause
analysis, and a reproducible exploitation walkthrough.

> **Educational use & academic integrity.** These are writeups for a wargame built to be
> broken, shared for learning and as a portfolio of technique. The literal flag tokens and
> intermediate passwords have been redacted (shown as `***FLAGXX***`) — the value is in
> the *method*, not the answer strings. If you are a 42 student, please use this as a
> reference for approach, not as a shortcut. Do not apply any of these techniques to
> systems you do not own or lack explicit authorization to test.

## How the game works

1. Log into `levelN` over SSH (port **4242**) with its password.
2. Exploit a weakness to run code, or read a secret, **as `flagN`**.
3. Run `getflag` as `flagN`. It prints a token.
4. That token is the login password for `levelN+1`.

```sh
ssh level00@<VM_IP> -p 4242
```

`level00` is the only level whose password is not obtained from a previous one.

## Levels

Each level links to its full writeup. "Entry point" is where the vulnerable input lives.

| #  | Vulnerability class          | Technique | Entry point | Extras |
|----|------------------------------|-----------|-------------|--------|
| [00](level00/resources/README.md) | Weak obfuscation             | Decode a Caesar/ROT-encoded credential (shift 15) | File owned by `flag00` (`/usr/sbin/john`) | [`caesar.sh`](level00/resources/caesar.sh) |
| [01](level01/resources/README.md) | Password-hash cracking       | Crack a DES `crypt(3)` hash from world-readable `/etc/passwd` | `/etc/passwd` | [`Dockerfile`](level01/resources/Dockerfile) (John the Ripper), [`hash.txt`](level01/resources/hash.txt) |
| [02](level02/resources/README.md) | Cleartext protocol           | Replay a telnet stream from a packet capture, honouring `0x7f` deletes | `level02.pcap` | [`Dockerfile`](level02/resources/Dockerfile) (tshark) |
| [03](level03/resources/README.md) | SUID PATH hijack             | Shadow `echo`, called via `/usr/bin/env`, on `$PATH` | SUID `level03` | [`echo`](level03/resources/echo) (payload) |
| [04](level04/resources/README.md) | OS command injection         | Unsanitised `x` parameter reaches a Perl backtick | CGI on `localhost:4747` | |
| [05](level05/resources/README.md) | Cron + world-writable dir    | Script dropped in `/opt/openarenaserver` runs as `flag05` | Cron job every 2 min | |
| [06](level06/resources/README.md) | PHP code injection           | `preg_replace` `/e` modifier evaluates `{${system(getflag)}}` | SUID `level06` + `level06.php` | |
| [07](level07/resources/README.md) | Command injection            | `LOGNAME` interpolated into `system()` | SUID `level07` | |
| [08](level08/resources/README.md) | Broken access control        | Substring check on the path bypassed via a symlink | SUID `level08` | |
| [09](level09/resources/README.md) | Weak cipher                  | Reverse a position-dependent Caesar shift (`out[i] = in[i] + i`) | `token` file | [`index_shift.sh`](level09/resources/index_shift.sh) |
| [10](level10/resources/README.md) | TOCTOU race                  | Win an `access()`/`open()` symlink race, exfiltrate over TCP 6969 | SUID `level10` | [`race.sh`](level10/resources/race.sh) |
| [11](level11/resources/README.md) | Command injection            | Lua `io.popen` with unsanitised input; the hash check is a decoy | Lua service on `127.0.0.1:5151` | |
| [12](level12/resources/README.md) | Command injection            | Perl backtick that survives `tr/a-z/A-Z/` and `s/\s.*//` (glob to an uppercase script) | CGI on `localhost:4646` | |
| [13](level13/resources/README.md) | Identity-check bypass        | `LD_PRELOAD` a fake `getuid()` on a non-SUID copy | SUID `level13` | [`solve.sh`](level13/resources/solve.sh) |
| [14](level14/resources/README.md) | Anti-debug + identity gate   | Patch `ptrace`/`getuid` return values in `gdb` | `/bin/getflag` itself | |

Notes on the chain:

- Levels 11, 12 and 13 print the next password directly (the injected `getflag`, or the
  binary itself), so no `su flagNN` is needed there.
- Levels 00, 01, 02, 08, 09 and 10 recover an intermediate `flagNN` password, then
  `su flagNN` and `getflag`.
- Level 14 ends the game; its writeup also covers kernel fingerprinting (Dirty COW as a
  fallback, overlayfs already patched).

## Skills demonstrated

- **Binary reverse-engineering** with `gdb`, `ltrace` and `strace` — including
  defeating a `ptrace` anti-debug check and patching register values at runtime.
- **SUID exploitation** — PATH hijacking, `LD_PRELOAD` symbol interposition, symlink
  tricks, and a TOCTOU (time-of-check/time-of-use) race.
- **Command injection** across multiple contexts — shell, Perl, PHP, and Lua
  CGI/network services, including payloads that survive input filters (uppercasing,
  whitespace truncation).
- **Cryptographic weaknesses** — Caesar/ROT and position-dependent shift ciphers, plus
  cracking a legacy DES `crypt(3)` hash with John the Ripper.
- **Network traffic analysis** — recovering telnet credentials from a packet capture.
- **Privilege escalation** via a world-writable directory consumed by a privileged cron job.
- **Containerised tooling** — third-party tools (John, tshark) run in Docker images
  instead of being installed on the host or VM.
- **Technical writing** — each level includes a root-cause analysis and a remediation note.

## Tools used

| Area                 | Tools |
|----------------------|-------|
| Recon                | `find`, `ls -l`, `file`, `strings`, `xxd`, `od`, `ps`, `uname` |
| Tracing / debugging  | `ltrace`, `strace`, `gdb`, `bash -x` |
| Cracking             | John the Ripper, in the Docker image from level01 |
| Network analysis     | `tshark`, in the Docker image from level02; `curl`, `nc` for services and exfiltration |
| File transfer        | `scp -P 4242` between host and VM |
| Scripting / build    | POSIX `sh`, Perl, Lua, PHP (targets), `gcc -m32` for the level13 shared library |

## Repository layout

```
snow-crash/
├── README.md               # this file
├── template.md             # skeleton used for every writeup
├── snowcrash_subject.pdf   # the original subject
└── levelXX/
    ├── flag                # recovered token (redacted placeholder)
    └── resources/
        ├── README.md       # the writeup (recon → analysis → exploitation → fix)
        └── ...             # scripts / Dockerfiles / data for that level
```

`.gitignore` excludes `*.pcap` and `*.iso`: the level02 capture and the VM image ship with
the project and are not stored here.

Each per-level writeup follows the structure in [`template.md`](template.md):

1. **Target Information** — user, password, target, SSH port.
2. **Reconnaissance & Discovery** — what was inspected and found.
3. **Vulnerability Analysis** — flaw type, root cause, and the fix.
4. **Exploitation Walkthrough** — reproducible steps.
5. **Flag** — the recovered credential (redacted here).

## Reproducing a level

1. Boot the Snow Crash ISO in a VM and note its IP (the ISO is not included here).
2. SSH in as `levelN` on port 4242. You need the password from the previous level, which
   you must recover yourself.
3. Follow the writeup in `levelN/resources/README.md`.
   - Scripts that run on the VM (`race.sh`, `index_shift.sh`, `solve.sh`) are copied over
     with `scp -P 4242` into `/tmp`, since the home directory is not writable.
   - Levels 01 and 02 run on the host through Docker:
     ```sh
     docker build -t level01-john level01/resources
     docker run --rm -v "$PWD/level01/resources":/crack level01-john hash.txt
     ```
   - Level 02 needs `level02.pcap` copied from the VM first.

## Disclaimer

All work here targets a wargame VM designed for this purpose, in a lawful, self-contained
environment. The techniques are documented for education and authorized security testing
only.
