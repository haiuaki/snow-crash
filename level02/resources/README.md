# Level 02

## 1. Target Information
- **User:** `level02`
- **Password:** `***FLAG01***`
- **Target:** `flag02`
- **SSH Port:** `4242`

---

## 2. Reconnaissance & Discovery
The home directory contains a packet capture left behind by the level:

```bash
ls -la
# level02.pcap
```

The file is not part of this repository (it ships on the project ISO). It is
downloaded during the evaluation with `scp`:

```bash
scp -P 4242 level02@<VM_IP>:level02.pcap .
```

**Findings:**
- `level02.pcap` is a network capture of a **telnet** session.
- telnet is cleartext, so the whole login — username *and* password — is
  recoverable from the packets.

---

## 3. Vulnerability Analysis
- **Flaw Type:** Credentials sent over an unencrypted protocol (telnet),
  captured in transit.
- **Technical Explanation:**
  - telnet transmits every keystroke in plaintext. Anyone able to sniff the
    link can reconstruct the session.
  - During the **username** phase the server echoes each keystroke, so letters
    appear twice (client byte + server echo).
  - During the **password** phase there is no echo, so only the client's bytes
    appear — one byte per keystroke.
  - The password was typed with corrections: several keystrokes are the
    **delete/backspace** byte `0x7f`. A naive read with `strings` or ASCII-only
    output shows the raw characters but not the deletions, producing the wrong
    password. The bytes must be replayed in order, honouring each `0x7f`.

---

## 4. Exploitation Walkthrough

tshark (the CLI of Wireshark) is external software, so per the subject it runs inside a dedicated container rather than being installed on the host or VM. The `Dockerfile` in this folder provides it:

```dockerfile
FROM alpine:3.23

RUN apk add --no-cache tshark

WORKDIR /capture

ENTRYPOINT ["tshark"]
```

The `ENTRYPOINT` makes the container behave like the `tshark` command itself.

### Step 1: Build the image (once)
```bash
docker build -t level02-tshark .
```

### Step 2: Follow the TCP stream
The current folder is mounted at `/capture` so the pcap is read in; nothing is baked into the image.

```bash
# ASCII view: shows the login and the typed characters
docker run --rm -v "$PWD":/capture level02-tshark \
    -r level02.pcap -q -z follow,tcp,ascii,0

# Hex view: needed to identify the non-printable bytes
docker run --rm -v "$PWD":/capture level02-tshark \
    -r level02.pcap -q -z follow,tcp,hex,0
```

### Step 3: Read the username
Each typed letter is echoed back by the server:
```text
wwwbugs login: l e v e l X   ->  "level..." (the login attempt in the capture)
```

### Step 4: Reconstruct the password
After `Password:` the client sends one byte per keystroke, with no echo. In the ASCII view the non-printable bytes show as `.`; the hex view confirms each one is `0x7f` (delete). Replaying the stream and applying every `0x7f` as "delete the previous character":

```text
f t _ w a n d r      -> ft_wandr
. . .   (3 x 0x7f)   -> delete r, d, n  -> ft_wa
N D R e l            -> ft_waNDRel
.       (1 x 0x7f)   -> delete l        -> ft_waNDRe
L 0 L                -> ***PASS_FLAG02***
```

Recovered password: **`***PASS_FLAG02***`**

### Step 5: Become flag02 and grab the flag
```bash
su flag02
# Password: ***PASS_FLAG02***
getflag
# Check flag.Here is your token : ***FLAG02***
```

---

## 5. Flag
```text
***FLAG02***
```
- **Next Level User:** `level03`
- **Password for next level:** `***FLAG02***`
