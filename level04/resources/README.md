# Level 04

## 1. Target Information
- **User:** `level04`
- **Password:** `***FLAG03***`
- **Target:** `flag04`
- **SSH Port:** `4242`

---

## 2. Reconnaissance & Discovery
Search for files owned by `flag04`:

```bash
find / -user flag04 2>/dev/null
```

**Findings:**
- A Perl CGI script owned by `flag04` is served by a webserver:
```text
/var/www/index.cgi
```
- The script carries a comment pointing at the listening port:
```perl
#!/usr/bin/perl
# localhost:4747
use CGI qw{param};
print "Content-type: text/html\n\n";

sub x {
  $y = $_[0];
  print `echo $y 2>&1`;
}

x(param("x"));
```
- The CGI reads the GET parameter `x` and interpolates it **straight into a backtick shell command** (`echo $y`). The server runs this `echo` with `flag04`'s privileges.

---

## 3. Vulnerability Analysis
- **Flaw Type:** OS command injection via unsanitised CGI parameter in a shell context.
- **Technical Explanation:**
  - `` `echo $y 2>&1` `` hands `$y` to `/bin/sh`. Perl backticks invoke a shell, so any shell metacharacter inside `$y` is interpreted, not treated as literal text.
  - The value of `$y` comes directly from `param("x")` with no escaping or quoting.
  - Injecting a command separator (`;`) lets us append our own command after `echo`: the shell runs `echo <stuff>` **and then** our command. Since the CGI executes as `flag04`, our injected `getflag` also runs as `flag04`.
  - **Root cause / fix:** never build shell command lines from untrusted input. Use list-form execution (`system LIST`) that bypasses the shell, or strictly validate/escape the input.

---

## 4. Exploitation Walkthrough

### Step 1: Confirm the service
```bash
curl "localhost:4747/?x=test"
# -> test      (the CGI echoes back our input)
```

### Step 2: Inject `getflag` through the `x` parameter
The payload we want the **server's shell** to run is `; getflag`, turning `echo $y` into `echo ; getflag`.

```bash
curl "localhost:4747/?x=%3Bgetflag"
# Check flag.Here is your token: ***FLAG04***
```

### Why `%3B` and not a literal `;`

`%3B` is the percent-encoding of `;`. Encoding it is required because a raw `;` is consumed *before* it ever reaches the vulnerable shell — at two earlier layers:

1. **The local shell (your `curl` command line).** `;` is a command separator in your own shell. Writing
   ```bash
   curl localhost:4747/?x=;getflag
   ```
   is parsed as two commands: `curl localhost:4747/?x=` followed by `getflag` run **locally** (as `level04`, where it fails). The `;` never becomes part of the URL. Encoding it as `%3B` (or heavy quoting) keeps it inside the argument passed to `curl`.

2. **The URL query string itself.** `;` is a reserved sub-delimiter in a URI (RFC 3986), historically also treated as a parameter separator alongside `&`. A literal `;` in the query is ambiguous and may be split off rather than delivered as part of the `x` value. `%3B` travels as opaque data.

The server's CGI layer then **URL-decodes** `%3B` back into a real `;` and stores it in `$y`. Only at that point does the character reach `` `echo $y` ``, where it finally acts as a shell separator and triggers the injection. In short: encode it so it survives your shell and the HTTP transport as inert text, and gets turned back into a metacharacter exactly where we want it — inside `flag04`'s shell.

---

## 5. Flag
```text
Check flag.Here is your token: ***FLAG04***
```
- **Next Level User:** `level05`
- **Password for next level:** `***FLAG04***`
