# decipher

[Chinese](README.md) | [English](README.en.md)

A high-performance hash recovery tool written in Go. It identifies hash algorithms, computes hashes and ciphertexts, cracks hashes with dictionaries, and manages precomputed databases.

## Features

- Identify common hash formats and supported algorithms.
- Compute hashes and reversible ciphertexts from plaintexts.
- Crack hashes with built-in or user-provided plaintext and salt dictionaries.
- Generate and query precomputed databases for supported static algorithms.
- Stream large dictionaries and salt sources with concurrent workers.
- Export results as CSV or JSON.

## Commands

| Command | Purpose |
| --- | --- |
| `enc` | Compute hashes or ciphertexts from plaintexts. |
| `dec` | Crack hashes or decrypt ciphertexts. |
| `id` | Identify possible hash algorithms. |
| `dict add` | Append user-provided entries to built-in dictionaries. |
| `dict init` | Generate precomputed database entries. |

Run `decipher --help` or append `--help` to a command to see native command-line help.

## Common commands

Examples use `./decipher` on Linux/macOS. In Windows PowerShell, use `.\decipher.exe`.

```sh
# Show help, version, and supported algorithms
./decipher --help
./decipher --version
./decipher --list

# Identify hash algorithms
./decipher id -i file:hashes.txt -o .

# Compute an MD5 hash
./decipher enc -p str:123456 -a 'md5($pass)' -A

# Crack hashes with a dictionary; -p - selects the built-in plaintext dictionary
./decipher dec -i file:hashes.txt -p file:words.txt -a 'md5($pass)' -A
./decipher dec -i file:hashes.txt -p -

# Append a user dictionary and build an MD5 precomputed database
./decipher dict add -p file:words.txt
./decipher dict init -a 'md5($pass)' -A

# Deduplicate precomputed data, or clear caches and failure records
./decipher --dc
./decipher --cc
```
## Input formats

Input values accept these prefixes:

| Prefix | Meaning |
| --- | --- |
| `file:PATH` | Read values line by line from a file. |
| `str:VALUE` | Use the value literally. |
| `gen:RULE` | Generate values according to a rule. |

Without a prefix, an existing file is read; otherwise the value is treated as a literal string. Repeat a flag to pass several values, or separate values with commas. Commas in strings and file paths are also split.

Use `-p -` and `-s -` to select the built-in plaintext and salt dictionaries. These values do not mean standard input. An explicit invalid `file:` path fails immediately and never falls back to a built-in dictionary.

### Input data by command

| Command | Parameter | Data format |
| --- | --- | --- |
| `enc` | `-p` | Plaintext values to hash or encrypt. Pass values directly or use a file with one plaintext per line. |
| `enc` | `-s` (optional) | Salt/key values. Pass values directly or use a file with one value per line. |
| `dec` | `-i` | Hashes or ciphertexts to crack/decrypt. Pass values directly or use a file with one target per line. A target may be `HASH`, `HASH:SALT`, or `HASH:SALT:EXTRA`; the default separator is `:` and can be changed with `--concat-symbol`. Only the hash and salt are used; the third and later fields are ignored. |
| `dec` | `-p`, `-s` (optional) | Candidate plaintexts and salts/keys. Pass values directly or use files with one value per line. |
| `id` | `-i` | Hashes to identify. Pass values directly or use a file with one hash per line. |

Examples: `enc -p str:123456` computes one plaintext; `dec -i file:hashes.txt` reads targets from a file; `id -i str:5f4dcc3b5aa765d61d8327deb882cf99` identifies one hash.

Choose inputs according to the command: `enc` reads plaintexts from `-p` and accepts salts or keys through `-s` when needed; `dec` reads targets from `-i` and candidate plaintexts and salts/keys from `-p` and `-s`; `id` only needs hashes through `-i`. Pass a single value as `str:VALUE`, or put batch values in a file referenced with `file:PATH`, with one entry per line.

## Parameters

| Parameter | Description |
| --- | --- |
| `-i, --hashes STRINGS` | Hashes, ciphertexts, or input files. Used by `dec` and `id`. |
| `-p, --plains STRINGS` | Plaintext values or candidate dictionaries. Used by `enc`, `dec`, and dictionary commands. |
| `-s, --secrets STRINGS` | Salts, keys, or dictionaries of salts/keys. |
| `-a, --algos STRINGS` | Filter algorithms by keyword. Partial matching is supported; defaults to all available algorithms. |
| `-A, --precise` | Match the algorithm name exactly when used with `-a`. |
| `--sp STRING`, `--ss STRING` | Add a prefix or suffix to each salt. |
| `--pp STRING`, `--ps STRING` | Add a prefix or suffix to each plaintext candidate. |
| `-w, --workers INT` | Number of workers. `0` selects a value based on the CPU count. |
| `-o, --output PATH` | Output directory, default `.`. Same-named result files are overwritten. |
| `-O, --output-type csv\|json` | Result format, default `csv`. |
| `--concat-symbol STRING` | Separator for hash fields when parsing `dec` targets; default `:`. |
| `--npc` | Disable precomputed database lookup. |
| `--ndc` | Skip dynamic hash cracking. |
| `-R, --rr` | Remove temporary dictionaries created during this run after success or failure. |
| `-C, --cc` | Clear precomputed databases, caches, and failure records, then exit. |
| `-D, --dc` | Deduplicate precomputed database files, then exit. |
| `--predb-dir PATH` | Directory for precomputed databases and built-in dictionaries; default `decipher_db`. |
| `--run-cache-dir PATH` | Directory for temporary dictionaries; default `decipher_cache`. |
| `--failure-cache PATH` | Failure-record file relative to the output directory; default `decipher.failure.csv`. |
| `--ll STRING`, `--lf PATH`, `--lcf STRING` | Configure log level, log file, and console log fields. |
| `-L, --list` | List all available algorithms and exit. |
| `-v, --version` | Show version information and exit. |

Each run selects one operation. `dict add` only appends to built-in dictionaries and requires `-p` or `-s`. `dict init` only writes precomputed data; when `-p` or `-s` is omitted, it reads the corresponding built-in dictionary. Result files for `enc`, `dec`, and `id` are overwritten. Success cache, built-in dictionaries, and precomputed database entries follow their existing append behavior.

## Output files

The `-o` option selects a directory. Commands write:

- `decipher.enc.csv/json`
- `decipher.dec.csv/json`
- `decipher.id.csv/json`

CSV and JSON are serialized in their standard formats. Failure records are written to the configured failure-cache file when there are new failures.

## Examples

Compute an MD5 hash:

```bash
./decipher enc -p str:123456 -a 'md5($pass)' -A
```

Crack hashes from a file with a candidate dictionary:

```bash
./decipher dec -i file:hashes.txt -p file:words.txt -a 'md5($pass)' -A
```

Identify algorithms and write results to the current directory:

```bash
./decipher id -i file:hashes.txt -o .
```

Append a user dictionary and generate precomputed data:

```bash
./decipher dict add -p file:words.txt
./decipher dict init -a 'md5($pass)' -A
```

Write JSON output:

```bash
./decipher dec -i file:hashes.txt -o . -O json
```

List all 66 available algorithm names with `-L`:

```text
  1:  base64($pass)
  2:  des_crmeb_admin
  3:  md5($pass)
  4:  md5($pass)[8,24]
  5:  md5(md5($pass))
  6:  md5(md5($pass).NiuCloud)
  7:  md5(md5(md5($pass)))
  8:  md5(unicode($pass))
  9:  base64(md5($pass))
  10:  md5($pass.$salt)
  11:  md5($salt.$pass)
  12:  md5($salt.$pass.$salt)
  13:  md5($salt.md5($pass))
  14:  md5(md5($salt).$pass)
  15:  md5($pass.md5($salt))
  16:  md5(md5($pass).$salt)
  17:  md5(md5($salt).md5($pass))
  18:  md5(md5($pass).md5($salt))
  19:  md5(sha1($pass))
  20:  md5(md5($pass)[8,24])
  21:  md5_custom_likeshop_2020
  22:  md5_custom_likeshop_2021
  23:  md5_custom_by_pwd
  24:  md5_custom_nc65
  25:  md5_custom_gmshop
  26:  md5($salt;$pass)
  27:  md5_md5_md5_bt_admin
  28:  md5($pass.$salt)_hex
  29:  md5($salt.$pass)_hex
  30:  md5($salt.$pass.$salt)_hex
  31:  md5($salt.md5($pass))_hex
  32:  md5(md5($salt).$pass)_hex
  33:  md5($pass.md5($salt))_hex
  34:  md5(md5($pass).$salt);VB;DZ_hex
  35:  md5(md5($salt).md5($pass))_hex
  36:  md5(md5($pass).md5($salt))_hex
  37:  sha1($pass)
  38:  sha1($pass.$salt)
  39:  sha1($pass-$salt)
  40:  sha1($salt.$pass)
  41:  sha1(sha1($pass))
  42:  sha1(md5($pass))
  43:  sha256($pass)
  44:  sha256($pass.$salt)
  45:  sha256($salt.$pass)
  46:  sha256(md5($pass))
  47:  sha256($pass.$salt);shiro
  48:  sha256_custom_nccloud
  49:  sha384($pass)
  50:  sha512($pass)
  51:  sha512($pass.$salt)
  52:  sha512($salt.$pass)
  53:  sha1($pass.$salt)_hex
  54:  sha1($salt.$pass)_hex
  55:  sha256($pass.$salt)_hex
  56:  sha256($salt.$pass)_hex
  57:  sha512($pass.$salt)_hex
  58:  sha512($salt.$pass)_hex
  59:  mysql_pre41
  60:  mysql5
  61:  ntlm
  62:  MSSQL2015
  63:  bcrypt($pass)
  64:  bcrypt(md5($pass))
  65:  bcrypt($pass.$salt)
  66:  scrypt($salt,$pass)
```

## Tests

Run the full test suite, race detector, static analysis, and build:

```bash
go test ./...
go test -race ./...
go vet ./...
go build -o bin/decipher.exe ./cmd/decipher
```

Tests cover CLI commands, algorithm behavior and salted input boundaries, dictionary parsing, cracking strategies, multi-dictionary runs, output serialization, cancellation, progress accounting, and Windows memory cases. See [the testing guide](docs/testing.md).

## Performance

Recent optimizations reduced repeated target preparation, candidate hashing, salt-affix construction, unused task dispatch, and repeated strategy preparation across dictionaries. In representative benchmarks, SHA-256 processing for 1,000 targets and 1,000 candidates improved from about 18.5 ms to 1.83 ms. Processing eight dictionaries with 100,000 targets improved from about 181.8 ms to 133.5 ms. Small end-to-end CLI cases can vary because startup and I/O contribute to their runtime.

See [the performance optimization report](docs/performance-optimization-report.md) for measurements and limitations.

