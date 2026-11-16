# Hash Identifier

A Python CLI and library that identifies which algorithm produced a hash
string, by inspecting its prefix, length, and character set. It returns
ranked candidates with a confidence score, a crack-difficulty rating, a
reason, and the matching **hashcat mode** and **John the Ripper format**.

It identifies hashes. It does not crack them.

## Features

- Prefix rules (bcrypt, Argon2, SHA-crypt, phpass, Django, LDAP, ...)
- Special shapes: NetNTLMv1/v2, MySQL5, DES crypt
- Hex-length matching (MD5, SHA-1, SHA-256, ...)
- Hashcat `-m` mode and John `--format` for each candidate
- Prints a ready-to-run `hashcat` command for the top candidate
- "Not a hash" hints: URL, `0x` hex, JWT, Base32, Base58, base64
- Evidence-weighted confidence scores (0.0 to 1.0)
- Crack difficulty per algorithm, with bcrypt and Argon2 cost parameters
  read from the hash itself
- `--split` mode for `user:hash:salt` style records
- Batch input from a file or stdin, with duplicate counting
- `--json` output for scripting

## Setup

Requires Python 3.13+ and [uv](https://docs.astral.sh/uv/).

```bash
./install.sh        # installs uv/just if missing, then runs `just setup`
```

## Usage

Quote hashes in single quotes so the shell does not expand `$`.

```bash
uv run hashid '5f4dcc3b5aa765d61d8327deb882cf99'
uv run hashid '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G'
uv run hashid --file test-hashes.txt
cat test-hashes.txt | uv run hashid
uv run hashid --json '5f4dcc3b5aa765d61d8327deb882cf99'
uv run hashid --split 'bob:5f4dcc3b5aa765d61d8327deb882cf99:salt123'
```

Options: `--top/-n N`, `--json`, `--file/-f PATH`, `--split/-s`.

Exit codes: `0` identified (or JSON output), `1` nothing identified (or a
split record with no hash field), `2` usage or file error.

### Example output

```bash
uv run hashid '5f4dcc3b5aa765d61d8327deb882cf99'
```

| algorithm | confidence | difficulty | hashcat -m | john --format |
|---|---|---|---|---|
| MD5 | medium (0.60) | trivial | 0 | raw-md5 |
| NTLM | low (0.33) | trivial | 1000 | nt |
| MD4 | low (0.23) | trivial | 900 | raw-md4 |
| RIPEMD-128 | low (0.19) | trivial | - | - |

Followed by the next step for the top candidate:

```
hashcat -m 0 -a 0 5f4dcc3b5aa765d61d8327deb882cf99 wordlist.txt
```

## Confidence scores

Each candidate has a `confidence_score` from 0.0 to 1.0, built from
evidence weights:

| Evidence | Score |
|---|---|
| Known prefix (`$2b$`, `$argon2id$`, ...) | 0.95 |
| Special shape (NetNTLM, MySQL5) | 0.85 |
| DES crypt (13 chars in the crypt alphabet) | 0.60 |
| Hex length match, rank N | 0.55 / N |
| Single-case hex | +0.05 |
| Generic `$name$...` shape | 0.40 |
| "Not a hash" hint | 0.30 |

For display the score maps to three buckets:

| Level | Score | Color |
|---|---|---|
| high | above 0.8 | green |
| medium | 0.5 to 0.8 | yellow |
| low | below 0.5 | cyan |

`--json` output contains the raw `confidence_score`.

## Crack difficulty

Every known algorithm has a difficulty: `trivial`, `moderate`, `hard` or
`very_hard`. For bcrypt and Argon2 the cost parameters are parsed out of the
hash string, so the rating reflects the real settings:

| Hash | difficulty | note |
|---|---|---|
| `$2b$04$...` | moderate | cost=4, much weaker than the default 12 |
| `$2b$12$...` | hard | cost=12, the modern default |
| `$2b$14$...` | very_hard | cost=14, paranoid setting |

The tiers are order-of-magnitude estimates, not benchmarks.

## Split mode

Breach dumps often hold combined records. `--split` labels each
colon-separated field as username, hash, salt, garbage or empty:

```bash
uv run hashid --split 'bob:5f4dcc3b5aa765d61d8327deb882cf99:salt123'
```

| # | field | role | detail |
|---|---|---|---|
| 1 | bob | username | name-shaped text before the hash |
| 2 | 5f4dcc3b5aa765d61d8327deb882cf99 | hash | MD5 (medium confidence) |
| 3 | salt123 | salt | short token after the hash |

Classification is heuristic. A hex salt can be mistaken for a hash, and a
username with digits or dots can match DES crypt by length.

## Library use

```python
from hash_identifier import identify, split_fields

top = identify("5f4dcc3b5aa765d61d8327deb882cf99")[0]
print(top.algorithm, top.confidence_score, top.crack_difficulty)

for field in split_fields("bob:5f4dcc3b5aa765d61d8327deb882cf99:salt123"):
    print(field.position, field.role, field.value)
```

## Development

```bash
just test     # pytest
just lint     # ruff, pylint, mypy
just format   # yapf
```

## Credits and license

Based on the hash-identifier project from
[CarterPerez-dev/Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects)
by CarterPerez-dev. Extended with hashcat/John hints, not-a-hash detectors,
split mode, evidence-weighted scoring and crack difficulty by
Ajinkya | JinX-8.

Licensed under AGPL-3.0-or-later. See `LICENSE`.