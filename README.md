# Hash Identifier

A Python CLI and library that identifies which algorithm produced a hash
string, by inspecting its prefix, length, and character set. It returns
ranked candidates with a confidence level, a reason, and the matching
**hashcat mode** and **John the Ripper format**.

It identifies hashes. It does not crack them.

## Features

- Prefix rules (bcrypt, Argon2, SHA-crypt, phpass, Django, LDAP, ...)
- Special shapes: NetNTLMv1/v2, MySQL5, DES crypt
- Hex-length matching (MD5, SHA-1, SHA-256, ...)
- Hashcat `-m` mode and John `--format` for each candidate
- Prints a ready-to-run `hashcat` command for the top candidate
- "Not a hash" hints: URL, `0x` hex, JWT, Base32, Base58, base64
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
```

Options: `--top/-n N`, `--json`, `--file/-f PATH`.

Exit codes: `0` identified (or JSON output), `1` nothing identified,
`2` usage or file error.

## Confidence levels

| Level | Meaning |
|---|---|
| high | Self-identifying prefix or unmistakable shape |
| medium | Most likely candidate for that hex length, or a DES crypt shape |
| low | Other possibilities at that length, or "not a hash" shape hints |

## Development

```bash
just test     # pytest
just lint     # ruff, pylint, mypy
just format   # yapf
```

## Credits and license

Based on the hash-identifier project from <upstream repo URL> by
CarterPerez-dev. Extended with hashcat/John hints and additional
not-a-hash detectors by <your name>.

Licensed under AGPL-3.0-or-later. See `LICENSE`.
