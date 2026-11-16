"""
©AngelaMos | 2026
hash_identifier.py

Identify what kind of hash a string is, by inspecting its shape

When someone hands you a string of gibberish like
`5f4dcc3b5aa765d61d8327deb882cf99` or `$2b$12$EixZaYVK1fsbw1ZfbX3OXe...`,
the first question is: what algorithm produced it? You can NOT crack
or analyze a hash without knowing what flavor of hash you are looking
at. Every cracking tool — hashcat, john the ripper — needs you to
specify an algorithm before it will start

This script does the looking-at part. Given a hash string, it returns
ranked candidates with a confidence score and a short reason

────────────────────────────────────────────────────────────────────
How identification actually works
────────────────────────────────────────────────────────────────────
There is no magic here. Hash strings carry shape clues

  1. PREFIX. Many modern hashes are stored in "PHC string format" —
     a self-describing format that starts with a marker like `$2b$`
     (bcrypt) or `$argon2id$` (Argon2id). When we see a known prefix
     we know the algorithm with HIGH confidence

  2. LENGTH. Raw hex output of a hash function is always the same
     length: MD5 produces 16 bytes = 32 hex chars; SHA-1 produces 20
     bytes = 40 hex chars; SHA-256 produces 32 bytes = 64 hex chars,
     and so on. Length alone narrows the field

  3. CHARSET. Different formats use different alphabets. Hex hashes
     use only 0-9 and a-f. Base64 uses 0-9, A-Z, a-z, +, /, and =.
     A string with `+` in it is not a hex hash

So our algorithm is: try prefix rules first, fall back to length +
charset rules, return the candidates ranked by confidence

────────────────────────────────────────────────────────────────────
What this script can and cannot do
────────────────────────────────────────────────────────────────────
CAN:    suggest likely algorithms for a hash you found
CANNOT: tell you the password the hash was made from
        (that is hashcat's job — see ../../beginner/hash-cracker)

────────────────────────────────────────────────────────────────────
What this file exposes
────────────────────────────────────────────────────────────────────
  HashCandidate          — one ranked guess (algorithm, confidence, reason)
  identify(text)         — return ranked candidates for a hash string
  main()                 — CLI entry point, called by `python hash_identifier.py <hash>`

Run it as a script and it prints a table; import it and it stays quiet.
Quote hashes in single quotes — bash eats `$2b$12$...` otherwise:

    python hash_identifier.py '5f4dcc3b5aa765d61d8327deb882cf99'
    python hash_identifier.py '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36...'
    python hash_identifier.py --file found_hashes.txt --top 2
    cat hashes.txt | python hash_identifier.py --json
    from hash_identifier import identify
"""

# Standard library: parse command-line flags like `--top 3` into a
# nice object so we do not have to slice `sys.argv` by hand.
import argparse
import json
import re
import sys
import shlex

# Standard library: Counter gives us duplicate counts for file/stdin
# batches in one pass, keeping order of first appearance for free
# (dicts and Counter both preserve insertion order since 3.7)
from collections import Counter

# Standard library: a decorator that turns a class into a small,
# immutable data record without writing `__init__` boilerplate, plus
# `asdict` which flattens a candidate into a plain dict for --json
from dataclasses import asdict, dataclass

# Standard library: a type hint that pins a value to a small fixed
# set of strings (here: "high" / "medium" / "low"). Mypy catches typos.
from typing import Literal

# Third-party (rich): the printer that actually draws the table to
# the terminal, with color and Unicode support.
from rich.console import Console

# Third-party (rich): builds the colored ASCII table we print for
# ranked hash candidates.
from rich.table import Table
from rich.markup import escape
# =============================================================================
# Confidence type — only three valid values
# =============================================================================
# Literal["high", "medium", "low"] is a type hint that says "this string
# can ONLY be one of these three values." Mypy will catch typos like
# "hgih" at edit time. We chose Literal over an Enum because I
# prefer Literals for small fixed sets

Confidence = Literal["high", "medium", "low"]
# =============================================================================
# Evidence weights — the numbers behind every confidence score
# =============================================================================
# Each kind of evidence has a base weight. A candidate's score is the base
# weight for the strongest evidence, plus small bonuses, clamped to 0.0-1.0.
# Same idea as a spam filter: weak signals in, one number out, then bucket
# the number for display

SCORE_PREFIX = 0.95  # a known `$algo$` prefix announces itself
SCORE_SPECIAL_SHAPE = 0.85  # NetNTLM / MySQL5: unmistakable shape
SCORE_LENGTH_FIRST = 0.55  # hex length match: divided by rank for the rest
SCORE_GENERIC_PHC = 0.40  # `$name$...` shape only, no specific rule
SCORE_NOT_A_HASH = 0.30  # shape hints: URL, JWT, base64...
CHARSET_BONUS = 0.05  # small additive bonus for a clean charset

# Display buckets: score > 0.8 is high, 0.5-0.8 is medium, below is low
HIGH_SCORE_THRESHOLD = 0.8
MEDIUM_SCORE_THRESHOLD = 0.5


def confidence_bucket(score: float) -> Confidence:
    """Map a 0.0-1.0 score to the three buckets the user sees"""
    if score > HIGH_SCORE_THRESHOLD:
        return "high"
    if score >= MEDIUM_SCORE_THRESHOLD:
        return "medium"
    return "low"

# =============================================================================
# Crack difficulty type — how hard is this hash to attack?
# =============================================================================
# Same idea as Confidence: a Literal pins the value to four strings so mypy
# catches typos. Rough guide, on one modern GPU:
#   trivial    billions of guesses per second  (raw MD5, SHA-*)
#   moderate   millions to hundreds of thousands (MD5 crypt, phpass)
#   hard       thousands                         (bcrypt cost 12)
#   very_hard  hundreds or fewer                 (Argon2id, 64 MiB)

CrackDifficulty = Literal["trivial", "moderate", "hard", "very_hard"]

# =============================================================================
# Result type — what identify() returns for each guess
# =============================================================================


@dataclass(frozen = True, slots = True)
class HashCandidate:
    """
    One possible identification of a hash string

    `frozen=True` makes the dataclass immutable, `slots=True` makes
    instances lightweight

    Fields
    ------
    algorithm
        Human-readable algorithm name like "SHA-256" or "bcrypt"
    confidence_score
        0.0-1.0, built from evidence weights (prefix, shape, length,
        charset). Higher means more certain
    reason
        Short explanation shown next to the algorithm name
    crack_difficulty
        How hard the hash is to crack, or None when we cannot say
        (not-a-hash hints, unknown PHC strings)
    """
    algorithm: str
    confidence_score: float
    reason: str
    hashcat_mode: int | None = None
    john_format: str | None = None
    crack_difficulty:CrackDifficulty | None = None

    @property
    def confidence(self) -> Confidence:
        """The display bucket, derived from the score (never stored)"""
        return confidence_bucket(self.confidence_score)




# =============================================================================
# Prefix rules — strongest signal we have
# =============================================================================
# Modern hashes use PHC-style strings: a leading `$` marker tells you
# exactly what algorithm produced the hash. When we see one of these
# prefixes we report HIGH confidence. The third element of each tuple
# is a short note we include in the reason field
#
# Order matters when prefixes overlap. We list more specific prefixes
# FIRST so they match before generic ones (e.g. `$argon2id$` before
# `$argon2$` would matter if both existed in the table)

PREFIX_RULES: list[tuple[str, str, str]] = [
    # Argon2 family — won the 2015 Password Hashing Competition
    ("$argon2id$", "Argon2id", "modern PHC string, the current standard"),
    ("$argon2i$", "Argon2i", "PHC string, side-channel-resistant variant"),
    ("$argon2d$", "Argon2d", "PHC string, GPU-resistant variant"),

    # bcrypt and its many variants — workhorse for the past 15 years
    ("$2y$", "bcrypt", "bcrypt PHC string, 2y variant (PHP)"),
    ("$2b$", "bcrypt", "bcrypt PHC string, 2b variant (current)"),
    ("$2a$", "bcrypt", "bcrypt PHC string, 2a variant (legacy)"),
    ("$2x$", "bcrypt", "bcrypt PHC string, 2x variant (legacy fix)"),

    # Unix crypt(3) family — what /etc/shadow uses on Linux
    ("$6$", "SHA-512 crypt", "Unix crypt(3) using SHA-512 (default on Linux)"),
    ("$5$", "SHA-256 crypt", "Unix crypt(3) using SHA-256"),
    ("$1$", "MD5 crypt", "Unix crypt(3) using MD5 (legacy, weak)"),

    # Apache htpasswd MD5 variant — same MD5 family as $1$ above but
    # with Apache's own salt-handling tweak. This is the format that
    # `htpasswd -m` emits by default, which makes it FAR more common
    # in the wild than the Unix $1$ form (every basic-auth tutorial
    # ends with one of these in a .htpasswd file)
    ("$apr1$", "Apache MD5-crypt", "Apache htpasswd MD5 variant (`htpasswd -m`)"),

    # yescrypt — newer Linux default in some distributions
    ("$y$", "yescrypt", "PHC string, modern Linux crypt successor"),

    # phpass — used by WordPress, phpBB, and other PHP apps
    ("$P$", "phpass", "WordPress / phpBB password hash"),
    ("$H$", "phpass", "phpBB-style phpass variant"),

    # Drupal 7
    ("$S$", "Drupal 7 (SHA-512)", "Drupal 7 PHC-style hash"),

    # scrypt as some implementations encode it
    ("$7$", "scrypt", "scrypt PHC-style hash"),

    # Django's default — recognizable by the algorithm name in the prefix
    ("pbkdf2_sha256$", "Django PBKDF2-SHA256", "Django default password hash"),
    ("pbkdf2_sha1$", "Django PBKDF2-SHA1", "Django legacy password hash"),
    ("bcrypt_sha256$", "Django bcrypt-SHA256", "Django bcrypt wrapper"),
    ("argon2$", "Django Argon2", "Django Argon2 wrapper"),

    # LDAP password schemes — base64 payload after the marker
    ("{SSHA}", "LDAP SSHA", "LDAP salted SHA-1 (base64 payload)"),
    ("{SHA}", "LDAP SHA", "LDAP SHA-1 (base64 payload)"),
    ("{SMD5}", "LDAP SMD5", "LDAP salted MD5 (base64 payload)"),
    ("{MD5}", "LDAP MD5", "LDAP MD5 (base64 payload)"),
    ("{CRYPT}", "LDAP CRYPT", "LDAP wrapping a crypt(3) hash"),

    # macOS/icloudKeychain
    ("$ml$", "macOS / iCloud Keychain", "Apple PBKDF2-SHA512"),
]


# =============================================================================
# Length-and-hex rules — fallback when no prefix matched
# =============================================================================
# Raw hash output is always the same length, so a string of N hex chars
# narrows down the algorithm. The list of algorithms for each length is
# sorted by REAL-WORLD prevalence. The first item gets MEDIUM confidence
# (the "most likely default"), the rest LOW (still possible)

# Hex chars are 0-9 plus a-f (or A-F if uppercase)
HEX_CHARSET: frozenset[str] = frozenset("0123456789abcdefABCDEF")

# Uppercase-only hex charset — some formats (MySQL5) ONLY ever emit
# uppercase hex because they print via the `%02X` C format specifier,
# so checking membership in this tighter charset lets us reject
# lowercase strings as false-positives instead of confidently saying
# "yes that is MySQL5" to an obviously hand-edited input
_HEX_UPPER_CHARSET: frozenset[str] = frozenset("0123456789ABCDEF")

# Length-in-hex-chars → list of algorithms, ordered by commonality
HEX_LENGTH_RULES: dict[int, list[str]] = {
    # 16 hex chars = 8 bytes = 64 bits. This is the pre-MySQL-4.1
    # OLD_PASSWORD() output — still produced today by MySQL's
    # OLD_PASSWORD() SQL function for legacy compatibility, and
    # still appears in CTFs and old MySQL breach dumps. The only
    # other thing that produces 16 hex chars in a security context
    # is a 64-bit CRC, which is rare enough that MySQL323 outranks it
    16: ["MySQL323", "CRC-64"],
    # 24 hex chars = 12 bytes = 96 bits
    24: ["Tiger-128"],
    # 32 hex chars = 16 bytes = 128 bits
    32: ["MD5", "NTLM", "MD4", "RIPEMD-128"],
    # 40 hex chars = 20 bytes = 160 bits
    40: ["SHA-1", "RIPEMD-160"],
    # 48 hex chars = 24 bytes = 192 bits
    48: ["Tiger-192"],
    # 56 hex chars = 28 bytes = 224 bits
    56: ["SHA-224", "SHA3-224"],
    # 64 hex chars = 32 bytes = 256 bits
    64: ["SHA-256", "SHA3-256", "BLAKE2s-256", "RIPEMD-256"],
    # 80 hex chars = 40 bytes = 320 bits (uncommon)
    80: ["RIPEMD-320"],
    # 96 hex chars = 48 bytes = 384 bits
    96: ["SHA-384", "SHA3-384"],
    # 128 hex chars = 64 bytes = 512 bits
    128: ["SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool"],
}
# =============================================================================
# Cracker-tool lookups — algorithm name -> hashcat mode / John format
# =============================================================================
# Keys must match the algorithm strings used in PREFIX_RULES and
# HEX_LENGTH_RULES exactly. Missing key = the tool has no matching mode
# (Tiger, CRC-64, yescrypt, etc.), which is honest, not a bug

HASHCAT_MODES: dict[str, int] = {
    "MD5": 0, "MD4": 900, "NTLM": 1000,
    "SHA-1": 100, "SHA-224": 1300, "SHA-256": 1400,
    "SHA-384": 10800, "SHA-512": 1700,
    "SHA3-224": 17300, "SHA3-256": 17400,
    "SHA3-384": 17500, "SHA3-512": 17600,
    "RIPEMD-160": 6000, "Whirlpool": 6100, "BLAKE2b-512": 600,
    "MySQL323": 200, "MySQL5": 300,
    "DES crypt": 1500, "MD5 crypt": 500, "Apache MD5-crypt": 1600,
    "SHA-256 crypt": 7400, "SHA-512 crypt": 1800,
    "bcrypt": 3200, "phpass": 400, "Drupal 7 (SHA-512)": 7900,
    "Django PBKDF2-SHA256": 10000,
    "LDAP SHA": 101, "LDAP SSHA": 111,
    "macOS / iCloud Keychain": 7100,
    "NetNTLMv1": 5500, "NetNTLMv2": 5600,
}

JOHN_FORMATS: dict[str, str] = {
    "MD5": "raw-md5", "MD4": "raw-md4", "NTLM": "nt",
    "SHA-1": "raw-sha1", "SHA-224": "raw-sha224",
    "SHA-256": "raw-sha256", "SHA-384": "raw-sha384",
    "SHA-512": "raw-sha512", "RIPEMD-160": "ripemd-160",
    "Whirlpool": "whirlpool", "BLAKE2b-512": "raw-blake2",
    "MySQL323": "mysql", "MySQL5": "mysql-sha1",
    "DES crypt": "descrypt", "MD5 crypt": "md5crypt",
    "Apache MD5-crypt": "md5crypt",
    "SHA-256 crypt": "sha256crypt", "SHA-512 crypt": "sha512crypt",
    "bcrypt": "bcrypt", "phpass": "phpass",
    "Drupal 7 (SHA-512)": "drupal7", "Django PBKDF2-SHA256": "django",
    "LDAP SHA": "nsldap", "LDAP SSHA": "salted-sha1",
    "macOS / iCloud Keychain": "PBKDF2-HMAC-SHA512",
    "NetNTLMv1": "netntlm", "NetNTLMv2": "netntlmv2",
}

# =============================================================================
# Crack difficulty — per-algorithm defaults, plus parameter parsing
# =============================================================================
# Keys must match the algorithm strings in PREFIX_RULES / HEX_LENGTH_RULES.
# Missing key = we do not know (generic PHC strings, LDAP CRYPT, hints)

CRACK_DIFFICULTY: dict[str, CrackDifficulty] = {
    # Fast, unsalted-or-lightly-salted digests: billions of guesses per second
    "MD5": "trivial", "MD4": "trivial", "NTLM": "trivial",
    "SHA-1": "trivial", "SHA-224": "trivial", "SHA-256": "trivial",
    "SHA-384": "trivial", "SHA-512": "trivial",
    "SHA3-224": "trivial", "SHA3-256": "trivial",
    "SHA3-384": "trivial", "SHA3-512": "trivial",
    "RIPEMD-128": "trivial", "RIPEMD-160": "trivial",
    "RIPEMD-256": "trivial", "RIPEMD-320": "trivial",
    "Tiger-128": "trivial", "Tiger-192": "trivial",
    "BLAKE2s-256": "trivial", "BLAKE2b-512": "trivial",
    "Whirlpool": "trivial", "CRC-64": "trivial",
    "MySQL323": "trivial", "MySQL5": "trivial",
    "DES crypt": "trivial",
    "LDAP SHA": "trivial", "LDAP SSHA": "trivial",
    "LDAP MD5": "trivial", "LDAP SMD5": "trivial",
    "NetNTLMv1": "trivial", "NetNTLMv2": "trivial",
    # Iterated but GPU-friendly: millions to hundreds of thousands per second
    "MD5 crypt": "moderate", "Apache MD5-crypt": "moderate",
    "phpass": "moderate", "Drupal 7 (SHA-512)": "moderate",
    "SHA-256 crypt": "moderate", "SHA-512 crypt": "moderate",
    "Django PBKDF2-SHA1": "moderate",
    # Many iterations or memory-hard: thousands per second
    "Django PBKDF2-SHA256": "hard", "macOS / iCloud Keychain": "hard",
    "yescrypt": "hard", "scrypt": "hard",
    # Parameterised: these are FALLBACKS, used only when the cost
    # parameters cannot be parsed out of the string
    "bcrypt": "hard", "Django bcrypt-SHA256": "hard",
    "Argon2id": "hard", "Argon2i": "hard", "Argon2d": "hard",
    "Django Argon2": "hard",
}

_BCRYPT_ALGORITHMS = frozenset({"bcrypt", "Django bcrypt-SHA256"})
_ARGON2_ALGORITHMS = frozenset(
    {"Argon2id", "Argon2i", "Argon2d", "Django Argon2"}
)

# bcrypt: `$2b$12$...` — the two digits are the cost; work doubles per +1.
# `search` (not `match`) so Django's `bcrypt_sha256$$2b$12$...` also works
_BCRYPT_COST_RE = re.compile(r"\$2[abxy]\$(\d{2})\$")
BCRYPT_DEFAULT_COST = 12
BCRYPT_MODERATE_BELOW = 10
BCRYPT_VERY_HARD_FROM = 14

# Argon2: `$argon2id$v=19$m=65536,t=3,p=4$...` — m is memory in KiB,
# t is passes, p is parallel lanes
_ARGON2_PARAMS_RE = re.compile(r"m=(\d+),t=(\d+),p=(\d+)")
ARGON2_MODERATE_BELOW_KIB = 8192  # 8 MiB
ARGON2_VERY_HARD_FROM_KIB = 65536  # 64 MiB


def _bcrypt_difficulty(text: str) -> tuple[CrackDifficulty, str] | None:
    """Read the bcrypt cost factor and judge it; None if no cost found"""
    match = _BCRYPT_COST_RE.search(text)
    if match is None:
        return None
    cost = int(match.group(1))
    difficulty: CrackDifficulty
    if cost < BCRYPT_MODERATE_BELOW:
        difficulty = "moderate"
        note = f"cost={cost} — much weaker than the default {BCRYPT_DEFAULT_COST}"
    elif cost < BCRYPT_DEFAULT_COST:
        difficulty = "hard"
        note = f"cost={cost} — below the modern default {BCRYPT_DEFAULT_COST}"
    elif cost == BCRYPT_DEFAULT_COST:
        difficulty = "hard"
        note = f"cost={cost} — the modern default"
    elif cost < BCRYPT_VERY_HARD_FROM:
        difficulty = "hard"
        note = f"cost={cost} — above the modern default {BCRYPT_DEFAULT_COST}"
    else:
        difficulty = "very_hard"
        note = f"cost={cost} — paranoid setting"
    return difficulty, note


def _argon2_difficulty(text: str) -> tuple[CrackDifficulty, str] | None:
    """Read Argon2 memory/time/lanes and judge them; None if absent"""
    match = _ARGON2_PARAMS_RE.search(text)
    if match is None:
        return None
    memory_kib = int(match.group(1))
    time_cost = int(match.group(2))
    lanes = int(match.group(3))
    params = f"m={memory_kib / 1024:g} MiB, t={time_cost}, p={lanes}"
    difficulty: CrackDifficulty
    if memory_kib < ARGON2_MODERATE_BELOW_KIB:
        difficulty = "moderate"
        note = f"{params} — very little memory, weak for Argon2"
    elif memory_kib < ARGON2_VERY_HARD_FROM_KIB:
        difficulty = "hard"
        note = f"{params} — reasonable memory cost"
    else:
        difficulty = "very_hard"
        note = f"{params} — strong memory cost"
    return difficulty, note


def _assess_difficulty(
    algorithm: str,
    text: str,
) -> tuple[CrackDifficulty | None, str]:
    """
    Return (difficulty, note) for one candidate

    Parameterised algorithms (bcrypt, Argon2) are judged from the
    parameters inside `text`. Everything else, and any parameterised
    hash whose parameters will not parse, uses the CRACK_DIFFICULTY
    table. The note is empty when there is nothing parameter-specific
    to say
    """
    detail: tuple[CrackDifficulty, str] | None = None
    if algorithm in _BCRYPT_ALGORITHMS:
        detail = _bcrypt_difficulty(text)
    elif algorithm in _ARGON2_ALGORITHMS:
        detail = _argon2_difficulty(text)
    if detail is not None:
        return detail
    return CRACK_DIFFICULTY.get(algorithm), ""
    

def _make_candidate(
    algorithm: str,
    score: float,
    reason: str,
    hash_text: str = "",
) -> HashCandidate:
    """
    Build a HashCandidate and fill in tool hints and crack difficulty

    `hash_text` is the hash string itself. Only the prefix step passes
    it, because only PHC strings carry readable cost parameters. When
    parsing yields a note (`cost=12 — the modern default`) it is
    appended to the reason
    """
    difficulty, note = _assess_difficulty(algorithm, hash_text)
    if note:
        reason = f"{reason}; {note}"
    return HashCandidate(
        algorithm = algorithm,
        confidence_score = round(min(max(score, 0.0), 1.0), 3),
        reason = reason,
        hashcat_mode = HASHCAT_MODES.get(algorithm),
        john_format = JOHN_FORMATS.get(algorithm),
        crack_difficulty = difficulty,
    )

# =============================================================================
# Helpers
# =============================================================================

def _is_hex(text: str) -> bool:
    """
    Return True iff every character in text is a hex digit and text is non-empty

    A hash like "5f4dcc..." passes; an empty string or anything with
    a non-hex character fails. We use the HEX_CHARSET frozenset for
    membership tests because `c in frozenset` is O(1) lookup, faster
    than `c in "0123456789abcdef..."` for big inputs
    """
    return bool(text) and all(c in HEX_CHARSET for c in text)

def _charset_bonus(text: str) -> float:
    """
    Return CHARSET_BONUS if hex text is single-case, else 0.0

    Real hash output is always all-lowercase or all-uppercase hex.
    Mixed case such as `5F4dcc...` is weaker evidence of a raw digest.
    Digit-only strings count as single-case
    """
    if text == text.lower() or text == text.upper():
        return CHARSET_BONUS
    return 0.0


# MySQL5 layout: `*` followed by 40 uppercase hex chars.
# Pulling both numbers out as named constants keeps the helper below
# from reading like sprinkled-in magic numbers — `_MYSQL5_TOTAL_LENGTH`
# tells the reader WHY the helper compares to 41 (40 hex chars + the
# leading `*`) instead of leaving 41 unexplained
_MYSQL5_HEX_BODY_LENGTH = 40
_MYSQL5_TOTAL_LENGTH = _MYSQL5_HEX_BODY_LENGTH + 1


def _is_mysql5(text: str) -> bool:
    """
    Return True for MySQL5 password format: `*` then 40 UPPERCASE hex chars

    MySQL5 stores SHA-1(SHA-1(password)) printed in uppercase hex with
    a leading `*`. Real MySQL5 output uses the `%02X` C format
    specifier, which is uppercase-only. We reject lowercase here so
    we do not return a confident HIGH-confidence "MySQL5" verdict on
    a hand-edited or mistyped string — better to fall through to
    no-match than to lie with conviction

    NOTE: we cannot just call `body.isupper()` to enforce the case.
    Python's `str.isupper` returns False when a string contains NO
    cased characters at all, which would wrongly reject an all-digit
    hex body like "0123456789ABCDEF..." with no letters in it.
    Checking membership in an uppercase-only charset is the test
    that actually matches the spec
    """
    if len(text) != _MYSQL5_TOTAL_LENGTH or not text.startswith("*"):
        return False
    body = text[1 :]
    return all(c in _HEX_UPPER_CHARSET for c in body)


# Traditional DES crypt — legacy /etc/passwd hashes from pre-shadow
# Unix systems. They have no prefix at all: just 13 characters drawn
# from a specific 64-char alphabet (the same alphabet used by all
# crypt(3) variants for their base64-style output). We pull both the
# charset and the expected length out as named constants so the helper
# below reads like its meaning instead of like sprinkled magic numbers
_DESCRYPT_CHARSET: frozenset[str] = frozenset(
    "./0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
)
_DESCRYPT_TOTAL_LENGTH = 13


def _is_descrypt(text: str) -> bool:
    """
    Return True for traditional 13-char DES crypt (legacy /etc/passwd)

    No prefix at all — just 13 characters drawn from `./0-9A-Za-z`.
    Old enough that you mostly see it in retro CTFs now, but real
    enough that hashcat still ships a mode (1500) for cracking it.
    We report MEDIUM (not HIGH) confidence on a match because a 13-char
    string in that charset CAN be other things (some session IDs,
    encoded values), and a beginner deserves an honest confidence
    level rather than a false-positive at HIGH
    """
    return (
        len(text) == _DESCRYPT_TOTAL_LENGTH
        and all(c in _DESCRYPT_CHARSET for c in text)
    )

# Base58 (Bitcoin alphabet) — no 0, O, I, or l, because they look alike.
# Bitcoin addresses are 26-35 chars; IPFS CIDv0 is 46; WIF keys are 51-52.
# Any plain alphanumeric word without those four letters is ALSO valid
# Base58, so the length floor and the mixed letters-and-digits check below
# are what keep this from flagging ordinary text

_BASE58_CHARSET: frozenset[str] = frozenset(
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)
_BASE58_MIN_LENGTH = 26
_BASE58_MAX_LENGTH = 60

# Base32 (RFC 4648) — uppercase A-Z plus digits 2-7, optional `=` padding.
# TOTP secrets are usually 16 or 32 chars
_BASE32_CHARSET: frozenset[str] = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
_BASE32_MIN_LENGTH = 16
_BASE32_MAX_PADDING = 6


def _is_base58(text: str) -> bool:
    """
    Return True if text is plausibly Base58: right length, only Base58
    characters, and a mix of letters and digits

    The mix check rejects plain words like "thequickbrownfoxjumps..."
    that happen to avoid 0/O/I/l. Real addresses and CIDs always
    contain both
    """
    return (
        _BASE58_MIN_LENGTH <= len(text) <= _BASE58_MAX_LENGTH
        and all(c in _BASE58_CHARSET for c in text)
        and any(c.isdigit() for c in text)
        and any(c.isalpha() for c in text)
    )


def _is_base32(text: str) -> bool:
    """
    Return True if text is plausibly Base32: uppercase letters and 2-7,
    long enough, with at most 6 trailing `=` padding characters
    """
    body = text.rstrip("=")
    padding = len(text) - len(body)
    return (
        len(body) >= _BASE32_MIN_LENGTH
        and padding <= _BASE32_MAX_PADDING
        and all(c in _BASE32_CHARSET for c in body)
    )


# =============================================================================
# The actual identifier
# =============================================================================
# pylint flags this function for having many return statements and many
# branches. That is the cost of writing the function as six numbered,
# linear steps — each step gets its own short block and returns the
# moment it finds a match, which is the structure that maps cleanly
# onto the docstring. Refactoring into helper functions would obscure
# the pedagogical line-by-line flow, so we accept the extra returns
# here as a deliberate teaching choice and silence the two warnings
# pylint: disable=too-many-return-statements,too-many-branches


def identify(raw_input: str) -> list[HashCandidate]:
    """
    Return ranked candidates for what algorithm produced `raw_input`

    Algorithm
    ---------
    Whitespace is trimmed from `raw_input` first. Then the six
    matching steps below run in order — each step's labeled comment
    (`# ----- Step N: ... -----`) inside the function body matches
    the number in this list, so the docstring and the code stay in
    lockstep:

    1. Walk the PREFIX_RULES table. The first prefix that matches
       wins (HIGH confidence). Each table row is unique enough that
       at most one entry can match a given input
    2. Check special non-PHC formats in order — NetNTLMv1/v2
       challenge-response records, MySQL5 (`*<40 hex>`), and the
       legacy 13-char DES crypt. Each has a distinctive shape that
       takes precedence over generic length-based matching
    3. If the input is pure hex, look up its length in
       HEX_LENGTH_RULES and report each candidate. The first entry
       at each length gets MEDIUM confidence (the modern default);
       the rest LOW
    4. If the input has a `$<algo>$...` shape but no PREFIX_RULES
       row matched, fall back to a generic PHC string match — LOW
       confidence because we only matched the shape, not a specific
       rule
    5. If the input looks like a URL (`http://`, `https://`), a `0x`
       hex value, a JWT (`eyJ...`), Base32, Base58, or a base64 blob
       (contains `+`, `/`, or `=`), say so with LOW confidence —
       these are not hashes, but a beginner deserves to know what
       they pasted instead of a silent no-match. The checks run in
       that order, because URLs and padded Base32 contain `/` and
       `=`, which the base64 check would otherwise swallow

    6. If nothing matched at all, return an empty list

    Parameters
    ----------
    raw_input
        The hash string to identify. Whitespace is trimmed before
        analysis but the rest is treated literally — case matters
        because some algorithms use uppercase output

    Returns
    -------
    list[HashCandidate]
        Possibly empty. When non-empty, candidates are ordered by
        confidence (high before medium before low) and within each
        confidence band by likelihood
    """
    # Trim whitespace — copy-pasted hashes often arrive with trailing
    # newlines or leading spaces. We do not modify case because some
    # formats are case-sensitive
    text = raw_input.strip()

    if not text:
        return []

    # ----- Step 1: prefix rules -----
    # Walk the table top-to-bottom. Entries in PREFIX_RULES are crafted
    # so that no two of them can EVER both match the same input — the
    # first prefix that matches is THE match. So we return it right
    # away instead of continuing the loop. HIGH confidence is the
    # right label because a known prefix is a definitive self-
    # identification: the hash literally announces what algorithm
    # produced it, we are not guessing
    for prefix, algorithm, note in PREFIX_RULES:
        if text.startswith(prefix):
            return [
                _make_candidate(
                    algorithm = algorithm,
                    score = SCORE_PREFIX,
                    reason = f"prefix `{prefix}` — {note}",
                    hash_text = text,
                )
            ]

    # ----- Step 2: special non-PHC formats -----
    # Formats that do not fit the `$algo$...` PHC mold but still have
    # unmistakable shapes. We check each in turn before falling through
    # to the generic length-based step

    # NetNTLMv1 / NetNTLMv2 — the dominant outputs of AD pentest
    # tools like Responder, secretsdump, ntlmrelayx, and Inveigh.
    # They are NOT hashes in the "irreversible function" sense —
    # they are challenge-response records — but every beginner who
    # runs their first AD lab pastes one of these into a hash
    # identifier. The literal `::` (an empty second field, where the
    # LM-hash used to live) is the structural giveaway. We test v2
    # FIRST because v2's hmac field at index 4 is 32 hex chars while
    # v1's nthash at the same index is 48 — so if we tested v1 first
    # we would still match v2 inputs at parts[3] (also 48 in v2's
    # case for the challenge length in some encodings)
    if "::" in text and text.count(":") >= 4:
        parts = text.split(":")
        # NetNTLMv2 layout:
        #   user :: domain : challenge : hmac(32 hex) : blob(>=32 hex)
        # The hmac at parts[4] is exactly 32 hex chars — that single
        # property is enough to disambiguate v2 from v1
        if (len(parts) >= 6 and len(parts[4]) == 32 and _is_hex(parts[4])):
            return [
                _make_candidate(
                    algorithm = "NetNTLMv2",
                    score = SCORE_SPECIAL_SHAPE,
                    reason =
                    "user::domain:challenge:hmac(32 hex):blob shape",
                )
            ]
        # NetNTLMv1 layout:
        #   user :: domain : lmhash(48 hex) : nthash(48 hex) : challenge
        # The lmhash at parts[3] is exactly 48 hex chars
        if (len(parts) >= 6 and len(parts[3]) == 48 and _is_hex(parts[3])):
            return [
                _make_candidate(
                    algorithm = "NetNTLMv1",
                    score = SCORE_SPECIAL_SHAPE,
                    reason =
                    "user::domain:lm(48 hex):nt(48 hex):challenge shape",
                )
            ]

    # MySQL5 — literal `*` + 40 uppercase hex chars
    if _is_mysql5(text):
        return [
            _make_candidate(
                algorithm = "MySQL5",
                score = SCORE_SPECIAL_SHAPE,
                reason =
                "starts with `*` followed by 40 uppercase hex chars",
            )
        ]

    # Traditional 13-char DES crypt — legacy /etc/passwd format
    # with no prefix at all. We report MEDIUM (not HIGH) because the
    # 13-char `./0-9A-Za-z` shape isn't fully unique to DES crypt
    if _is_descrypt(text):
        return [
            _make_candidate(
                algorithm = "DES crypt",
                score = SCORE_LENGTH_FIRST + CHARSET_BONUS,
                reason =
                "13 chars in `./0-9A-Za-z` — legacy /etc/passwd format",
            )
        ]

        # ----- Step 3: length + hex charset -----
    if _is_hex(text):
        algorithms = HEX_LENGTH_RULES.get(len(text), [])
        bonus = _charset_bonus(text)
        candidates: list[HashCandidate] = []
        # rank is 1-based: 1st candidate scores 0.55, 2nd 0.275, 3rd 0.183...
        # The charset bonus is added on top of each
        for rank, algorithm in enumerate(algorithms, start = 1):
            label = (
                "most likely candidate at this length"
                if rank == 1 else "also possible at this length"
            )
            candidates.append(
                _make_candidate(
                    algorithm = algorithm,
                    score = SCORE_LENGTH_FIRST / rank + bonus,
                    reason = f"{len(text)} hex chars — {label}",
                )
            )
        return candidates
    # ----- Step 4: generic PHC string fallback -----
    # If the input starts with `$<name>$...` and <name> looks like a
    # plausible algorithm identifier, it is almost certainly a PHC
    # string from an algorithm we do not have a specific rule for.
    # Passlib alone ships ~30 PHC encodings; our PREFIX_RULES table
    # covers only the most common 20-or-so. Reporting it as a generic
    # PHC string with the extracted algorithm name is strictly better
    # than silence, and the LOW confidence label is honest about not
    # having a specific rule to confirm the algorithm
    if text.startswith("$"):
        # Drop the leading `$`, then look for the second `$` that
        # closes the algorithm-name field. If there's no second `$`,
        # this isn't a PHC string at all, just a string that happens
        # to start with `$` — fall through
        rest = text[1 :]
        if "$" in rest:
            algo_name = rest.split("$", 1)[0]
            # The PHC spec restricts algorithm IDs to alphanumeric
            # plus `-` and `_`. We accept exactly that charset and
            # reject anything weirder — anything containing spaces,
            # punctuation, etc. is almost certainly not a real PHC
            # string and we'd rather stay silent than make up a name
            if algo_name and all(c.isalnum() or c in "-_"
                                 for c in algo_name):
                return [
                    _make_candidate(
                        algorithm = f"PHC string ({algo_name})",
                        score = SCORE_GENERIC_PHC,
                        reason =
                        f"`${algo_name}$...` shape — generic PHC, no specific rule",
                    )
                ]

    # ----- Step 5: not-a-hash shape hints -----
    # Order matters: URLs and padded Base32 both contain characters
    # (`/`, `=`) that the base64 check at the bottom would swallow, and
    # Base32 must precede Base58 because every Base32 string without
    # I/O is also valid Base58. Every branch is LOW confidence — these
    # are shape hints, not certainties
    lowered = text.lower()

    if lowered.startswith(("http://", "https://")):
        return [
            _make_candidate(
                algorithm = "URL (not a hash)",
                score = SCORE_NOT_A_HASH,
                reason = "starts with `http://` or `https://` — a web address",
            )
        ]

    if lowered.startswith("0x") and _is_hex(text[2 :]):
        body_length = len(text) - 2
        if body_length == 40:
            hint = "`0x` + 40 hex chars — looks like an Ethereum address"
        elif body_length == 64:
            hint = (
                "`0x` + 64 hex chars — could be an Ethereum tx hash or "
                "Keccak-256 digest; drop the `0x` to see hex candidates"
            )
        else:
            hint = "`0x` + hex digits — address, memory value, or similar"
        return [
            _make_candidate(
                algorithm = "0x hex value (not a password hash)",
                score = SCORE_NOT_A_HASH,
                reason = hint,
            )
        ]

    if text.startswith("eyJ"):
        # (your existing JWT branch, unchanged)
        return [
            _make_candidate(
                algorithm = "JWT (not a hash)",
                score = SCORE_NOT_A_HASH,
                reason =
                "leading `eyJ` is base64 of `{\"` — JWT, not a hash",
            )
        ]

    if _is_base32(text):
        return [
            _make_candidate(
                algorithm = "Base32 string (not a hash)",
                score = SCORE_NOT_A_HASH,
                reason =
                "only A-Z and 2-7 — TOTP secret, onion address, or other Base32 data",
            )
        ]

    if _is_base58(text):
        return [
            _make_candidate(
                algorithm = "Base58 string (not a hash)",
                score = SCORE_NOT_A_HASH,
                reason =
                "only Base58 characters — Bitcoin address or IPFS CID? weak signal, could be any token",
            )
        ]

    if any(c in text for c in "+/=") and len(text) > 8:
        # (your existing base64 branch, unchanged)
        return [
            _make_candidate(
                algorithm = "Base64 blob (not a hash)",
                score = SCORE_NOT_A_HASH,
                reason = "contains base64-only chars (`+`, `/`, `=`)",
            )
        ]

    # ----- Step 6: nothing matched -----
    # If we got here, the input has no known prefix, no special
    # shape, no hex length we recognize, no PHC-string shape, and
    # no obvious not-a-hash shape either. Returning an empty list
    # is better than returning bad guesses — the CLI prints a
    # clean "could not identify" message instead
    return []

    # =============================================================================
# Field splitting — a layer ON TOP of identify()
# =============================================================================
# Breach dumps often hold combined records like `user:hash:salt`. This layer
# splits on `:` and labels each field. It never changes identify(); it just
# calls it once per field and adds position-based heuristics

FieldRole = Literal["username", "hash", "salt", "garbage", "empty"]


@dataclass(frozen = True, slots = True)
class SplitField:
    """
    One colon-separated field and what we think it is

    position    1-based index of the field in the record
    value       the field text, whitespace-trimmed
    role        username / hash / salt / garbage / empty
    detail      short reason shown in the table
    candidate   the top HashCandidate when role == "hash", else None
    """
    position: int
    value: str
    role: FieldRole
    detail: str
    candidate: HashCandidate | None = None


# Every "not a hash" hint in step 5 of identify() contains this marker:
# "URL (not a hash)", "0x hex value (not a password hash)", ...
_NOT_A_HASH_MARKER = "(not a"

# Starts with a letter, then letters/digits/`.`/`_`/`@`/`-`, max 32 chars
# (covers `alice`, `bob_99`, `alice@example.com`)
_USERNAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9._@-]{0,31}")
_SALT_MAX_LENGTH = 64


def _top_hash_candidate(value: str) -> HashCandidate | None:
    """
    Return identify()'s best guess for `value`, but only if it is a real hash

    Returns None for empty fields, all-letter fields (usernames — this
    stops a 13-letter name matching DES crypt), and the "not a hash" hints
    """
    if not value or value.isalpha():
        return None
    candidates = identify(value)
    if not candidates or _NOT_A_HASH_MARKER in candidates[0].algorithm:
        return None
    return candidates[0]


def _classify_field(
    position: int,
    value: str,
    candidate: HashCandidate | None,
    before_hash: bool,
) -> SplitField:
    """Label one field using its hash result and where it sits in the record"""
    if not value:
        return SplitField(position, value, "empty", "empty field")
    if candidate is not None:
        detail = f"{candidate.algorithm} ({candidate.confidence} confidence)"
        return SplitField(position, value, "hash", detail, candidate)
    if before_hash:
        if _USERNAME_RE.fullmatch(value):
            return SplitField(
                position, value, "username", "name-shaped text before the hash"
            )
        return SplitField(
            position, value, "garbage", "not a hash and not name-shaped"
        )
    if len(value) <= _SALT_MAX_LENGTH and not any(c.isspace() for c in value):
        return SplitField(position, value, "salt", "short token after the hash")
    return SplitField(
        position, value, "garbage", "too long or has whitespace for a salt"
    )


def split_fields(raw_input: str) -> list[SplitField]:
    """
    Split a `user:hash:salt`-style record and classify every field

    A record that is ALREADY a high-confidence format as a whole (NetNTLM
    lines are full of colons) is returned as one hash field instead of
    being torn apart. Blank input returns an empty list
    """
    text = raw_input.strip()
    if not text:
        return []

    whole = identify(text)
    if whole and whole[0].confidence == "high":
        detail = f"{whole[0].algorithm} (whole record, not split)"
        return [SplitField(1, text, "hash", detail, whole[0])]

    values = [part.strip() for part in text.split(":")]
    candidates = [_top_hash_candidate(value) for value in values]
    # Index of the first real hash, or None. `is None` (not `or`) because
    # index 0 is a valid position and is falsy
    first_hash = next(
        (i for i, candidate in enumerate(candidates) if candidate is not None),
        None,
    )

    return [
        _classify_field(
            position = index + 1,
            value = value,
            candidate = candidate,
            before_hash = first_hash is None or index < first_hash,
        ) for index, (value, candidate) in enumerate(
            zip(values, candidates, strict = True)
        )
    ]


# =============================================================================
# CLI — argparse + a rich table
# =============================================================================


def _build_argument_parser() -> argparse.ArgumentParser:
    """
    Construct the argparse parser used by main()

    Pulled out into its own function so tests can call it without
    actually running the CLI. Each argument is documented inline
    """
    parser = argparse.ArgumentParser(
        prog = "hashid",
        description = (
            "Identify a hash string by prefix, length, and charset. "
            "Returns ranked candidates with confidence and reasoning."
        ),
    )
    parser.add_argument(
        "hash",
        nargs="?",
        help =
        "The hash string to identify (wrap in single quotes if it contains $).",
    )
    parser.add_argument(
        "--top",
        "-n",
        type = int,
        default = 5,
        help = "Show at most this many candidates (default: 5, minimum 1).",
    )
    parser.add_argument(
        "--json",
        action = "store_true",
        help = "Output candidates as JSON instead of a rich table.",
    )
    parser.add_argument(
        "--file",
        "-f",
        metavar = "PATH",
        help = "Read one hash per line from a file (blank lines are skipped).",
    )
    parser.add_argument(
        "--split",
        "-s",
        action = "store_true",
        help = "Treat each input as a colon-separated record "
        "(user:hash:salt) and classify every field.",
    )
    return parser


def _render_table(
    raw_input: str,
    candidates: list[HashCandidate],
    console: Console,
) -> None:
    """
    Print a rich Table showing the identified candidates

    A Table is a bordered grid. We give it six columns: algorithm,
    confidence (color-coded),difficulty,reason,hashcat and john format
    """
    table = Table(
        title = f"Candidates for: {raw_input.strip()}",
        title_style = "bold cyan",
        show_lines = False,
    )
    table.add_column("algorithm", style = "bold white", no_wrap = True)
    table.add_column("confidence", no_wrap = True)
    table.add_column("difficulty", no_wrap = True)
    table.add_column("reason", style = "dim")
    table.add_column("hashcat -m" , justify= "right" ,no_wrap=True)
    table.add_column("john --format" , no_wrap= True)



    # Color confidence levels so the eye can scan them quickly.
    # green → yellow → cyan is a gradient that reads "strong, weaker,
    # weakest" without ever colliding with red, which is reserved for
    # the no-match error message printed elsewhere in main(). Painting
    # "low" in red would make three weak-but-valid guesses look like
    # three errors at a glance — broken visual hierarchy
    confidence_colors: dict[Confidence,
                            str] = {
                                "high": "green",
                                "medium": "yellow",
                                "low": "cyan",
                            }
    for candidate in candidates:
        color = confidence_colors[candidate.confidence]
        table.add_row(
            candidate.algorithm,
            f"[{color}]{candidate.confidence} "
            f"({candidate.confidence_score:.2f})[/{color}]",
            candidate.crack_difficulty or "-",
            candidate.reason,
            "-" if candidate.hashcat_mode is None else str(candidate.hashcat_mode),
            candidate.john_format or "-",
        )

    console.print(table)




_ROLE_COLORS: dict[FieldRole, str] = {
    "username": "cyan",
    "hash": "green",
    "salt": "yellow",
    "garbage": "red",
    "empty": "dim",
    }





def _render_split_table(
    record: str,
    fields: list[SplitField],
    count: int,
    console: Console,
) -> None:
    """Print one table per record: field number, value, role, reason"""
    suffix = f" (repeated {count} times)" if count > 1 else ""
    table = Table(
        title = f"Fields in: {escape(record)}{suffix}",
        title_style = "bold cyan",
    )
    table.add_column("#", justify = "right", no_wrap = True)
    # overflow="fold" wraps long values (a 60-char bcrypt) instead of
    # cutting them off with an ellipsis
    table.add_column("field", overflow = "fold")
    table.add_column("role", no_wrap = True)
    table.add_column("detail", style = "dim")
    for field in fields:
        color = _ROLE_COLORS[field.role]
        table.add_row(
            str(field.position),
            escape(field.value) or "(empty)",
            f"[{color}]{field.role}[/{color}]",
            escape(field.detail),
        )
    console.print(table)


def _run_split(
    records: list[str],
    counts: Counter[str],
    as_json: bool,
    is_batch: bool,
    console: Console,
) -> int:
    """
    Run --split mode over the unique records and return an exit code

    JSON always exits 0 (the caller reads the roles). Text mode exits 1
    if any record had no hash field at all
    """
    results = [(record, split_fields(record)) for record in records]

    if as_json:
        payload = [
            {
                "input": record,
                "count": counts[record],
                "fields": [asdict(f) for f in fields],
            } for record, fields in results
        ]
        output = payload if is_batch else {
            "input": payload[0]["input"],
            "fields": payload[0]["fields"],
        }
        print(json.dumps(output, indent = 2, ensure_ascii = False))
        return 0

    without_hash = 0
    for record, fields in results:
        _render_split_table(record, fields, counts[record], console)
        if not any(f.role == "hash" for f in fields):
            without_hash += 1
            console.print("[red]no hash field found in this record[/red]")
    return 0 if without_hash == 0 else 1




def _read_hash_file(path: str, console: Console) -> list[str] | None:
    """
    Return the non-blank lines of `path`, or None if it could not be read

    argparse.FileType() would be the one-liner here, but it raises
    argparse's own traceback-flavoured `ArgumentError` straight to the
    user for a typo'd path. Opening the file ourselves lets us print
    one clean red line and exit with a status code instead — the nicer
    failure mode for a CLI a beginner is using for the first time
    """
    try:
        with open(path, encoding = "utf-8", errors = "replace") as handle:
            return [line.strip() for line in handle if line.strip()]
    except OSError as error:
        console.print(f"[red]could not read `{path}`:[/red] {error}")
        return None


def main() -> int:
    """
    CLI entry point — return a process exit code

    0 = identified (or JSON printed, even when the candidate list is
        empty, because a machine caller reads that list itself)
    1 = nothing identified in text mode — a human should look again
    2 = usage error — no input, unreadable/empty file, bad `--top`

    Wrapping the body in a function (instead of running at module
    import time) means the test suite can import this module without
    accidentally executing the CLI
    """
    parser = _build_argument_parser()
    args = parser.parse_args()
    console = Console()

    # ----- Gather the inputs -----
    # Three sources, in priority order: --file, the positional hash,
    # then piped stdin. Anything after that means "no input given",
    # and we print help rather than guessing
    raw_lines: list[str] = []
    is_batch = False

    if args.file:
        lines = _read_hash_file(args.file, console)
        if lines is None:
            return 2
        raw_lines = lines
        is_batch = True
    elif args.hash:
        raw_lines = [args.hash]
    elif not sys.stdin.isatty():
        raw_lines = [line.strip() for line in sys.stdin if line.strip()]
        is_batch = True
    else:
        # No input at all — show help and bail. Exit 2 (usage error)
        # rather than 1, so a script driving this tool can tell "I
        # forgot to pass a hash" apart from "the hash is unknown"
        parser.print_help()
        return 2

    # A --file/stdin that turned out to be empty is a usage problem,
    # not a "no identification" result — say so explicitly instead of
    # printing nothing at all
    if not raw_lines:
        console.print("[red]no hashes to identify[/red] (input was empty)")
        return 2

    # `top` has to be at least 1. `candidates[:0]` is a valid slice
    # that yields an empty list, which would otherwise render a header
    # with no rows and exit 0 as if it had found something
    top = args.top
    if top < 1:
        console.print(f"[yellow]--top {top} is meaningless[/yellow] — using 1")
        top = 1

    # ----- Deduplicate, keeping order of first appearance -----
    # Breach dumps repeat the same hash across rows (one row per
    # account sharing a password). Counting repeats turns 40k lines
    # into a readable list and tells the user which hash is shared
    hash_counts = Counter(raw_lines)
    unique_hashes = list(hash_counts)

    # More than one unique hash always means batch output, even if the
    # user typed them some other way
    if len(unique_hashes) > 1:
        is_batch = True

        # ----- --split mode: classify colon-separated fields -----
    if args.split:
        return _run_split(unique_hashes, hash_counts, args.json, is_batch, console)

    # ----- JSON output (single object, or array for batches) -----
    if args.json:
        if is_batch:
            batch_output = [
                {
                    "input": h,
                    "count": hash_counts[h],
                    "candidates": [asdict(c) for c in identify(h)[:top]],
                }
                for h in unique_hashes
            ]
            print(json.dumps(batch_output, indent = 2, ensure_ascii = False))
        else:
            h = unique_hashes[0]
            print(
                json.dumps(
                    {"input": h, "candidates": [asdict(c) for c in identify(h)[:top]]},
                    indent = 2,
                    ensure_ascii = False,
                )
            )
        # JSON is machine-readable: the caller inspects `candidates`
        # being empty itself, so we always exit 0. (The old code exited
        # 0 for JSON and 1 for the text table on the same unknown
        # input — an inconsistency a shell script would trip over.)
        return 0

    # ----- Batch text output: one line per hash, with repeat count -----
    if is_batch:
        unidentified = 0
        for h in unique_hashes:
            trimmed = identify(h)[:top]
            count = hash_counts[h]
            repeat_msg = f" (repeated {count} times)" if count > 1 else ""

            if not trimmed:
                unidentified += 1
                console.print(
                    f"[red]{h}{repeat_msg}[/red] -> No identification possible"
                )
            else:
                top_candidate = trimmed[0]
                console.print(
                    f"[green]{h}{repeat_msg}[/green] -> {top_candidate.algorithm} "
                    f"({top_candidate.confidence} confidence)"
                )
        return 0 if unidentified == 0 else 1

    # ----- Single interactive hash: the full rich table -----
    h = unique_hashes[0]
    candidates = identify(h)
    trimmed = candidates[:top]

    if not candidates:
        console.print(
            "[red]No identification possible.[/red] "
            "Input did not match any known prefix, special format, "
            "or hex length."
        )
        return 1

    _render_table(h, trimmed, console)

    top_candidate = trimmed[0]
    if top_candidate.hashcat_mode is not None:
        # shlex.quote wraps the hash in single quotes so `$` survives bash
        # escape() stops rich from treating `[...]` inside a hash as markup
        command = (
            f"hashcat -m {top_candidate.hashcat_mode} -a 0 "
            f"{shlex.quote(h)} wordlist.txt"
        )
        console.print(f"\n[dim]Next step:[/dim] {escape(command)}")
    elif top_candidate.confidence == "high":
        console.print(
            "\n[dim]No hashcat mode known for this format — "
            "see ../../beginner/hash-cracker.[/dim]"
        )

    return 0
# =============================================================================
# Entry point
# =============================================================================
# Without this guard the module is importable but running it directly —
# `python hash_identifier.py <hash>` — would silently do nothing, because
# main() would never be called. The guard also keeps the CLI from firing
# when a test suite does `import hash_identifier`. `sys.exit(...)` turns
# the returned status code into the process exit code.
if __name__ == "__main__":
    sys.exit(main())
