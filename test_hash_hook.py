"""
©AngelaMos | 2026
test_hash_hook.py
"""

from pathlib import Path
import pytest
import hash_hook

BCRYPT = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"


def _write(tmp_path: Path, text: str) -> str:
    file = tmp_path / "sample.txt"
    file.write_text(text, encoding="utf-8")
    return str(file)


def test_clean_file_is_allowed(tmp_path: Path) -> None:
    assert hash_hook.main([_write(tmp_path, "hello world\nnothing here\n")]) == 0


def test_bare_hash_line_blocks(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = hash_hook.main([_write(tmp_path, f"ok\n{BCRYPT}\n")])
    assert code == 1
    assert ":2:" in capsys.readouterr().out


def test_hash_inside_assignment_blocks(tmp_path: Path) -> None:
    assert hash_hook.main([_write(tmp_path, f'password = "{BCRYPT}"\n')]) == 1


def test_user_colon_hash_blocks(tmp_path: Path) -> None:
    assert hash_hook.main([_write(tmp_path, f"alice:{BCRYPT}\n")]) == 1


def test_allow_marker_skips_line(tmp_path: Path) -> None:
    line = f'FIXTURE = "{BCRYPT}"  # pragma: allow-hash\n'
    assert hash_hook.main([_write(tmp_path, line)]) == 0


def test_medium_confidence_hex_is_allowed(tmp_path: Path) -> None:
    # 32 hex could be MD5 or NTLM or anything, so we don't block
    assert hash_hook.main([_write(tmp_path, "5f4dcc3b5aa765d61d8327deb882cf99\n")]) == 0


def test_binary_and_missing_files_are_skipped(tmp_path: Path) -> None:
    binary = tmp_path / "blob.bin"
    binary.write_bytes(b"\xff\xfe\x00\x80")
    assert hash_hook.main([str(binary), str(tmp_path / "nope.txt")]) == 0

def test_short_prefix_in_prose_is_allowed(tmp_path: Path) -> None:
    # `$2b$...` in a docstring has the bcrypt prefix but is not a hash
    text = 'Example: password = "$2b$..." or math like $S$ and $P$\n'
    assert hash_hook.main([_write(tmp_path, text)]) == 0

def test_truncated_example_with_ellipsis_is_allowed(tmp_path: Path) -> None:
    # Docs abbreviate hashes as `$2b$12$Eix...`, which is a placeholder
    text = "python hashid.py '$2b$12$EixZaYVK1fsbw1ZfbX3OXe...'\n"
    assert hash_hook.main([_write(tmp_path, text)]) == 0