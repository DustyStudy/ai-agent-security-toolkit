"""open_within_roots: the tool-side open that closes the check-then-open symlink race
(the class behind the Filesystem MCP server's CVE-2025-53109/53110)."""

from __future__ import annotations

import os
import sys

import pytest

from agentsec.sandbox import open_within_roots
from agentsec.sandbox.validators import path_within_roots

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "root"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "a.txt").write_text("inside")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a.txt").write_text("SECRET")
    return root, outside


def test_reads_and_writes_inside_the_root(tree):
    root, _ = tree
    with open_within_roots(str(root / "docs" / "a.txt"), [str(root)]) as f:
        assert f.read() == "inside"
    with open_within_roots(str(root / "docs" / "new.txt"), [str(root)], "w") as f:
        f.write("x")
    with open_within_roots(str(root / "docs" / "new.txt"), [str(root)], "rb") as f:
        assert f.read() == b"x"


def test_refuses_a_path_outside_the_roots(tree):
    root, outside = tree
    with pytest.raises(PermissionError):
        open_within_roots(str(outside / "a.txt"), [str(root)])
    with pytest.raises(PermissionError):
        open_within_roots(str(root / ".." / "outside" / "a.txt"), [str(root)])


@posix_only
def test_a_directory_swapped_for_a_symlink_after_the_check_is_not_followed(tree):
    root, outside = tree
    path = str(root / "docs" / "a.txt")
    ok, resolved = path_within_roots(path, [str(root)])  # the guard's check passes...
    assert ok
    # ...then the attacker swaps the directory for a symlink before the tool opens the file.
    os.rename(root / "docs", root / "docs.old")
    os.symlink(outside, root / "docs")
    with open(resolved) as f:  # a plain open() follows it: the race this helper closes
        assert f.read() == "SECRET"
    with pytest.raises(OSError):
        open_within_roots(resolved, [str(root)])


@posix_only
def test_a_file_swapped_for_a_symlink_is_not_followed_or_truncated(tree):
    root, outside = tree
    target = root / "docs" / "a.txt"
    target.unlink()
    os.symlink(outside / "a.txt", target)
    # path_within_roots now resolves outside, so this is refused up front...
    with pytest.raises(PermissionError):
        open_within_roots(str(target), [str(root)], "w")
    assert (outside / "a.txt").read_text() == "SECRET"


@posix_only
def test_a_fifo_is_refused_without_blocking(tree):
    root, _ = tree
    fifo = root / "docs" / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(OSError, match="regular file"):
        open_within_roots(str(fifo), [str(root)])


@pytest.mark.parametrize("mode", ["rw", "r++", "q"])
def test_refuses_an_unknown_mode(tree, mode):
    root, _ = tree
    with pytest.raises(ValueError):
        open_within_roots(str(root / "docs" / "a.txt"), [str(root)], mode)


@posix_only
def test_the_last_component_swapped_after_the_check_is_not_followed(tree):
    root, outside = tree
    target = root / "docs" / "a.txt"
    _, resolved = path_within_roots(str(target), [str(root)])
    target.unlink()
    os.symlink(outside / "a.txt", target)
    with pytest.raises(OSError):
        open_within_roots(resolved, [str(root)], "w")  # would truncate the outside file
    assert (outside / "a.txt").read_text() == "SECRET"


@posix_only
@pytest.mark.parametrize("swap", ["directory", "file"])
@pytest.mark.parametrize("nofollow", [True, False])
def test_a_swap_inside_the_helper_between_its_check_and_its_open_fails(
    tree, monkeypatch, swap, nofollow
):
    """The swap lands after the helper's own check: the no-follow walk must still refuse it."""
    import agentsec.sandbox.validators as v

    root, outside = tree
    real_check = v.path_within_roots

    def check_then_swap(path, roots):
        result = real_check(path, roots)
        if swap == "directory":
            os.rename(root / "docs", root / "docs.old")
            os.symlink(outside, root / "docs")
        else:
            (root / "docs" / "a.txt").unlink()
            os.symlink(outside / "a.txt", root / "docs" / "a.txt")
        return result

    monkeypatch.setattr(v, "path_within_roots", check_then_swap)
    if not nofollow:  # the fallback used where openat/O_NOFOLLOW are missing (Windows)
        monkeypatch.setattr(v, "_NOFOLLOW", 0)
    with pytest.raises(OSError) as e:
        open_within_roots(str(root / "docs" / "a.txt"), [str(root)], "w")
    assert not isinstance(e.value, PermissionError)  # refused by the open, not the check
    assert (outside / "a.txt").read_text() == "SECRET"
