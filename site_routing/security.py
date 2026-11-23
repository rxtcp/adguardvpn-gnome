"""Root-owned filesystem boundary shared by persistence and installed entry points."""
import os
from pathlib import Path
import stat


def verify_path(path: Path, owner: int = 0, private: bool = False, directory: bool = False) -> None:
    for current in (*reversed(path.parents), path):
        if current == Path('/'):
            continue
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid not in (0, owner) or metadata.st_mode & 0o022:
            raise RuntimeError('Untrusted Site Routing ownership or permissions.')
    metadata = path.lstat()
    if metadata.st_uid != owner or (directory and not stat.S_ISDIR(metadata.st_mode)) or (not directory and not stat.S_ISREG(metadata.st_mode)):
        raise RuntimeError('Invalid Site Routing file type or owner.')
    if private and metadata.st_mode & 0o077:
        raise RuntimeError('Site Routing data must be private.')


def verified_open(path: Path, flags: int, owner: int = 0) -> int:
    descriptor = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    metadata = os.fstat(descriptor)
    if metadata.st_uid != owner or metadata.st_mode & 0o077 or not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise RuntimeError('Untrusted Site Routing data file.')
    return descriptor
