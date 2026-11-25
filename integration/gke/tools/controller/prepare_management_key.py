"""Give the launch service custody of its provisioned management TLS key."""

import argparse
import os
from pathlib import Path
import stat


def prepare(path):
    if not path.is_absolute() or path.parent.resolve(strict=True) != path.parent:
        raise ValueError("absolute management key path required")
    uid, gid = os.geteuid(), os.getegid()
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= (64 << 10)
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError("management key must be an owner-only regular file")
        if (info.st_uid, info.st_gid) != (uid, gid):
            os.fchown(fd, uid, gid)
        info = os.fstat(fd)
        if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (uid, gid, 0o600):
            raise ValueError("management key ownership does not match the launch service")
    finally:
        os.close(fd)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("key", type=Path)
    args = parser.parse_args()
    try:
        prepare(args.key)
    except (OSError, ValueError):
        parser.exit(1, "management key preparation rejected\n")
