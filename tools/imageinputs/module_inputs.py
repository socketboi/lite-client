"""Collect only Go dependency manifests, preserving local replace paths."""
from pathlib import Path
import shutil
import sys


def collect(source, output):
    if output.exists():
        raise ValueError('Module input directory must be fresh')
    output.mkdir(parents=True)
    for path in sorted(source.rglob('*')):
        if path.suffix not in ('.mod', '.sum'):
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError('Regular module manifest required: ' + str(path))
        destination = output / path.relative_to(source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)


if __name__ == '__main__':
    collect(*map(Path, sys.argv[1:]))
