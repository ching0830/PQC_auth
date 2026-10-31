"""Explicit research build; every binary remains in the fixed /tmp root."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
BUILD = Path('/tmp/pqsat_cap_native_opening_build_v0_1')
FLAGS = ['-O3', '-std=c17', '-fPIC', '-shared', '-fopenmp', '-Wall', '-Wextra', '-Werror', '-march=x86-64']


def build(profile='portable'):
    if profile not in ('portable', 'asan', 'ubsan'):
        raise ValueError('unknown profile')
    BUILD.mkdir(exist_ok=True)
    flags = FLAGS.copy()
    if profile != 'portable':
        flags += ['-g', '-fno-omit-frame-pointer', '-fno-sanitize-recover=all',
                  '-fsanitize=' + ('address,undefined' if profile == 'asan' else 'undefined')]
    library = BUILD / ('libopening_' + profile + '.so')
    command = ['/usr/bin/gcc', *flags, str(ROOT / 'native/blind_uov_cap_opening_v0_1/opening.c'), '-lcrypto', '-o', str(library)]
    subprocess.run(command, check=True, cwd=BUILD)
    raw = library.read_bytes()
    record = dict(profile=profile, command=command, flags=flags, library_path=str(library),
                  library_bytes=len(raw), library_sha256=hashlib.sha256(raw).hexdigest(),
                  compiler=subprocess.check_output(['/usr/bin/gcc', '--version'], text=True),
                  dependencies=subprocess.check_output(['ldd', str(library)], text=True))
    (BUILD / ('build_' + profile + '.json')).write_text(json.dumps(record, indent=2)+'\n')
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('profile', choices=('portable', 'asan', 'ubsan'), default='portable', nargs='?')
    print(json.dumps(build(parser.parse_args().profile), indent=2))
