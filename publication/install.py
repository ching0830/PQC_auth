"""Provision verified external inputs once, outside all source worktrees."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

from .runtime import ROOT, verify_artifacts


def source_paths(args):
    catalog = json.loads((ROOT/'provenance/external_artifacts.json').read_text())
    result = {}
    for name, pin in catalog['artifacts'].items():
        if name.startswith('toolchain/'):
            source = args.toolchain/name[len('toolchain/'):]
        elif name.startswith('deps/'):
            source = args.deps/name[len('deps/'):]
        elif name.startswith('setup-build/'):
            source = args.setup_build/name[len('setup-build/'):]
        elif name == 'trace.T':
            source = args.public_t
        else:
            source = args.cache
        if not source.is_file() or source.stat().st_size != pin['bytes']:
            raise ValueError('external source size/type: '+name)
        with source.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if digest != pin['sha256']:
            raise ValueError('external source SHA-256: '+name)
        result[name] = source
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('toolchain', 'deps', 'public-t', 'setup-build', 'cache'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--destination', type=Path)
    args = parser.parse_args()
    sources = source_paths(args)
    if args.check_only:
        print(json.dumps(dict(verified=len(sources), copied=0)))
    else:
        if args.destination is None:
            parser.error('--destination or --check-only required')
        destination = args.destination
        if not destination.is_absolute() or destination != destination.resolve() or destination.is_relative_to(ROOT):
            parser.error('canonical absolute external destination required')
        destination.mkdir(mode=0o700)
        for name, source in sources.items():
            target = destination/name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(0o555 if name in ('toolchain/bin/rustc', 'setup-build/hplus_setup') else 0o444)
        checked = verify_artifacts(destination)
        if not checked['ready']:
            raise ValueError('installed artifact verification failed')
        print(json.dumps(dict(verified=len(sources), copied=len(sources), ready=True)))
