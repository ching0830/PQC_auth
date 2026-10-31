"""Prepare the complete pinned Cargo source tree; never downloads or compiles."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
COMMIT = '4428e759dd27956bd5b9ae5025d67eb8ccc1accf'


def digest(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('regular source required')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def overlay(fork, package, name):
    record = json.loads((package/(name+'.json')).read_text())
    patch = package/(name+'.patch')
    if record['upstream_commit'] != COMMIT or digest(patch) != record['patch_sha256']:
        raise ValueError('ordered overlay identity')
    for item in record['files']:
        relative = Path(item['path'])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('canonical overlay path')
        path = fork/relative
        if digest(path) != item['base_sha256']:
            raise ValueError('overlay base source')
    subprocess.run(['git', '-C', str(fork), 'apply', '--check', str(patch)], check=True)
    subprocess.run(['git', '-C', str(fork), 'apply', str(patch)], check=True)
    for item in record['files']:
        if digest(fork/item['path']) != item['patched_sha256']:
            raise ValueError('overlay final source')
    return record['patch_sha256']


def stage(upstream, output):
    upstream = upstream.resolve(strict=True)
    if subprocess.check_output(['git', '-C', str(upstream), 'rev-parse', 'HEAD'], text=True).strip() != COMMIT:
        raise ValueError('exact upstream commit required')
    if subprocess.check_output(['git', '-C', str(upstream), 'status', '--porcelain']):
        raise ValueError('clean pinned upstream required')
    output.mkdir(mode=0o700)
    fork = output/'binius64-research'
    subprocess.run(['git', 'clone', '--quiet', '--no-hardlinks', '--no-checkout', str(upstream), str(fork)], check=True)
    subprocess.run(['git', '-C', str(fork), 'checkout', '--quiet', '--detach', COMMIT], check=True)
    path = ROOT/'native/buov_cap_binius_research_v0_1/patches/apply_research_patch.py'
    spec = importlib.util.spec_from_file_location('publication_research_patches', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    base = module.apply(fork, check_only=False, workspace=True, bounded=True, parallel=True)
    extra = []
    for directory, name in (('buov_cap_cs_cache_research_v0_1', 'compact_cache_parts_v0_1'),
                            ('buov_cap_target128_research_v0_1', 'target128_query_v0_1')):
        extra.append(overlay(fork, ROOT/'native'/directory/'patches', name))
    adapter = output/'adapter'
    shutil.copytree(ROOT/'dependencies/binius/adapter', adapter)
    template = adapter/'Cargo.toml.in'
    (adapter/'Cargo.toml').write_text(template.read_text().replace('@BINIUS@', str(fork)))
    record = dict(upstreamCommit=COMMIT, basePatches=base, extraPatchSHA256=extra,
                  CargoLockSHA256=digest(adapter/'Cargo.lock'),
                  compileCommand=['cargo', 'build', '--manifest-path', str(adapter/'Cargo.toml'),
                                  '--release', '--bin', 'pqsat-binius-target128-research', '--locked'],
                  exactCompilerAndRlibRebuildValidated=False, compilationExecuted=False)
    (output/'source-stage.json').write_text(json.dumps(record, indent=2)+'\n')
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(stage(args.upstream, args.output.resolve()), sort_keys=True))
