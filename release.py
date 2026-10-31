#!/usr/bin/env python3
"""Single entrypoint for the pinned thesis-code snapshot."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('test', help='bounded source/codec/I/O tests; no full proof')
    commands.add_parser('compare', help='recompute the separate public result cohorts')
    doctor = commands.add_parser('doctor', help='verify all external input sizes and SHA-256')
    doctor.add_argument('--config', type=Path, required=True)
    run = commands.add_parser('run', help='real Hchi+ issuance to independent VerifyTicket')
    run.add_argument('--config', type=Path, required=True)
    run.add_argument('--label', required=True)
    args = parser.parse_args()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=os.pathsep.join((str(ROOT/'src'), str(ROOT))))
    if args.command == 'test':
        return subprocess.call([sys.executable, '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-v'], cwd=ROOT, env=env)
    if args.command == 'compare':
        return subprocess.call([sys.executable, '-B', '-m', 'publication.compare'], cwd=ROOT, env=env)
    from publication.runtime import configuration, verify_artifacts
    cfg = configuration(args.config)
    result = verify_artifacts(cfg['artifacts'])
    print(json.dumps(result, sort_keys=True), flush=True)
    if not result['ready']:
        return 2
    if args.command == 'doctor':
        return 0
    if not args.label.replace('-', '').isalnum():
        parser.error('fresh alphanumeric/hyphen label required')
    env.update(PQSAT_PUBLICATION_CONFIG=str(args.config.resolve()),
               PYTHONPATH=os.pathsep.join((str(ROOT/'publication/bootstrap'), str(ROOT/'src'), str(ROOT))))
    return subprocess.call([sys.executable, '-B', '-m', 'benchmarks.buov_cap_hplus_research_v0_1.run',
                            '--label', args.label, '--wait-seconds', '120'], cwd=ROOT, env=env)


if __name__ == '__main__':
    raise SystemExit(main())
