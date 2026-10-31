"""Research-only ticket consumer: own configuration, M/CR -> Scope/u -> native V.

The operator supplies a separately sealed public configuration FD and its exact
size/SHA. The untrusted stdin frame has only M/CR/CZ/pi2. No caller u, cPK,
Scope, session records, verdict, witness, issuer key or CAP state is accepted.
Configuration identity is not authenticated provisioning or an origin proof.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import sys
import time

from publication.shared import check_limits
from .native_build import provision, verifier_kwargs
from pq_rbbc.blind_uov_hplus_research_v0_1.native_verifier import NativeCAPVerifier
from pq_rbbc.blind_uov_hplus_research_v0_1.uov import UOVPublicMap, CPK_BYTES
from pq_sat_auth.prototypes.buov_cap_hplus_research_v0_1.ticket_consumer import (
    ResearchPublicConfig, prepare_ticket,
)

CONFIG_SCHEMA = 'BUOVCAPHPlusResearchTicketOwnConfigV1'
RESULT_SCHEMA = 'BUOVCAPHPlusResearchTicketVerificationV1'
MAX_CONFIG_BYTES = 512 << 10
MAX_TICKET_BYTES = 32 << 10


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def configuration_bytes(config):
    if type(config) is not ResearchPublicConfig:
        raise ValueError('exact own public configuration')
    raw = canonical(dict(schema=CONFIG_SCHEMA, cpk=config.public_map.canonical_cpk.hex(),
                         scope_records={k: v.hex() for k, v in config.records().items()}))
    if not 0 < len(raw) <= MAX_CONFIG_BYTES:
        raise ValueError('bounded own configuration')
    return raw


def decode_configuration(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_CONFIG_BYTES:
        raise ValueError('bounded own configuration bytes')
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError('duplicate own configuration field')
            out[key] = value
        return out
    value = json.loads(raw, object_pairs_hook=unique)
    if (type(value) is not dict or set(value) != {'schema', 'cpk', 'scope_records'}
            or value['schema'] != CONFIG_SCHEMA or canonical(value) != raw
            or type(value['scope_records']) is not dict):
        raise ValueError('canonical own configuration schema')
    def hex_bytes(value, size=None):
        if type(value) is not str or len(value) > 2 * CPK_BYTES:
            raise ValueError('bounded canonical hex')
        raw = bytes.fromhex(value)
        if raw.hex() != value or (size is not None and len(raw) != size):
            raise ValueError('canonical hex width')
        return raw
    public_map = UOVPublicMap(hex_bytes(value['cpk'], CPK_BYTES))
    records = {k: hex_bytes(v) for k, v in value['scope_records'].items()}
    config = ResearchPublicConfig.from_records(public_map, records)
    if configuration_bytes(config) != raw:
        raise ValueError('configuration exact re-encoding')
    return config


def read_configuration(fd, size, sha256):
    """Use the same bounded immutable bytes after identity validation; no reopen."""
    if (type(fd) is not int or fd < 3 or type(size) is not int or not 0 < size <= MAX_CONFIG_BYTES
            or type(sha256) is not str or len(sha256) != 64
            or any(c not in '0123456789abcdef' for c in sha256)):
        raise ValueError('operator configuration identity')
    info = os.fstat(fd)
    # Linux F_GET_SEALS / WRITE|GROW|SHRINK|SEAL, same UAPI as existing sealed_public.
    required = 0x0008 | 0x0004 | 0x0002 | 0x0001
    if (not stat.S_ISREG(info.st_mode) or info.st_size != size
            or fcntl.fcntl(fd, 1034) & required != required):
        raise ValueError('sealed own configuration FD')
    raw = os.pread(fd, MAX_CONFIG_BYTES + 1, 0)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha256:
        raise ValueError('exact own configuration bytes size and SHA')
    return decode_configuration(raw)


def run(args):
    check_limits(); whole = time.monotonic()
    # stdin is bounded even for a rejected configuration; never print its bytes.
    raw = sys.stdin.buffer.read(MAX_TICKET_BYTES + 1)
    record = dict(schema=RESULT_SCHEMA, accepted=False, stage='configuration_rejected',
        Prove=0, proof_Verify=0, u_reconstructed=False, setup_seconds=None, verify_seconds=None,
        configuration_bytes=args.configuration_bytes, ticket_frame_bytes=len(raw),
        M_bytes=None, CR_bytes=None, CZ_bytes=None, pi2_bytes=None,
        UE_witness_received=False, issuer_key_received=False, CAP_state_received=False,
        final_payload_persisted=False, caller_u_accepted=False, relation_threads=1, opening_threads=1,
        production_entry_changed=False, full_formal_issuance=False)
    try:
        config = read_configuration(args.configuration_fd, args.configuration_bytes, args.configuration_sha256)
    except (ValueError, TypeError, OSError):
        pass
    else:
        record['stage'] = 'ticket_rejected'
        begin = time.monotonic()
        try:
            prepared = prepare_ticket(config, raw)
        except (ValueError, TypeError):
            pass
        else:
            record.update(u_reconstructed=True, reconstruction_and_codec_seconds=time.monotonic() - begin,
                M_bytes=len(prepared.M), CR_bytes=len(prepared.cr), CZ_bytes=len(prepared.cz),
                pi2_bytes=len(prepared.pi2))
            # A native provisioning/setup/internal error is fatal, not a negative proof verdict.
            libraries = provision(args.exploration); begin = time.monotonic()
            with NativeCAPVerifier.load(**verifier_kwargs(libraries)) as factory:
                with factory.bind(prepared.statement, relation_threads=1, opening_threads=1) as verifier:
                    record['setup_seconds'] = time.monotonic() - begin
                    begin = time.monotonic(); record['proof_Verify'] = 1
                    accepted = verifier.verify(prepared.cr, prepared.cz, prepared.pi2)
                    record['verify_seconds'] = time.monotonic() - begin
            if type(accepted) is not bool:
                raise ValueError('exact actual native CAP verdict')
            record.update(stage='verified', accepted=accepted)
    record.update(whole_seconds=time.monotonic() - whole,
        memory_HWM_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024)
    sys.stdout.write(json.dumps(record, sort_keys=True, allow_nan=False) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exploration', type=Path, required=True)
    parser.add_argument('--configuration-fd', type=int, required=True)
    parser.add_argument('--configuration-bytes', type=int, required=True)
    parser.add_argument('--configuration-sha256', required=True)
    try:
        run(parser.parse_args())
    except Exception:
        print('RESEARCH_TICKET_CONSUMER_FAILURE', file=sys.stderr); sys.exit(2)
