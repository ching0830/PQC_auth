"""UE-side research adapter for a separate own-configuration ticket consumer.

Only the four-field public presentation travels in the private RAM stdin pipe.
The configuration FD is supplied by the trusted experiment harness, not by that
frame. It contains no issuance-session/RID fields. No presentation or its hash
is persisted. Controls are outside the single successful-flow stopwatch.
"""
from dataclasses import replace
import hashlib
import json
import os
import subprocess
import sys
import time

from .cap_adapter import FinalCAPKernel
from publication.shared import sealed_public
from .ticket_consumer_verify import configuration_bytes, canonical, RESULT_SCHEMA, MAX_CONFIG_BYTES
from pq_rbbc.blind_uov_hplus_research_v0_1.codec import decode_pi_2, encode_pi_2
from pq_rbbc.blind_uov_hplus_research_v0_1.uov import UOVPublicMap, CPK_BYTES, issuer_key_id
from pq_sat_auth.prototypes.buov_cap_hplus_research_v0_1.ticket_consumer import (
    ResearchPublicConfig, encode_ticket,
)


def changed(raw, offset=0):
    return raw[:offset] + bytes([raw[offset] ^ 1]) + raw[offset + 1:]


class ResearchTicketCAPKernel(FinalCAPKernel):
    def __init__(self, libraries, exploration, config, message):
        if type(config) is not ResearchPublicConfig or type(message) is not bytes or len(message) != 388:
            raise ValueError('own configuration and exact actual M')
        super().__init__(libraries, exploration)
        self.config, self.message = config, message
        self.configuration = configuration_bytes(config)
        self.configuration_pin = dict(bytes=len(self.configuration), sha256=hashlib.sha256(self.configuration).hexdigest())

    def _invoke(self, raw, *, own_configuration=None, expected_sha=None):
        own = self.configuration if own_configuration is None else own_configuration
        digest = hashlib.sha256(own).hexdigest() if expected_sha is None else expected_sha
        begin = time.monotonic()
        with sealed_public(own, MAX_CONFIG_BYTES) as fd:
            child = subprocess.run([sys.executable, '-B', '-m',
                'benchmarks.buov_cap_hplus_research_v0_1.ticket_consumer_verify',
                '--exploration', str(self.exploration), '--configuration-fd', str(fd),
                '--configuration-bytes', str(len(own)), '--configuration-sha256', digest],
                pass_fds=(fd,), input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=dict(os.environ, OMP_NUM_THREADS='1', OMP_THREAD_LIMIT='1', RAYON_NUM_THREADS='1'),
                timeout=120, preexec_fn=lambda: os.sched_setaffinity(0, {min(os.sched_getaffinity(0))}))
        if child.returncode or child.stderr or len(child.stdout) > 64 << 10:
            raise ValueError('fresh actual ticket-consumer process')
        lines = child.stdout.splitlines()
        if len(lines) != 1:
            raise ValueError('exact ticket consumer telemetry framing')
        record = json.loads(lines[0])
        if (record['schema'] != RESULT_SCHEMA or type(record['accepted']) is not bool
                or type(record['proof_Verify']) is not int or record['proof_Verify'] not in (0, 1)
                or record['Prove'] != 0 or record['relation_threads'] != 1 or record['opening_threads'] != 1
                or record['stage'] not in ('configuration_rejected', 'ticket_rejected', 'verified')
                or any(record[k] is not False for k in ('UE_witness_received', 'issuer_key_received',
                    'CAP_state_received', 'final_payload_persisted', 'caller_u_accepted', 'production_entry_changed'))):
            raise ValueError('actual research ticket-consumer execution metadata')
        called = record['stage'] == 'verified'
        if (record['proof_Verify'] != int(called) or record['u_reconstructed'] is not called
                or (record['accepted'] and not called)
                or (called and not isinstance(record['verify_seconds'], float))
                or (not called and record['verify_seconds'] is not None)):
            raise ValueError('actual Verify vs entry rejection counter')
        record.update(controller_seconds=time.monotonic() - begin,
            public_ticket_input_bytes=len(raw), public_configuration_FD_bytes=len(own),
            public_telemetry_reply_bytes=len(child.stdout))
        return record

    def verify(self, statement, c_r, c_z, pi_2):
        # statement.u is deliberately absent from both the frame and the worker API.
        if statement.ctx != self.config.records()['ctx'] or statement.public_map != self.config.public_map:
            raise ValueError('honest flow own-configuration correspondence')
        raw = encode_ticket(self.message, c_r, c_z, pi_2)
        record = self._invoke(raw)
        if record['accepted'] is not True or record['proof_Verify'] != 1:
            raise ValueError('one actual self-reconstructing ticket verification')
        self.verify_calls += 1; self.verifier_record = record
        return True

    def controls(self, c_r, c_z, pi_2):
        begin = time.monotonic(); M = self.message
        good = encode_ticket(M, c_r, c_z, pi_2)
        parsed = decode_pi_2(pi_2)
        bad_proof = encode_pi_2(replace(parsed, hidden_leaf_commitments=(
            changed(parsed.hidden_leaf_commitments[0]), *parsed.hidden_leaf_commitments[1:])))
        generation = self.config.records()
        generation['configuration_generation'] = ((int.from_bytes(generation['configuration_generation'], 'big') + 1) % (1 << 64)).to_bytes(8, 'big')
        changed_generation = configuration_bytes(ResearchPublicConfig.from_records(self.config.public_map, generation))
        # Canonical foreign-map diagnostic; no KeyGen-image claim, SK or new ticket.
        foreign_map = UOVPublicMap(bytes(CPK_BYTES)); foreign = self.config.records()
        foreign.update(issuer_map_digest=foreign_map.public_map_digest, issuer_key_id=issuer_key_id(foreign_map))
        foreign_configuration = configuration_bytes(ResearchPublicConfig.from_records(foreign_map, foreign))
        wrong_profile = json.loads(self.configuration)
        wrong_profile['scope_records']['cap_profile_fingerprint'] = '00' * 32
        joined = json.loads(self.configuration); joined['scope_records']['RID'] = '00' * 32
        # Every good/mutated presentation remains RAM-only, including negative frames.
        cases = [
            ('good-before', good, None, None, True, 1),
            ('changed-M-SN', encode_ticket(changed(M, 32), c_r, c_z, pi_2), None, None, False, 1),
            ('changed-M-q', encode_ticket(changed(M, 48), c_r, c_z, pi_2), None, None, False, 1),
            ('changed-CR-salt', encode_ticket(M, changed(c_r, 50), c_z, pi_2), None, None, False, 1),
            ('changed-CZ-delta', encode_ticket(M, c_r, changed(c_z, 50), pi_2), None, None, False, 1),
            ('changed-pi2-hidden-commitment', encode_ticket(M, c_r, c_z, bad_proof), None, None, False, 1),
            ('changed-own-configuration-generation', good, changed_generation, None, False, 1),
            ('foreign-own-issuer-map', good, foreign_configuration, None, False, 1),
            ('wrong-M-ctx', encode_ticket(changed(M), c_r, c_z, pi_2), None, None, False, 0),
            ('unknown-ticket-version', changed(good, 9), None, None, False, 0),
            ('trailing-caller-u', good + bytes(72), None, None, False, 0),
            ('wrong-own-CAP-profile', good, canonical(wrong_profile), None, False, 0),
            ('configuration-RID-injection', good, canonical(joined), None, False, 0),
            ('wrong-configuration-SHA', good, None, '00' * 32, False, 0),
            ('good-after', good, None, None, True, 1),
        ]
        rows = []
        for name, frame, own, sha, accepted, calls in cases:
            record = self._invoke(frame, own_configuration=own, expected_sha=sha)
            if record['accepted'] is not accepted or record['proof_Verify'] != calls:
                raise ValueError('ticket-consumer control outcome: ' + name)
            rows.append(dict(name=name, expected_outcome_satisfied=True, verifier=record))
        return dict(schema='BUOVCAPHPlusResearchTicketControlsV1', completed=True, cases=rows,
            actual_proof_Verify=sum(row['verifier']['proof_Verify'] for row in rows),
            entry_rejections=sum(row['verifier']['proof_Verify'] == 0 for row in rows),
            Prove=0, CAP_Init_calls=0, inversion_calls=0, controls_in_successful_flow_window=False,
            final_payload_persisted=False, mutated_payload_persisted=False,
            issuer_private_key_loaded_by_controls=False, whole_seconds=time.monotonic() - begin)
