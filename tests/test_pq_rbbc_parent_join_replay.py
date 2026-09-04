import hashlib
import unittest
from types import SimpleNamespace

import pq_rbbc_cap_commit as cap
import pq_rbbc_parent_join_replay as join
import pq_rbbc_reference as reference


def fake_production_execution():
    commitment = SimpleNamespace(
        parameters_fingerprint=cap.profile_fingerprint(cap.PRODUCTION_PARAMETERS),
        derived_mask=int.from_bytes(hashlib.shake_256(b"v2.29-mask").digest(72), "little"),
        encoded=hashlib.shake_256(b"v2.29-commitment").digest(
            cap.commitment_bytes(cap.PRODUCTION_PARAMETERS)
        ),
    )
    return SimpleNamespace(commitment=commitment)


class ParentJoinReplayTests(unittest.TestCase):
    def test_parent_bound_fixture_preserves_ticket_lifecycle(self) -> None:
        _, base_statement, base_witness, _ = reference.reference_fixture()
        fixture = join.build_parent_bound_fixture(fake_production_execution())
        self.assertEqual(fixture.statement.common_ctx, base_statement.common_ctx)
        self.assertEqual(fixture.statement.rid, base_statement.rid)
        self.assertEqual(fixture.statement.payload, base_statement.payload)
        self.assertEqual(fixture.witness.sn, base_witness.sn)
        self.assertEqual(fixture.witness.holder_key, base_witness.holder_key)
        self.assertEqual(fixture.witness.error, base_witness.error)
        self.assertEqual(
            fixture.message,
            hashlib.shake_256(
                reference.LABEL_TICKET + base_statement.payload.encode()
            ).digest(32),
        )
        self.assertTrue(
            reference.verify_relation(
                fixture.matrix,
                fixture.statement,
                fixture.witness,
                fixture.adapter,
            ).ok
        )

    def test_parent_binding_uses_production_values(self) -> None:
        execution = fake_production_execution()
        fixture = join.build_parent_bound_fixture(execution)
        self.assertEqual(fixture.commitment, execution.commitment.encoded)
        self.assertEqual(
            fixture.mask,
            execution.commitment.derived_mask.to_bytes(72, "little"),
        )
        self.assertEqual(
            fixture.statement.blind_request.masked_target,
            bytes(a ^ b for a, b in zip(fixture.mask, fixture.hash_image)),
        )
        changed = bytes((fixture.message[0] ^ 1,)) + fixture.message[1:]
        self.assertFalse(
            fixture.adapter.verify_cap_hash(
                changed,
                fixture.mask,
                fixture.witness.blind_randomness,
                fixture.hash_image,
            )
        )

    def test_source_ports_are_exact_and_disjoint(self) -> None:
        fixture = join.build_parent_bound_fixture(fake_production_execution())
        ports = {port.port_id: port for port in join.source_ports(fixture)}
        self.assertEqual(ports["shared.message"].wire_start, 387)
        self.assertEqual(ports["shared.message"].bit_length, 256)
        self.assertEqual(
            ports["global.phase-b.commitment"].bit_length, 43_128
        )
        self.assertEqual(
            ports["global.phase-b.derived-mask"].wire_start, 40_127_634
        )
        self.assertEqual(
            ports["global.phase-b.request-hash"].wire_start, 40_194_018
        )
        values = join.source_assignment(tuple(ports.values()))
        self.assertEqual(len(values), 44_536)

    def test_join_accounting_and_namespace_are_frozen(self) -> None:
        self.assertEqual(join.JOIN_ROWS, 1_408)
        self.assertEqual(join.PARENT_JOIN_ROWS, 2_972_988)
        self.assertEqual(join.COMBINED_ROWS, 589_030_555)
        self.assertEqual(join.PARENT_WIRE_START, 429_757_233)
        self.assertEqual(join.PARENT_WIRE_END, 432_737_534)
        self.assertEqual(
            join.PARENT_WIRE_END - join.PARENT_WIRE_START + 1,
            join.PARENT_NONCONSTANT_WIRES,
        )
        self.assertGreater(join.PARENT_WIRE_START, join.AGGREGATE_MAX_WIRE_ID)

    def test_characteristic_two_constant_folding(self) -> None:
        mapped, constant = join._normalize_linear((0, 1, 2, 1, 3), 1)
        self.assertEqual(
            mapped,
            (join.PARENT_WIRE_START, join.PARENT_WIRE_START + 1),
        )
        self.assertEqual(constant, 1)
        self.assertEqual(join._map_multiplicand(0), 0)
        self.assertEqual(join._map_multiplicand(1), 1)


if __name__ == "__main__":
    unittest.main()
