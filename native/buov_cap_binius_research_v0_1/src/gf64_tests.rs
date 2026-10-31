//! PUBLIC scalar/circuit controls only. No CAP state, RNG or proof generation.
use super::*;
use binius_frontend::Circuit;

// Frozen vectors from independent polynomial carry-less product/long division.
// Include cases that distinguish GF64 reduction from integer/low-word products.
const KATS: &[(u64, u64, u64)] = &[
    (0, u64::MAX, 0),
    (1, u64::MAX, u64::MAX),
    (0x8000_0000_0000_0000, 2, 0x1b),
    (0x8000_0000_0000_0000, 3, 0x8000_0000_0000_001b),
    (0x8000_0000_0000_0000, 0x8000_0000_0000_0000, 0xc000_0000_0000_005a),
    (u64::MAX, u64::MAX, 0x5555_5555_5555_5513),
    (0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210, 0x4882_7ab5_5d97_6fa0),
    (0xdead_beef_cafe_babe, 0x1020_3040_5060_7080, 0xaf54_c536_34a7_c4d8),
];

fn mix(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[derive(Clone, Copy)]
enum Mutation {
    None,
    OutputLowBit,
    OutputHighBit,
    FirstInput,
}

struct VariableCircuit {
    circuit: Circuit,
    a: Wire,
    b: Wire,
    output: Wire,
}

impl VariableCircuit {
    fn new() -> Self {
        let builder = CircuitBuilder::new();
        let a = builder.add_witness();
        let b = builder.add_witness();
        let output = builder.add_inout();
        let computed = mul(&builder, a, b);
        builder.assert_eq("GF64_full_word_product", computed, output);
        Self { circuit: builder.build(), a, b, output }
    }

    fn check(&self, a: u64, b: u64, expected: u64, mutation: Mutation) -> bool {
        let mut filler = self.circuit.new_witness_filler();
        filler[self.a] = Word(a);
        filler[self.b] = Word(b);
        filler[self.output] = Word(expected);
        assert!(self.circuit.populate_wire_witness(&mut filler).is_ok(), "public GF64 evaluator");
        // Mutate only AFTER deriving internal wires, then check actual emitted
        // constraints. A failed evaluator assertion is not counted as rejection.
        match mutation {
            Mutation::None => {}
            Mutation::OutputLowBit => filler[self.output] = Word(expected ^ 1),
            Mutation::OutputHighBit => filler[self.output] = Word(expected ^ (1u64 << 63)),
            Mutation::FirstInput => filler[self.a] = Word(a ^ 1),
        }
        self.circuit.constraint_system().verify(&filler.into_value_vec()).is_ok()
    }
}

#[test]
fn scalar_reference_and_variable_circuit_known_answers() {
    let fixture = VariableCircuit::new();
    for &(a, b, expected) in KATS {
        assert_eq!(reference_mul(a, b), expected, "public GF64 KAT");
        assert_eq!(reference_mul(b, a), expected, "commuted public GF64 KAT");
        assert!(fixture.check(a, b, expected, Mutation::None));
    }
}

#[test]
fn all_basis_products_and_public_high_bit_patterns() {
    let fixture = VariableCircuit::new();
    // Every basis pair exercises every position of the full 127-bit product.
    for i in 0..64 {
        for j in 0..64 {
            let (a, b) = (1u64 << i, 1u64 << j);
            assert!(fixture.check(a, b, reference_mul(a, b), Mutation::None));
        }
    }
    for i in 0..256 {
        let (a, b) = (mix(i), mix(i ^ 0x6a09_e667_f3bc_c909));
        assert!(fixture.check(a, b, reference_mul(a, b), Mutation::None));
        assert!(fixture.check(b, a, reference_mul(a, b), Mutation::None));
    }
}

#[test]
fn constant_specialization_matches_variable_field_product() {
    for constant in [0, 1, 2, MODULUS_LOW, 1u64 << 32, 1u64 << 63, u64::MAX] {
        let builder = CircuitBuilder::new();
        let input = builder.add_witness();
        let output = builder.add_inout();
        builder.assert_eq("GF64_public_coefficient", mul_const(&builder, input, constant), output);
        let circuit = builder.build();
        for value in (0..64).map(|i| 1u64 << i).chain((0..128).map(mix)) {
            let mut filler = circuit.new_witness_filler();
            filler[input] = Word(value);
            filler[output] = Word(reference_mul(value, constant));
            assert!(circuit.populate_wire_witness(&mut filler).is_ok(), "public GF64 constant evaluator");
            assert!(circuit.constraint_system().verify(&filler.into_value_vec()).is_ok());
        }
    }
}

#[test]
fn same_wire_square_and_high_bit_reduction() {
    let builder = CircuitBuilder::new();
    let input = builder.add_witness();
    let output = builder.add_inout();
    builder.assert_eq("GF64_square_same_wire", mul(&builder, input, input), output);
    let circuit = builder.build();
    for value in (0..64).map(|i| 1u64 << i).chain((0..128).map(mix)) {
        let mut filler = circuit.new_witness_filler();
        filler[input] = Word(value);
        filler[output] = Word(reference_mul(value, value));
        assert!(circuit.populate_wire_witness(&mut filler).is_ok(), "public GF64 square evaluator");
        assert!(circuit.constraint_system().verify(&filler.into_value_vec()).is_ok());
    }
}

#[test]
fn altered_committed_values_rejected_by_constraints() {
    let fixture = VariableCircuit::new();
    for &(a, b, expected) in &KATS[2..] {
        for mutation in [Mutation::OutputLowBit, Mutation::OutputHighBit, Mutation::FirstInput] {
            assert!(!fixture.check(a, b, expected, mutation), "changed committed GF64 word must reject");
        }
    }
}

#[test]
fn auditable_word_constraint_cost_without_integer_or_ghash_mul() {
    let fixture = VariableCircuit::new();
    let cs = fixture.circuit.constraint_system();
    assert!(cs.imul_constraints.is_empty(), "no integer multiplication");
    assert!(cs.bmul_constraints.is_empty(), "no GHASH/BMUL embedding");
    // Source operation bound is 380 BAND/shift operations before fusion. A
    // conservative cap also leaves room for frontend bookkeeping constraints.
    assert!(cs.and_constraints.len() <= 512, "bounded scalar GF64 gadget");
    assert_eq!(cs.n_inout, 1);
}
