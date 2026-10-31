//! Same Keccak-f permutation, with private theta-D words materialized.
//!
//! Pinning D cuts repeated affine support expansion. It does not promote a
//! state word to a public input, change the sponge, or use the non-ZK M4 API.
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire};
use binius_circuits::keccak::permutation::{R, RC};

pub fn permute(b: &CircuitBuilder, state: &mut [Wire;25]) {
    for rc in RC {
        let c: [Wire;5] = std::array::from_fn(|x| b.bxor_multi(
            &std::array::from_fn::<_,5,_>(|y| state[x+5*y])));
        let d: [Wire;5] = std::array::from_fn(|x| {
            let word = b.bxor(c[(x+4)%5], b.rotl(c[(x+1)%5],1));
            b.force_commit(word);
            word
        });
        for y in 0..5 { for x in 0..5 {
            state[x+5*y] = b.bxor(state[x+5*y],d[x]);
        }}
        let mut rotated = *state;
        for y in 0..5 { for x in 0..5 {
            rotated[y+5*((2*x+3*y)%5)] = b.rotl(state[x+5*y],R[x+5*y]);
        }}
        for y in 0..5 { for x in 0..5 {
            let a = if x==0 && y==0 {b.bxor(rotated[0],b.add_constant(Word(rc)))}
                    else {rotated[x+5*y]};
            state[x+5*y] = b.fax(b.bnot(rotated[(x+1)%5+5*y]),rotated[(x+2)%5+5*y],a);
        }}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_permutation_and_private_pinning() {
        let b=CircuitBuilder::new();
        let inputs: [Wire;25]=std::array::from_fn(|_|b.add_witness());
        let outputs: [Wire;25]=std::array::from_fn(|_|b.add_inout());
        let mut reference=inputs;
        binius_circuits::keccak::keccak_f1600(&b,&mut reference);
        let mut compact=inputs;
        permute(&b,&mut compact);
        for i in 0..25 {
            b.assert_eq("equivalent_keccak",compact[i],reference[i]);
            b.assert_eq("expected_keccak",compact[i],outputs[i]);
        }
        let circuit=b.build();
        assert_eq!(circuit.constraint_system().n_inout,25);
        let mut values=[0u64;25];
        // Frozen all-zero Keccak-f1600 answer, independent public control.
        values.copy_from_slice(&[
            0xf1258f7940e1dde7,0x84d5ccf933c0478a,0xd598261ea65aa9ee,0xbd1547306f80494d,0x8b284e056253d057,
            0xff97a42d7f8e6fd4,0x90fee5a0a44647c4,0x8c5bda0cd6192e76,0xad30a6f71b19059c,0x30935ab7d08ffc64,
            0xeb5aa93f2317d635,0xa9a6e6260d712103,0x81a57c16dbcf555f,0x43b831cd0347c826,0x01f22f1a11a5569f,
            0x05e5635a21d9ae61,0x64befef28cc970f2,0x613670957bc46611,0xb87c5a554fd00ecb,0x8c3ee88a1ccf32c8,
            0x940c7922ae3a2614,0x1841f924a2c509e4,0x16f53526e70465c2,0x75f644e97f30a13b,0xeaf1ff7b5ceca249]);
        let mut witness=circuit.new_witness_filler();
        for i in 0..25 {witness[inputs[i]]=Word(0);witness[outputs[i]]=Word(values[i]);}
        circuit.populate_wire_witness(&mut witness).unwrap();
        let mut witness=witness.into_value_vec();
        circuit.constraint_system().verify(&witness).unwrap();
        witness[circuit.witness_index(outputs[17])]=Word(values[17]^1);
        assert!(circuit.constraint_system().verify(&witness).is_err());
    }
}
