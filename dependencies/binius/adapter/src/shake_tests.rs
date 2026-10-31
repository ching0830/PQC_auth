//! Public golden vectors generated independently with Python hashlib SHAKE256.
//! Message byte i is (17*i+3) mod 256. Each stored output is 291 bytes;
//! the 72-byte KAT takes its prefix. These controls replay circuit constraints,
//! not a SNARK proof, and use no real CAP state, secret input or secret output.
use super::*;

const KATS: &[(usize, &str)] = &[
    (0, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d677231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5caaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53fb8e9eb2ea203bdc970f50ae55428a91f7f53ac266b28419c3778a15fd248d339ede785fb7f5a1aaa96d313eacc890936c173cdcd0fab882c45755feb3aed96d477ff96390bf9a66d"),
    (1, "db4252337900d8ab7f609d170135d459a6798945d5a574d4a9db7b623c754d078fb2239762994969a1f372801817bb304f5b549a6bb5cb7c69950c5f439caf192455668cbfe3f6cce5a3c45d15411243dd4174f8e697af999a0b40d0c0b91828c53d08f286986544b961c7b9c86d789936b6e8a4a3a981cbf8e83442a9392f5b6fc61c9a1c3247a3c8dda02514cd9471c6d1bdad7fe09eaaddc474190995d5f57b38b52fc5d31488c6cf13afa621d5010005b69d94406a54b4bf8fe57a73a882c7591b1ddec112b70d134801793ff7a6090da48f20414140e12a31fe7577f9398b63d50e345b0f6626f1393ce86da095e4976c02dd70200f669e799475a99fab59f93988648dcafd7a8494f3c07a9d26a81df06ca33f687f8109f17c51bf1f72317e5e"),
    (135, "872c7d7192a9d1a5d23b15f25b7f5530684bb1bac638e286681b3c3953a3b97faf76182bd131dfdae1a78c6d47e4b9c9e4be1b4a48e8188c3dcdacfe1431179939b9608e0967ecd0aaabe996b5231299395e58692665bc3f1604fadda2db90dda1b443d9e3025544f8d58c2bf4a918b7933ed2c54c7a0958db0be1648adbab0cac3251c731d2aa542786e983fc5450e1daad71977a2b94c014685d6ad7eeb00797dc872d52d290755e1781bde5322f6962686a5a49804d4b7bb0effb9213b5d6c25ee6735aacb1ad5ff8d074cb0ea84d38d7657a58f633c5c98d49fba23c50b17a2e1b5cc902f7b4cd99471f4d6952fe143bb513af3ef81942945db90278831b4f048da8c254380d19d6262bb33952b7f56e3935e8f6ba63fe4cdb1818bc9d8b026730"),
    (136, "ed4a017052e2d4063658818d54f2a1b8c17afe879363f50437b0592e7319fd8eede65e9de766f3bd0e51adaa2855009fc1b0e7230633290a138a66a8bf791605e6762b34424f9a5b1f05abeb6ab8dac26fa782da6a3f1e6fea6c6ad32ba901f9c8fed822b4fdf53264646559397f45c227366cb834849a51e829d3c180b9485e1174f4b9d31877a1857292a992ef112ec9a939743d8c61e5fbb06584d3953497757d1f3c8ae7996b40dfe74374648c969451822db7b891c96b9044af00f9b5fcdd9b338c0592dbaeef85a9c470242bebd7fd179ff11f1a3af52e432523b39b18607697ceca31c0d66f10da9476d228bb609545a8250cbab4fbfbe53a12f3a9b863243ed4cc8f77129158dd3aed6dbe1e8dec38109e7b7cc51439ccbc63b02a5bf6a847"),
    (137, "afd9177d8c6dda1cebc6411cf5a693c9481401bcad12dd898b3e33128bfafd5d1a7d1cd3f807152b5b18a3db2f38594b0f9b0d4b157e2aeac4d0eda287788c900334fc830f4dbad44b9cf645382f226b32d95f9f1a6b60f9efe0a94ee663d25b451151f3766e5f881c056cfb77ff2c02c2c4240dd960d9fc67040034b6e3ba691704d0c936cc8abe35d86dd282ba077c110de8345fa400e1a30f4ed3c37c3c856e315279fea33fe28671c8f84d178e9f07ac4a565b5053d3d44abe0364cea115f6b5b4db5d4dd3070e19a1202127756c99bf68943f3e684569da9cffa2212780b819cc53afa6d462ab993eafe90482b2aea25dcfd5b83d4d1bf6e4903c1ccae14d59a84f01402acc8c0a3b12553ad94e3e18ba698bbc150109a0c1e3ee7b619b5fd249"),
    (5799, "b5847738d8aec8dc13c161d0c4f80fa06e1f3f547bd9c4b99dea364cb55510d7d5a88cebea17d83815a472c6cefe42cc55bd516058520700cdefb28e3e070ab86b1132c5e732575cc6433f024d0c42bd4177f25fa164e775ce8d7f989621f3e7dad0ab4c8220d8d9794ee09a3fc75146a44fdb55ebccaa4d7cbee149cd64c82da545ed10a6531952053fb380f6b4cd1d66746f6dfec209ace0428d54f1ca84a68012008a10cf8f906cb5c9e461c8b0937868ef47549ea88dcd88e59079b5750be18a3d078ad2276b6c3f15eccfae8bc14833294d9889572c62e2bbc0472a90c4014d6fa1d69e1ca683bec2f9d4d2b40b4c2c0aa4f3a4588c6c0da11411983ad3add44dbfb464fc5f19c71b6fbf7d108a3651c1c2123aaff67dc1bb0a2549df54d2c279"),
];

fn known_answer(message_bytes: usize) -> Vec<u8> {
    let encoded = KATS.iter().find(|(n, _)| *n == message_bytes).unwrap().1;
    (0..encoded.len()).step_by(2)
        .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap()).collect()
}
#[derive(Clone, Copy)]
enum Mutation {
    None,
    InputTail,
    OutputByte,
    OutputTail,
}

// Fill a canonical assignment first, then mutate only the specified committed
// word. Rejection therefore exercises the emitted constraints, rather than an
// evaluator assertion, an alternative hash function, or a malformed proof.
fn run_case(message_bytes: usize, output_bytes: usize, mutation: Mutation) -> bool {
    let message: Vec<u8> = (0..message_bytes).map(|i| (17 * i + 3) as u8).collect();
    let expected = known_answer(message_bytes);
    let builder = CircuitBuilder::new();
    let inputs: Vec<_> = (0..message_bytes.div_ceil(8))
        .map(|_| builder.add_witness()).collect();
    let computed = shake256_fixed(&builder, &inputs, message_bytes, output_bytes);
    let outputs: Vec<_> = (0..output_bytes.div_ceil(8))
        .map(|_| builder.add_inout()).collect();
    assert_eq!(computed.len(), outputs.len());
    for (&actual, &expected) in computed.iter().zip(&outputs) {
        builder.assert_eq("public_SHAKE_known_answer", actual, expected);
    }
    let circuit = builder.build();
    let mut witness = circuit.new_witness_filler();
    for (&wire, chunk) in inputs.iter().zip(message.chunks(8)) {
        let mut bytes = [0u8; 8];
        bytes[..chunk.len()].copy_from_slice(chunk);
        witness[wire] = Word(u64::from_le_bytes(bytes));
    }
    for (&wire, chunk) in outputs.iter().zip(expected[..output_bytes].chunks(8)) {
        let mut bytes = [0u8; 8];
        bytes[..chunk.len()].copy_from_slice(chunk);
        witness[wire] = Word(u64::from_le_bytes(bytes));
    }
    assert!(circuit.populate_wire_witness(&mut witness).is_ok(), "public KAT evaluator");
    match mutation {
        Mutation::None => {}
        Mutation::InputTail => {
            assert_ne!(message_bytes % 8, 0);
            let wire = *inputs.last().unwrap();
            let previous = witness[wire].0;
            witness[wire] = Word(previous | (1u64 << ((message_bytes % 8) * 8)));
        }
        Mutation::OutputByte => {
            let wire = outputs[0];
            let previous = witness[wire].0;
            witness[wire] = Word(previous ^ 1);
        }
        Mutation::OutputTail => {
            assert_ne!(output_bytes % 8, 0);
            let wire = *outputs.last().unwrap();
            let previous = witness[wire].0;
            witness[wire] = Word(previous | (1u64 << ((output_bytes % 8) * 8)));
        }
    }
    circuit.constraint_system().verify(&witness.into_value_vec()).is_ok()
}

#[test]
fn shake72_known_answers_and_byte_boundaries() {
    for &(message_bytes, _) in KATS {
        assert!(run_case(message_bytes, 72, Mutation::None),
                "public 72-byte KAT at message length {message_bytes}");
    }
}

#[test]
fn shake291_known_answers_multiple_squeeze_and_output_tail() {
    for &(message_bytes, _) in KATS {
        assert!(run_case(message_bytes, 291, Mutation::None),
                "public 291-byte KAT at message length {message_bytes}");
    }
}

#[test]
fn noncanonical_unused_input_bits_rejected_by_constraints() {
    for message_bytes in [1, 135, 137, 5799] {
        assert!(!run_case(message_bytes, 72, Mutation::InputTail),
                "unused input bytes must be constrained zero");
    }
}

#[test]
fn changed_public_output_and_unused_output_bits_rejected_by_constraints() {
    assert!(!run_case(137, 72, Mutation::OutputByte), "changed public digest");
    assert!(!run_case(137, 291, Mutation::OutputTail), "noncanonical output tail");
}

#[test]
fn public_shapes_and_permutation_counts() {
    for (message_bytes, absorbs) in [(0, 1), (1, 1), (135, 1), (136, 2), (137, 2), (5799, 43)] {
        assert_eq!(permutation_count(message_bytes, 72), absorbs);
        assert_eq!(permutation_count(message_bytes, 291), absorbs + 2);
    }
    for (message_bytes, output_bytes) in [
        (MAX_MESSAGE_BYTES + 1, 72), (usize::MAX, 72),
        (0, 0), (0, MAX_OUTPUT_BYTES + 1), (0, usize::MAX),
    ] {
        assert!(std::panic::catch_unwind(|| permutation_count(message_bytes, output_bytes)).is_err());
    }
    // Exact wire count, including the empty message, is checked before allocation.
    for (message_bytes, wire_count) in [(9, 1), (0, 1), (1, 2)] {
        assert!(std::panic::catch_unwind(|| {
            let builder = CircuitBuilder::new();
            let inputs: Vec<_> = (0..wire_count).map(|_| builder.add_witness()).collect();
            shake256_fixed(&builder, &inputs, message_bytes, 72);
        }).is_err());
    }
}
