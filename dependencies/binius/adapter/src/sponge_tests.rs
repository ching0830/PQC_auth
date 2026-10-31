//! Public constraint-replay controls, not proofs and not real CAP secrets.
//! Golden bytes: Python hashlib.shake_256; existing independently implemented
//! trace_mceliece6688128_research_v0_1._cshake256/_kmac256 for nonempty N/S.
//! Empty N/S uses hashlib, since the trace helper only needs nonempty N/S.
//! Message/key/custom test byte i = (17*i+3) mod 256, except the NIST cSHAKE
//! sample X=00010203, S="Email Signature", L=512 bits (sample #3).
//! KMAC sample #4 instead uses K=40..5f, X=00010203, L=512,
//! S="My Tagged Application". Official primary sample PDFs:
//! https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf
//! https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
//! Large full-h1 is checked by public shape arithmetic only, never built here.
use super::*;
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Shake,
    Cshake,
    Kmac,
}
struct Kat {
    name: &'static str,
    kind: Kind,
    key_bytes: usize,
    message_bytes: usize,
    n: &'static str,
    s: &'static str,
    output_bytes: usize,
    counter: bool,
    digest: &'static str,
}
const KATS: &[Kat] = &[
    Kat {
        name: "shake0",
        kind: Kind::Shake,
        key_bytes: 0,
        message_bytes: 0,
        n: "",
        s: "",
        output_bytes: 72,
        counter: false,
        digest: "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb13957",
    },
    Kat {
        name: "shake135",
        kind: Kind::Shake,
        key_bytes: 0,
        message_bytes: 135,
        n: "",
        s: "",
        output_bytes: 291,
        counter: false,
        digest: "872c7d7192a9d1a5d23b15f25b7f5530684bb1bac638e286681b3c3953a3b97faf76182bd131dfdae1a78c6d47e4b9c9e4be1b4a48e8188c3dcdacfe1431179939b9608e0967ecd0aaabe996b5231299395e58692665bc3f1604fadda2db90dda1b443d9e3025544f8d58c2bf4a918b7933ed2c54c7a0958db0be1648adbab0cac3251c731d2aa542786e983fc5450e1daad71977a2b94c014685d6ad7eeb00797dc872d52d290755e1781bde5322f6962686a5a49804d4b7bb0effb9213b5d6c25ee6735aacb1ad5ff8d074cb0ea84d38d7657a58f633c5c98d49fba23c50b17a2e1b5cc902f7b4cd99471f4d6952fe143bb513af3ef81942945db90278831b4f048da8c254380d19d6262bb33952b7f56e3935e8f6ba63fe4cdb1818bc9d8b026730",
    },
    Kat {
        name: "shake136",
        kind: Kind::Shake,
        key_bytes: 0,
        message_bytes: 136,
        n: "",
        s: "",
        output_bytes: 72,
        counter: false,
        digest: "ed4a017052e2d4063658818d54f2a1b8c17afe879363f50437b0592e7319fd8eede65e9de766f3bd0e51adaa2855009fc1b0e7230633290a138a66a8bf791605e6762b34424f9a5b",
    },
    Kat {
        name: "shake137",
        kind: Kind::Shake,
        key_bytes: 0,
        message_bytes: 137,
        n: "",
        s: "",
        output_bytes: 137,
        counter: false,
        digest: "afd9177d8c6dda1cebc6411cf5a693c9481401bcad12dd898b3e33128bfafd5d1a7d1cd3f807152b5b18a3db2f38594b0f9b0d4b157e2aeac4d0eda287788c900334fc830f4dbad44b9cf645382f226b32d95f9f1a6b60f9efe0a94ee663d25b451151f3766e5f881c056cfb77ff2c02c2c4240dd960d9fc67040034b6e3ba691704d0c936cc8abe35",
    },
    Kat {
        name: "cshake_empty",
        kind: Kind::Cshake,
        key_bytes: 0,
        message_bytes: 137,
        n: "",
        s: "",
        output_bytes: 137,
        counter: false,
        digest: "afd9177d8c6dda1cebc6411cf5a693c9481401bcad12dd898b3e33128bfafd5d1a7d1cd3f807152b5b18a3db2f38594b0f9b0d4b157e2aeac4d0eda287788c900334fc830f4dbad44b9cf645382f226b32d95f9f1a6b60f9efe0a94ee663d25b451151f3766e5f881c056cfb77ff2c02c2c4240dd960d9fc67040034b6e3ba691704d0c936cc8abe35",
    },
    Kat {
        name: "cshake_nist",
        kind: Kind::Cshake,
        key_bytes: 0,
        message_bytes: 4,
        n: "",
        s: "456d61696c205369676e6174757265",
        output_bytes: 64,
        counter: true,
        digest: "d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c",
    },
    Kat {
        name: "cshake_fn",
        kind: Kind::Cshake,
        key_bytes: 0,
        message_bytes: 1,
        n: "46756e6374696f6e",
        s: "",
        output_bytes: 72,
        counter: false,
        digest: "c2bcd034392d2ee09bb9a46592f7fb72ea73d0ce005e31c90e4dfbf4e1c22fc38d88771d46f46712de866499a6cc56d32ef977921650ab280ee4f451a83ff379624d112d7382e691",
    },
    Kat {
        name: "cshake_both",
        kind: Kind::Cshake,
        key_bytes: 0,
        message_bytes: 137,
        n: "4e",
        s: "53",
        output_bytes: 291,
        counter: false,
        digest: "61c9b516c2aac8c66e2edbe2a93125709b3f212e74a823870a1a3573048334eb662bce21f01c3a3180174d989cce828e4eeecf76ed9d0fbc66f9a1c2285dbf2b42650d8682fff44ebc758a095c5d08f48985f7ab27d6a9d7a81fbb030e9e4e944e0a6738f747acfeffa231f14af3c6204fde116e7830dafb7814025ad21cbde107fd1d83734513f523c4e1c51b46751d77e9cbdf58cc5be29821b402cdfbfeb1f88867def0a49447c92282638da86f274c744136ffcd1b55c9e94df8f77071c566c838c0eb91255face439c8636142310729bd6cb1c165d4bdc2cba5c09615378b9d0c7bf090010ce67852fade05125e250bbacfd2b36c5e7a7eaa8f7c773a0db9c38bece0d34e1e6370d8a271fdc488361a618f047309e922d78b00c0ab3d50d3171b",
    },
    Kat {
        name: "cshake_prefix135",
        kind: Kind::Cshake,
        key_bytes: 0,
        message_bytes: 7,
        n: "4e",
        s: "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f2031425364758697a8b9cadbecfd0e1f30415263748596a7b8c9daebfc0d1e2f405162738495a6b7c8d9eafb0c1d2e3f5061",
        output_bytes: 72,
        counter: false,
        digest: "0c705647dbe63473c7c13088f4f293b3a3ed9b319e1360444ce16b9bc249a15c199b84de423b84a84fba176068d87f71cc153874c3130c5666e4ba6ad6af2fe77f923d7ca8a4ebf2",
    },
    Kat {
        name: "cshake_prefix136",
        kind: Kind::Cshake,
        key_bytes: 0,
        message_bytes: 8,
        n: "4e",
        s: "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f2031425364758697a8b9cadbecfd0e1f30415263748596a7b8c9daebfc0d1e2f405162738495a6b7c8d9eafb0c1d2e3f506172",
        output_bytes: 72,
        counter: false,
        digest: "a8cb00a873dd19a7ef2152b69bb30577c8120e163f4c9c80b65f4058ba7856eb865385261a2c90fa8856bb9eb9f4eaf426733fd48948ceb18aa04f9ea08bbd48e7d7a4485f7df71d",
    },
    Kat {
        name: "cshake_prefix137",
        kind: Kind::Cshake,
        key_bytes: 0,
        message_bytes: 9,
        n: "4e",
        s: "031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f2031425364758697a8b9cadbecfd0e1f30415263748596a7b8c9daebfc0d1e2f405162738495a6b7c8d9eafb0c1d2e3f50617283",
        output_bytes: 72,
        counter: false,
        digest: "89bfd9d19895a7600d726ac730d74ee2367c854e87b88671567d3a00572c8c45de01bafd0a11ae7d3fe1bd09f45b7dd061d284e171f468241b271265a3e2ca6177555ce58f9a440f",
    },
    Kat {
        name: "kmac0",
        kind: Kind::Kmac,
        key_bytes: 0,
        message_bytes: 0,
        n: "4b4d4143",
        s: "",
        output_bytes: 32,
        counter: false,
        digest: "0b002c51ec240a9ae0e9399cecb6a6a136452522342f7e6c17c62b8cd51f583b",
    },
    Kat {
        name: "kmac31",
        kind: Kind::Kmac,
        key_bytes: 31,
        message_bytes: 1,
        n: "4b4d4143",
        s: "",
        output_bytes: 32,
        counter: false,
        digest: "630e788e14d93ecf5ed5399b582b7c42deb72f9e1ca827db9f16f9a16040f7f3",
    },
    Kat {
        name: "kmac32",
        kind: Kind::Kmac,
        key_bytes: 32,
        message_bytes: 352,
        n: "4b4d4143",
        s: "50515341542d56332f54524143452d4d41432f76302e31",
        output_bytes: 32,
        counter: false,
        digest: "e6a06babba691edf34c63292289560c7b81381dfd130f442b7f7c88b6b28a58c",
    },
    Kat {
        name: "kmac_keypad135",
        kind: Kind::Kmac,
        key_bytes: 130,
        message_bytes: 9,
        n: "4b4d4143",
        s: "637573746f6d",
        output_bytes: 137,
        counter: false,
        digest: "38a4a1834caa78cd52bc4b668dde21bb845e07a116f96cae63168700b2e7e7922ed458bd350a27f215ea66cd097d197e6a7f8f498cd4f5c7c2e29b2c53a62c95010f6d673ce10aeb5c4d24b71a8b729bf0c76fc883fdc255d6c8df72b4158ace63869d57c6fb115521a7e4c51bf666d1777061b87aaff9b8476e914de8a534f97dc576c093b9b9125f",
    },
    Kat {
        name: "kmac_keypad136",
        kind: Kind::Kmac,
        key_bytes: 131,
        message_bytes: 7,
        n: "4b4d4143",
        s: "637573746f6d",
        output_bytes: 291,
        counter: false,
        digest: "278527d4a1d0e6760b2b19cf8f287e6d5526caa5d66ea309df1deb7272af393c3b356b940d1242c61062292a78d718d02717f3651d98f493a5eaaee878b7001604f0a6ce7a06b3b238626eefe34e4c1ed15cf72313258efd6e73fe3c05bb57103a901e707de3f515b919e586fae1dac612378f8a5bbb211b61db7ebf0d2c933957716bbac3fd2f589142df1bdcf0b2a6ae569e9e68adadd41f8e65eefc235859f9bfb8f63bbddcf31517b6c311c05abeca3bcf47ab9bea6dcad4975ca7b77005442ac45f4dc8c9e4d853332ae4219e236966a545d5f28cd45fc64c4cabff08123521f78fe72bcb5069ccd51c8055cd50a0fdbd355fa33a754c5353192b448f8779b846facdcf134b23a68f2e10a23be1b9f76c39f1e09c7982b34fec2ed2228dee34a4",
    },
    Kat {
        name: "kmac_keypad137",
        kind: Kind::Kmac,
        key_bytes: 132,
        message_bytes: 8,
        n: "4b4d4143",
        s: "637573746f6d",
        output_bytes: 72,
        counter: false,
        digest: "c267f084f865d6f6b694991734f5537d4397ae2aa8a61bac158ffd0de173dcde23e5c3d000423fd6979367c037d58f5d18c2139635bbbe0ff2ddb2a4ab3631a959b744bec560e2b3",
    },
    Kat {
        name: "kmac255",
        kind: Kind::Kmac,
        key_bytes: 255,
        message_bytes: 135,
        n: "4b4d4143",
        s: "53",
        output_bytes: 32,
        counter: false,
        digest: "35a328abe29f8e8e61c9b385bb7a71e65bda8cf6fb6aeb2b2123ccbbce0ec21c",
    },
    Kat {
        name: "kmac256",
        kind: Kind::Kmac,
        key_bytes: 256,
        message_bytes: 136,
        n: "4b4d4143",
        s: "53",
        output_bytes: 32,
        counter: false,
        digest: "7651f1e81e06d06a095e63642902634788dda84d85957b0541e9c139a7c8a99c",
    },
    Kat {
        name: "cshake135",
        kind: Kind::Cshake,
        key_bytes: 0,
        message_bytes: 135,
        n: "4e",
        s: "53",
        output_bytes: 72,
        counter: false,
        digest: "f203b7749ed015fd759e6775fbc25df1b3cd38fd24a5193cacefe9551f9dc3471c7813adcc5f58464f293577f9b6e78ba790d57f13f3ef79396395b3eaa6e887a55659ad96e4ffde",
    },
    Kat {
        name: "cshake136",
        kind: Kind::Cshake,
        key_bytes: 0,
        message_bytes: 136,
        n: "4e",
        s: "53",
        output_bytes: 72,
        counter: false,
        digest: "424ec14c584e2812367bbfc049cec52bd233d60a944084f49242de05128d90682d3d1cfe208e7fc663ab159648735ad7cb76ef511b0ccc7699948f1d98d07035dbe0b22824038a1b",
    },
    Kat {
        name: "kmac_suffix135",
        kind: Kind::Kmac,
        key_bytes: 32,
        message_bytes: 132,
        n: "4b4d4143",
        s: "53",
        output_bytes: 32,
        counter: false,
        digest: "a35f37301c727ff3a2fa600d91efe9e2eaef359002b997cd2c6a4d698c88a6a6",
    },
    Kat {
        name: "kmac_suffix136",
        kind: Kind::Kmac,
        key_bytes: 32,
        message_bytes: 133,
        n: "4b4d4143",
        s: "53",
        output_bytes: 32,
        counter: false,
        digest: "83b1e704a44e96698cd542f2498c9ff9f2194ffe8833956f985ec2bd5e7fc9ee",
    },
    Kat {
        name: "kmac_suffix137",
        kind: Kind::Kmac,
        key_bytes: 32,
        message_bytes: 134,
        n: "4b4d4143",
        s: "53",
        output_bytes: 32,
        counter: false,
        digest: "4120949673a6b875f1fb5c956aa5d9472db087b437902b86310339332c0f6efe",
    },
    Kat {
        name: "kmac_nist",
        kind: Kind::Kmac,
        key_bytes: 32,
        message_bytes: 4,
        n: "4b4d4143",
        s: "4d7920546167676564204170706c69636174696f6e",
        output_bytes: 64,
        counter: true,
        digest: "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd",
    },
];
fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (17 * i + 3) as u8).collect()
}
fn word(bytes: &[u8]) -> Word {
    let mut full = [0u8; 8];
    full[..bytes.len()].copy_from_slice(bytes);
    Word(u64::from_le_bytes(full))
}
thread_local! { static PERMUTATIONS: Cell<usize> = const { Cell::new(0) }; }
fn counted_permutation(b: &CircuitBuilder, state: &mut [Wire; 25]) {
    PERMUTATIONS.with(|n| n.set(n.get() + 1));
    keccak_f1600(b, state);
}
#[derive(Clone, Copy)]
enum Mutation {
    None,
    KeyTail,
    MessageTail,
    KeyByte,
    MessageByte,
    OutputByte,
    OutputTail,
}

fn run(k: &Kat, mutation: Mutation) -> bool {
    let message = if k.counter {
        (0..k.message_bytes).map(|i| i as u8).collect()
    } else {
        pattern(k.message_bytes)
    };
    let key = if k.name == "kmac_nist" {
        (0x40u8..0x60).collect()
    } else {
        pattern(k.key_bytes)
    };
    let n = hex(k.n);
    let s = hex(k.s);
    let digest = hex(k.digest);
    assert_eq!(digest.len(), k.output_bytes);
    let b = CircuitBuilder::new();
    let key_wires: Vec<_> = (0..k.key_bytes.div_ceil(8))
        .map(|_| b.add_witness())
        .collect();
    let input: Vec<_> = (0..k.message_bytes.div_ceil(8))
        .map(|_| b.add_witness())
        .collect();
    PERMUTATIONS.with(|n| n.set(0));
    let (actual, expected_calls) = match k.kind {
        Kind::Shake => (
            shake256_fixed_with_permutation(
                &b,
                &input,
                k.message_bytes,
                k.output_bytes,
                counted_permutation,
            ),
            shake256_permutation_count(k.message_bytes, k.output_bytes),
        ),
        Kind::Cshake => (
            cshake256_fixed_with_permutation(
                &b,
                &input,
                k.message_bytes,
                k.output_bytes,
                &n,
                &s,
                counted_permutation,
            ),
            cshake256_permutation_count(k.message_bytes, k.output_bytes, &n, &s),
        ),
        Kind::Kmac => (
            kmac256_fixed_with_permutation(
                &b,
                &key_wires,
                k.key_bytes,
                &input,
                k.message_bytes,
                k.output_bytes,
                &s,
                counted_permutation,
            ),
            kmac256_permutation_count(k.key_bytes, k.message_bytes, k.output_bytes, &s),
        ),
    };
    assert_eq!(
        PERMUTATIONS.with(Cell::get),
        expected_calls,
        "all absorb/squeeze dispatches"
    );
    let expected: Vec<_> = (0..k.output_bytes.div_ceil(8))
        .map(|_| b.add_inout())
        .collect();
    assert_eq!(actual.len(), expected.len());
    for (&a, &e) in actual.iter().zip(&expected) {
        b.assert_eq("public_sponge_golden", a, e);
    }
    let circuit = b.build();
    let mut w = circuit.new_witness_filler();
    for (&wire, bytes) in key_wires.iter().zip(key.chunks(8)) {
        w[wire] = word(bytes);
    }
    for (&wire, bytes) in input.iter().zip(message.chunks(8)) {
        w[wire] = word(bytes);
    }
    for (&wire, bytes) in expected.iter().zip(digest.chunks(8)) {
        w[wire] = word(bytes);
    }
    assert!(
        circuit.populate_wire_witness(&mut w).is_ok(),
        "public KAT evaluator"
    );
    // Only after a valid canonical fill: reject emitted constraints, not merely
    // an evaluator assertion or an unsupported public shape.
    let change = match mutation {
        Mutation::None => None,
        Mutation::KeyTail => {
            assert_ne!(k.key_bytes % 8, 0);
            Some((*key_wires.last().unwrap(), 1u64 << (8 * (k.key_bytes % 8))))
        }
        Mutation::MessageTail => {
            assert_ne!(k.message_bytes % 8, 0);
            Some((*input.last().unwrap(), 1u64 << (8 * (k.message_bytes % 8))))
        }
        Mutation::KeyByte => Some((key_wires[0], 1)),
        Mutation::MessageByte => Some((input[0], 1)),
        Mutation::OutputByte => Some((expected[0], 1)),
        Mutation::OutputTail => {
            assert_ne!(k.output_bytes % 8, 0);
            Some((
                *expected.last().unwrap(),
                1u64 << (8 * (k.output_bytes % 8)),
            ))
        }
    };
    if let Some((wire, mask)) = change {
        let previous = w[wire].0;
        w[wire] = Word(previous ^ mask);
    }
    circuit
        .constraint_system()
        .verify(&w.into_value_vec())
        .is_ok()
}
fn kat(name: &str) -> &'static Kat {
    KATS.iter().find(|k| k.name == name).unwrap()
}

#[test]
fn independent_shake_goldens_and_empty_cshake_identity() {
    for k in KATS
        .iter()
        .filter(|k| k.kind == Kind::Shake || k.name == "cshake_empty")
    {
        assert!(run(k, Mutation::None), "public KAT {}", k.name);
    }
    assert_eq!(kat("shake137").digest, kat("cshake_empty").digest);
}
#[test]
fn cshake_function_customization_bytepad_and_multi_squeeze_goldens() {
    for k in KATS
        .iter()
        .filter(|k| k.kind == Kind::Cshake && k.name != "cshake_empty")
    {
        assert!(run(k, Mutation::None), "public cSHAKE KAT {}", k.name);
    }
}
#[test]
fn kmac_key_bytepad_boundaries_lengths_and_actual_trace_golden() {
    for k in KATS.iter().filter(|k| k.kind == Kind::Kmac) {
        assert!(run(k, Mutation::None), "public KMAC KAT {}", k.name);
    }
}
#[test]
fn canonical_input_tails_and_binding_mutations_rejected() {
    assert!(!run(kat("kmac31"), Mutation::KeyTail));
    assert!(!run(kat("kmac31"), Mutation::MessageTail));
    assert!(!run(kat("kmac31"), Mutation::KeyByte));
    assert!(!run(kat("kmac31"), Mutation::MessageByte));
    assert!(!run(kat("cshake_fn"), Mutation::MessageTail));
    assert!(!run(kat("shake137"), Mutation::OutputByte));
    assert!(!run(kat("cshake_both"), Mutation::OutputTail));
}
#[test]
fn public_encoding_integer_bytepad_and_domain_controls() {
    assert_eq!(left_encode(0), [1, 0]);
    assert_eq!(right_encode(0), [0, 1]);
    assert_eq!(left_encode(255), [1, 255]);
    assert_eq!(right_encode(255), [255, 1]);
    assert_eq!(left_encode(256), [2, 1, 0]);
    assert_eq!(right_encode(256), [1, 0, 2]);
    assert_eq!(
        left_encode(u64::MAX),
        [8, 255, 255, 255, 255, 255, 255, 255, 255]
    );
    assert_eq!(
        right_encode(u64::MAX),
        [255, 255, 255, 255, 255, 255, 255, 255, 8]
    );
    assert_eq!(encode_string(b""), [1, 0]);
    assert_eq!(encode_string(b"A"), [1, 8, 65]);
    for bytes in [0, 1, 133, 134, 135, 136, 137] {
        let input = pattern(bytes);
        let padded = bytepad_136(&input);
        assert_eq!(&padded[..2], &[1, 136]);
        assert_eq!(&padded[2..2 + bytes], &input);
        assert!(padded[2 + bytes..].iter().all(|&x| x == 0));
        assert_eq!(padded.len() % 136, 0);
        assert_eq!(padded.len(), (bytes + 2).div_ceil(136) * 136);
    }
    assert!(cshake256_prefix(b"", b"").is_empty());
    assert_ne!(cshake256_prefix(b"N", b""), cshake256_prefix(b"", b"N"));
    assert_ne!(cshake256_prefix(b"AB", b"C"), cshake256_prefix(b"A", b"BC"));
    assert_eq!(cshake256_prefix(b"N", &pattern(127)).len(), 136);
    assert_eq!(cshake256_prefix(b"N", &pattern(128)).len(), 136);
    assert_eq!(cshake256_prefix(b"N", &pattern(129)).len(), 272);
    assert_eq!(bytepad_136(&encode_string(&pattern(130))).len(), 136);
    assert_eq!(bytepad_136(&encode_string(&pattern(131))).len(), 136);
    assert_eq!(bytepad_136(&encode_string(&pattern(132))).len(), 272);
}
#[test]
fn exact_public_full_recipe_counts_without_large_circuits() {
    assert_eq!(shake256_permutation_count(1971136, 48), 14494); // full h1
    assert_eq!(shake256_permutation_count(162, 48), 2); // one leaf commitment
    assert_eq!(shake256_permutation_count(162, 291), 4); // one selected tape
    assert_eq!(shake256_permutation_count(1195, 80), 9); // trace KDF
    assert_eq!(shake256_permutation_count(5799, 72), 43); // full message H
    assert_eq!(
        kmac256_permutation_count(32, 352, 32, b"PQSAT-V3/TRACE-MAC/v0.1"),
        5
    );
    assert_eq!(shake256_permutation_count(136, 136), 2);
    assert_eq!(shake256_permutation_count(136, 137), 3);
    assert_eq!(cshake256_permutation_count(0, 72, b"", b""), 1);
    assert_eq!(cshake256_permutation_count(0, 72, b"N", b""), 2);
    assert!(shake256_permutation_count(MAX_MESSAGE_BYTES, MAX_OUTPUT_BYTES) > 0);
    assert!(
        kmac256_permutation_count(
            MAX_KEY_BYTES,
            MAX_MESSAGE_BYTES,
            MAX_OUTPUT_BYTES,
            &vec![0; MAX_CUSTOMIZATION_BYTES]
        ) > 0
    );
}
#[test]
fn unsupported_public_shapes_reject_before_circuit_construction() {
    let reject = |f: &dyn Fn()| assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
    reject(&|| {
        shake256_permutation_count(usize::MAX, 32);
    });
    reject(&|| {
        shake256_permutation_count(MAX_MESSAGE_BYTES + 1, 32);
    });
    reject(&|| {
        shake256_permutation_count(0, 0);
    });
    reject(&|| {
        shake256_permutation_count(0, MAX_OUTPUT_BYTES + 1);
    });
    reject(&|| {
        cshake256_permutation_count(0, 32, &vec![0; MAX_FUNCTION_NAME_BYTES + 1], b"");
    });
    reject(&|| {
        cshake256_permutation_count(0, 32, b"", &vec![0; MAX_CUSTOMIZATION_BYTES + 1]);
    });
    reject(&|| {
        kmac256_permutation_count(MAX_KEY_BYTES + 1, 0, 32, b"");
    });
    reject(&|| {
        bytepad_length(usize::MAX);
    });
    let b = CircuitBuilder::new();
    let one = b.add_witness();
    reject(&|| {
        shake256_fixed(&b, &[], 1, 32);
    });
    reject(&|| {
        cshake256_fixed(&b, &[one], 0, 32, b"N", b"");
    });
    reject(&|| {
        kmac256_fixed(&b, &[one], 0, &[], 0, 32, b"");
    });
    reject(&|| {
        kmac256_fixed(&b, &[], 0, &[], 1, 32, b"");
    });
}
#[test]
fn packed_wire_concatenation_all_offsets_no_byte_witness_expansion() {
    // No hash is built: isolate word-carry joins at every possible byte
    // offset, including empty segments, aligned inputs and partial tails.
    let b = CircuitBuilder::new();
    let mut packed = PackedMessage::new(&b);
    let mut all = Vec::new();
    let mut inputs = Vec::new();
    for bytes in [
        1, 0, 7, 2, 6, 3, 5, 4, 4, 5, 3, 6, 2, 7, 1, 8, 9, 15, 16, 17,
    ] {
        let value = pattern(bytes);
        let wires: Vec<_> = (0..bytes.div_ceil(8)).map(|_| b.add_witness()).collect();
        packed.append(&wires, bytes, true);
        all.extend_from_slice(&value);
        inputs.push((wires, value));
    }
    assert_eq!(packed.bytes, all.len());
    assert_eq!(packed.words.len(), all.len().div_ceil(8));
    for (&actual, bytes) in packed.words.iter().zip(all.chunks(8)) {
        b.assert_eq("public_packed_join", actual, b.add_constant(word(bytes)));
    }
    let circuit = b.build();
    let mut w = circuit.new_witness_filler();
    for (wires, value) in inputs {
        for (&wire, bytes) in wires.iter().zip(value.chunks(8)) {
            w[wire] = word(bytes);
        }
    }
    assert!(
        circuit.populate_wire_witness(&mut w).is_ok(),
        "public packed join evaluator"
    );
    assert!(
        circuit
            .constraint_system()
            .verify(&w.into_value_vec())
            .is_ok(),
        "public packed join constraints"
    );
}
