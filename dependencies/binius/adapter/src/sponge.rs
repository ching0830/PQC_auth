//! Bounded fixed-byte SHAKE256, cSHAKE256 and KMAC256 circuit primitives.
//!
//! SP 800-185 encodings use big-endian integers; circuit bytes are packed
//! little-endian in full 64-bit words. N, S, lengths and output length are
//! public circuit-shape inputs, while message/key words may be private.
//! Unused input-word bytes are constrained to zero. This module constructs
//! constraints only; it does not prove, verify, or qualify a protocol.
//!
//! The public caps admit the current full-h1 preimage without constructing it
//! here. They are API allocation caps, not an RSS bound or proof admission.

use binius_circuits::keccak::keccak_f1600;
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire};

pub const RATE_BYTES: usize = 136;
pub const MAX_MESSAGE_BYTES: usize = 2 << 20;
pub const MAX_OUTPUT_BYTES: usize = 1024;
pub const MAX_KEY_BYTES: usize = 4096;
pub const MAX_FUNCTION_NAME_BYTES: usize = 256;
pub const MAX_CUSTOMIZATION_BYTES: usize = 4096;
/// Includes all cSHAKE/KMAC prefixes, key padding and right_encode(L).
pub const MAX_ABSORB_BYTES: usize = MAX_MESSAGE_BYTES
    + MAX_KEY_BYTES
    + MAX_FUNCTION_NAME_BYTES
    + MAX_CUSTOMIZATION_BYTES
    + 4 * RATE_BYTES;
const RATE_WORDS: usize = RATE_BYTES / 8;
/// Allows a caller to select an independently checked implementation of the
/// same permutation. Identity/correctness of that implementation is the
/// caller's responsibility; all absorb and squeeze calls use it consistently.
pub type Permutation = fn(&CircuitBuilder, &mut [Wire; 25]);

/// SP 800-185 left_encode for a public integer (including zero).
pub fn left_encode(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    let mut out = Vec::with_capacity(9 - start);
    out.push((8 - start) as u8);
    out.extend_from_slice(&bytes[start..]);
    out
}

/// SP 800-185 right_encode for a public integer (including zero).
pub fn right_encode(value: u64) -> Vec<u8> {
    let mut out = left_encode(value);
    let width = out.remove(0);
    out.push(width);
    out
}

fn bit_length(bytes: usize) -> u64 {
    u64::try_from(bytes)
        .expect("bounded byte length")
        .checked_mul(8)
        .expect("bounded bit length")
}

fn add_length(a: usize, b: usize) -> usize {
    let n = a.checked_add(b).expect("bounded sponge length addition");
    assert!(n <= MAX_ABSORB_BYTES, "bounded combined sponge input");
    n
}

/// Encode a bounded public byte string; private strings use circuit wires.
pub fn encode_string(value: &[u8]) -> Vec<u8> {
    assert!(
        value.len() <= MAX_MESSAGE_BYTES,
        "bounded encoded public string"
    );
    let mut out = left_encode(bit_length(value.len()));
    let length = add_length(out.len(), value.len());
    out.reserve(length - out.len());
    out.extend_from_slice(value);
    out
}

fn bytepad_length(value_bytes: usize) -> usize {
    let n = add_length(left_encode(RATE_BYTES as u64).len(), value_bytes);
    add_length(n, (RATE_BYTES - n % RATE_BYTES) % RATE_BYTES)
}

/// SP 800-185 bytepad(value, 136), for public encoding bytes only.
pub fn bytepad_136(value: &[u8]) -> Vec<u8> {
    let length = bytepad_length(value.len());
    let mut out = Vec::with_capacity(length);
    out.extend_from_slice(&left_encode(RATE_BYTES as u64));
    out.extend_from_slice(value);
    out.resize(length, 0);
    out
}

fn common_shape(message_bytes: usize, output_bytes: usize) {
    assert!(
        message_bytes <= MAX_MESSAGE_BYTES,
        "bounded sponge message length"
    );
    assert!(
        (1..=MAX_OUTPUT_BYTES).contains(&output_bytes),
        "bounded positive sponge output length"
    );
}

fn customization_shape(function_name: &[u8], customization: &[u8]) {
    assert!(
        function_name.len() <= MAX_FUNCTION_NAME_BYTES,
        "bounded public function name"
    );
    assert!(
        customization.len() <= MAX_CUSTOMIZATION_BYTES,
        "bounded public customization"
    );
}

fn prefix_length(function_name: &[u8], customization: &[u8]) -> usize {
    customization_shape(function_name, customization);
    if function_name.is_empty() && customization.is_empty() {
        return 0;
    }
    let name = add_length(
        left_encode(bit_length(function_name.len())).len(),
        function_name.len(),
    );
    let custom = add_length(
        left_encode(bit_length(customization.len())).len(),
        customization.len(),
    );
    bytepad_length(add_length(name, custom))
}

/// cSHAKE's public prefix; empty N and S select SHAKE with no prefix.
pub fn cshake256_prefix(function_name: &[u8], customization: &[u8]) -> Vec<u8> {
    let length = prefix_length(function_name, customization);
    if length == 0 {
        return Vec::new();
    }
    let mut strings = encode_string(function_name);
    strings.extend_from_slice(&encode_string(customization));
    let out = bytepad_136(&strings);
    assert_eq!(out.len(), length, "exact cSHAKE prefix length");
    out
}

fn count(absorb_bytes: usize, output_bytes: usize) -> usize {
    assert!(
        absorb_bytes <= MAX_ABSORB_BYTES,
        "bounded combined sponge input"
    );
    assert!(
        (1..=MAX_OUTPUT_BYTES).contains(&output_bytes),
        "bounded positive sponge output length"
    );
    absorb_bytes / RATE_BYTES + 1 + (output_bytes - 1) / RATE_BYTES
}

pub fn shake256_permutation_count(message_bytes: usize, output_bytes: usize) -> usize {
    common_shape(message_bytes, output_bytes);
    count(message_bytes, output_bytes)
}

pub fn cshake256_permutation_count(
    message_bytes: usize,
    output_bytes: usize,
    function_name: &[u8],
    customization: &[u8],
) -> usize {
    common_shape(message_bytes, output_bytes);
    count(
        add_length(prefix_length(function_name, customization), message_bytes),
        output_bytes,
    )
}

fn kmac_length(
    key_bytes: usize,
    message_bytes: usize,
    output_bytes: usize,
    customization: &[u8],
) -> usize {
    common_shape(message_bytes, output_bytes);
    assert!(key_bytes <= MAX_KEY_BYTES, "bounded KMAC key length");
    let encoded_key = add_length(left_encode(bit_length(key_bytes)).len(), key_bytes);
    let length = add_length(
        prefix_length(b"KMAC", customization),
        bytepad_length(encoded_key),
    );
    let length = add_length(length, message_bytes);
    add_length(length, right_encode(bit_length(output_bytes)).len())
}

pub fn kmac256_permutation_count(
    key_bytes: usize,
    message_bytes: usize,
    output_bytes: usize,
    customization: &[u8],
) -> usize {
    count(
        kmac_length(key_bytes, message_bytes, output_bytes, customization),
        output_bytes,
    )
}

/// A byte concatenation implemented with word shifts, not per-bit witnesses.
struct PackedMessage<'a> {
    builder: &'a CircuitBuilder,
    words: Vec<Wire>,
    bytes: usize,
    zero: Wire,
}

impl<'a> PackedMessage<'a> {
    fn new(builder: &'a CircuitBuilder) -> Self {
        Self {
            builder,
            words: Vec::new(),
            bytes: 0,
            zero: builder.add_constant(Word::ZERO),
        }
    }

    fn append(&mut self, words: &[Wire], bytes: usize, private: bool) {
        assert_eq!(
            words.len(),
            bytes.div_ceil(8),
            "exact packed sponge input wire count"
        );
        let new_bytes = add_length(self.bytes, bytes);
        if private && bytes % 8 != 0 {
            let last = words[words.len() - 1];
            let mask = (1u64 << (8 * (bytes % 8))) - 1;
            let masked = self
                .builder
                .band(last, self.builder.add_constant(Word(mask)));
            self.builder
                .assert_eq("sponge_input_tail_zero", last, masked);
        }
        let offset = self.bytes % 8;
        if offset == 0 {
            self.words.extend_from_slice(words);
        } else {
            let base = self.bytes / 8;
            self.words.resize(new_bytes.div_ceil(8), self.zero);
            for (i, &word) in words.iter().enumerate() {
                let lo = self.builder.shl(word, (8 * offset) as u32);
                self.words[base + i] = self.builder.bxor(self.words[base + i], lo);
                if base + i + 1 < self.words.len() {
                    let hi = self.builder.shr(word, (64 - 8 * offset) as u32);
                    self.words[base + i + 1] = self.builder.bxor(self.words[base + i + 1], hi);
                }
            }
        }
        self.bytes = new_bytes;
    }

    fn public(&mut self, value: &[u8]) {
        // Validate total length before constants or the temporary word vector.
        add_length(self.bytes, value.len());
        let words: Vec<_> = value
            .chunks(8)
            .map(|chunk| {
                let mut bytes = [0u8; 8];
                bytes[..chunk.len()].copy_from_slice(chunk);
                self.builder.add_constant(Word(u64::from_le_bytes(bytes)))
            })
            .collect();
        self.append(&words, value.len(), false);
    }

    fn finish(mut self, output_bytes: usize, suffix: u8, permutation: Permutation) -> Vec<Wire> {
        assert!(suffix == 0x1f || suffix == 0x04, "SHAKE/cSHAKE delimiter");
        let padded_words = (self.bytes / RATE_BYTES + 1) * RATE_WORDS;
        self.public(&[suffix]);
        self.words.resize(padded_words, self.zero);
        let last = padded_words - 1;
        self.words[last] = self.builder.bxor(
            self.words[last],
            self.builder.add_constant(Word(0x80u64 << 56)),
        );
        let mut state = [self.zero; 25];
        for block in self.words.chunks_exact(RATE_WORDS) {
            for (lane, &word) in block.iter().enumerate() {
                state[lane] = self.builder.bxor(state[lane], word);
            }
            permutation(self.builder, &mut state);
        }
        let mut output = Vec::with_capacity(output_bytes.div_ceil(8));
        let mut remaining = output_bytes;
        while remaining != 0 {
            let bytes = remaining.min(RATE_BYTES);
            let words = bytes.div_ceil(8);
            for lane in 0..words {
                let word = if lane + 1 == words && bytes % 8 != 0 {
                    let mask = (1u64 << (8 * (bytes % 8))) - 1;
                    self.builder
                        .band(state[lane], self.builder.add_constant(Word(mask)))
                } else {
                    state[lane]
                };
                output.push(word);
            }
            remaining -= bytes;
            if remaining != 0 {
                permutation(self.builder, &mut state);
            }
        }
        output
    }
}

/// SHAKE256 with exact input word count and canonical unused high bytes.
pub fn shake256_fixed(
    builder: &CircuitBuilder,
    message: &[Wire],
    message_bytes: usize,
    output_bytes: usize,
) -> Vec<Wire> {
    shake256_fixed_with_permutation(builder, message, message_bytes, output_bytes, keccak_f1600)
}

pub fn shake256_fixed_with_permutation(
    builder: &CircuitBuilder,
    message: &[Wire],
    message_bytes: usize,
    output_bytes: usize,
    permutation: Permutation,
) -> Vec<Wire> {
    shake256_permutation_count(message_bytes, output_bytes);
    assert_eq!(
        message.len(),
        message_bytes.div_ceil(8),
        "exact packed sponge input wire count"
    );
    let mut packed = PackedMessage::new(builder);
    packed.append(message, message_bytes, true);
    packed.finish(output_bytes, 0x1f, permutation)
}

/// cSHAKE256(X,L,N,S), for public byte strings N/S and private-or-public X.
/// Empty N and S are exactly SHAKE256(X,L), as required by SP 800-185.
pub fn cshake256_fixed(
    builder: &CircuitBuilder,
    message: &[Wire],
    message_bytes: usize,
    output_bytes: usize,
    function_name: &[u8],
    customization: &[u8],
) -> Vec<Wire> {
    cshake256_fixed_with_permutation(
        builder,
        message,
        message_bytes,
        output_bytes,
        function_name,
        customization,
        keccak_f1600,
    )
}

pub fn cshake256_fixed_with_permutation(
    builder: &CircuitBuilder,
    message: &[Wire],
    message_bytes: usize,
    output_bytes: usize,
    function_name: &[u8],
    customization: &[u8],
    permutation: Permutation,
) -> Vec<Wire> {
    cshake256_permutation_count(message_bytes, output_bytes, function_name, customization);
    assert_eq!(
        message.len(),
        message_bytes.div_ceil(8),
        "exact packed sponge input wire count"
    );
    let prefix = cshake256_prefix(function_name, customization);
    let suffix = if prefix.is_empty() { 0x1f } else { 0x04 };
    let mut packed = PackedMessage::new(builder);
    packed.public(&prefix);
    packed.append(message, message_bytes, true);
    packed.finish(output_bytes, suffix, permutation)
}

/// KMAC256(K,X,L,S); this is fixed-output KMAC, not KMACXOF.
/// Key/message may share existing constrained wires. Lengths and S are public;
/// the secret key is never converted to host bytes or a public constant.
pub fn kmac256_fixed(
    builder: &CircuitBuilder,
    key: &[Wire],
    key_bytes: usize,
    message: &[Wire],
    message_bytes: usize,
    output_bytes: usize,
    customization: &[u8],
) -> Vec<Wire> {
    kmac256_fixed_with_permutation(
        builder,
        key,
        key_bytes,
        message,
        message_bytes,
        output_bytes,
        customization,
        keccak_f1600,
    )
}

pub fn kmac256_fixed_with_permutation(
    builder: &CircuitBuilder,
    key: &[Wire],
    key_bytes: usize,
    message: &[Wire],
    message_bytes: usize,
    output_bytes: usize,
    customization: &[u8],
    permutation: Permutation,
) -> Vec<Wire> {
    let length = kmac_length(key_bytes, message_bytes, output_bytes, customization);
    assert_eq!(
        key.len(),
        key_bytes.div_ceil(8),
        "exact packed KMAC key wire count"
    );
    assert_eq!(
        message.len(),
        message_bytes.div_ceil(8),
        "exact packed sponge input wire count"
    );
    let mut packed = PackedMessage::new(builder);
    packed.public(&cshake256_prefix(b"KMAC", customization));
    let mut prefix = left_encode(RATE_BYTES as u64);
    prefix.extend_from_slice(&left_encode(bit_length(key_bytes)));
    let padding = (RATE_BYTES - (prefix.len() + key_bytes) % RATE_BYTES) % RATE_BYTES;
    packed.public(&prefix);
    packed.append(key, key_bytes, true);
    packed.public(&vec![0u8; padding]);
    packed.append(message, message_bytes, true);
    packed.public(&right_encode(bit_length(output_bytes)));
    assert_eq!(packed.bytes, length, "exact KMAC encoded input length");
    packed.finish(output_bytes, 0x04, permutation)
}

#[cfg(test)]
#[path = "sponge_tests.rs"]
mod tests;
