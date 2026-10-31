//! Fixed-length SHAKE256 circuit for the bounded F7 capability gate.
//!
//! Uses the pinned upstream Keccak-f[1600] gadget, with SHAKE's 0x1f
//! delimiter (not Keccak-256's 0x01). Inputs and outputs are little-endian
//! packed u64 words. Input bytes outside the declared length are constrained
//! to zero; output bytes beyond the requested length are derived zeroes.
//! This module creates constraints only: it neither proves nor verifies a proof.

use binius_circuits::keccak::keccak_f1600;
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire};

/// Largest admitted message: the exact full-H preimage for this F7 gate.
pub const MAX_MESSAGE_BYTES: usize = 5799;
/// Bound covers full-H's 72 bytes and public SHAKE multi-squeeze controls.
pub const MAX_OUTPUT_BYTES: usize = 291;
pub const RATE_BYTES: usize = 136;
const RATE_WORDS: usize = RATE_BYTES / 8;
const STATE_WORDS: usize = 25;

fn shape(message_bytes: usize, output_bytes: usize) {
    assert!(message_bytes <= MAX_MESSAGE_BYTES, "bounded SHAKE message length");
    assert!(
        (1..=MAX_OUTPUT_BYTES).contains(&output_bytes),
        "bounded positive SHAKE output length"
    );
}

/// Number of actual Keccak-f calls, including additional squeeze blocks.
pub fn permutation_count(message_bytes: usize, output_bytes: usize) -> usize {
    shape(message_bytes, output_bytes);
    (message_bytes / RATE_BYTES + 1) + (output_bytes - 1) / RATE_BYTES
}

/// Build exact fixed-length SHAKE256 over `message_bytes` packed LE bytes.
///
/// Returns exactly `output_bytes.div_ceil(8)` words. The last returned word
/// has zero high bytes when the output is not word-aligned. Circuit equality
/// checks must use full-word `assert_eq`/`assert_zero`, not MSB-only Boolean
/// assertions. No message value is accepted or printed while building.
///
/// Panics on unsupported public lengths or a non-exact input wire count.
pub fn shake256_fixed(
    builder: &CircuitBuilder,
    message: &[Wire],
    message_bytes: usize,
    output_bytes: usize,
) -> Vec<Wire> {
    shape(message_bytes, output_bytes);
    assert_eq!(
        message.len(),
        message_bytes.div_ceil(8),
        "exact packed SHAKE input wire count"
    );
    let blocks = message_bytes / RATE_BYTES + 1;
    let padded_words = blocks * RATE_WORDS;
    let zero = builder.add_constant(Word::ZERO);
    let mut padded = Vec::with_capacity(padded_words);
    let tail_bytes = message_bytes % 8;
    if tail_bytes == 0 {
        padded.extend_from_slice(message);
        padded.push(builder.add_constant(Word(0x1f)));
    } else {
        let last = message.len() - 1;
        padded.extend_from_slice(&message[..last]);
        let mask = (1u64 << (tail_bytes * 8)) - 1;
        let masked = builder.band(message[last], builder.add_constant(Word(mask)));
        // Unlike merely masking the word, this rejects alternate encodings
        // that carry arbitrary witness bits outside the declared byte length.
        builder.assert_eq("shake_input_tail_zero", message[last], masked);
        let suffix = builder.add_constant(Word(0x1fu64 << (tail_bytes * 8)));
        padded.push(builder.bxor(masked, suffix));
    }
    padded.resize(padded_words, zero);
    let last = padded_words - 1;
    padded[last] = builder.bxor(padded[last], builder.add_constant(Word(0x80u64 << 56)));

    let mut state = [zero; STATE_WORDS];
    for block in padded.chunks_exact(RATE_WORDS) {
        for (lane, &word) in block.iter().enumerate() {
            state[lane] = builder.bxor(state[lane], word);
        }
        keccak_f1600(builder, &mut state);
    }

    let mut output = Vec::with_capacity(output_bytes.div_ceil(8));
    let mut remaining = output_bytes;
    while remaining != 0 {
        let bytes = remaining.min(RATE_BYTES);
        let words = bytes.div_ceil(8);
        for lane in 0..words {
            let word = if lane + 1 == words && bytes % 8 != 0 {
                let mask = (1u64 << ((bytes % 8) * 8)) - 1;
                builder.band(state[lane], builder.add_constant(Word(mask)))
            } else {
                state[lane]
            };
            output.push(word);
        }
        remaining -= bytes;
        if remaining != 0 {
            keccak_f1600(builder, &mut state);
        }
    }
    output
}

#[cfg(test)]
#[path = "shake_tests.rs"]
mod tests;
