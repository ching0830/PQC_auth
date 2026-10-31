//! Polynomial-basis GF(2^64) word gadgets for the research PC2 relation.
//!
//! Bit i is the coefficient of x^i. The reduction polynomial is exactly
//! x^64 + x^4 + x^3 + x + 1. These are circuit constraints over the pinned
//! Binius frontend's word AND/XOR/shifts, not integer multiplication or a
//! truncation of GHASH multiplication. No values, randomness or proof are
//! consumed by circuit construction.

use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire};

/// Low coefficients of x^64 + x^4 + x^3 + x + 1, in LSB0 order.
pub const MODULUS_LOW: u64 = 0x1b;

// The arithmetic shift broadcasts a's high bit to all 64 positions. AND
// with 0x1b supplies the exact reduction when shifting x^63 past x^64.
fn xtime(builder: &CircuitBuilder, a: Wire) -> Wire {
    let high_mask = builder.sar(a, 63);
    let reduction = builder.band(high_mask, builder.add_constant(Word(MODULUS_LOW)));
    builder.bxor(builder.shl(a, 1), reduction)
}

// Shift bit i to the sign position, then broadcast it. This selects a full
// word, rather than relying on the frontend's MSB-only Boolean assertions.
fn bit_mask(builder: &CircuitBuilder, a: Wire, i: u32) -> Wire {
    builder.sar(builder.shl(a, 63 - i), 63)
}

/// Constrain the product of two arbitrary private or public GF64 words.
///
/// The fixed 64-step construction sums a*x^i for every set bit i of b, with
/// reduction after each shift. Circuit shape never depends on either value.
/// Before frontend optimization this uses 127 BANDs, 253 nontrivial shifts,
/// and 126 XORs; no IMUL/BMUL gate or unconstrained auxiliary witness is used.
/// The frontend may fuse shifts or constant masks, so compiled constraint
/// counts must be measured separately from these source-operation counts.
pub fn mul(builder: &CircuitBuilder, a: Wire, b: Wire) -> Wire {
    let mut power = a;
    let mut product = builder.band(power, bit_mask(builder, b, 0));
    for i in 1..64 {
        power = xtime(builder, power);
        let term = builder.band(power, bit_mask(builder, b, i));
        product = builder.bxor(product, term);
    }
    product
}

/// Constrain a times a fixed, PUBLIC polynomial-basis coefficient.
///
/// Specialization depends only on the public constant: zero and one return
/// the corresponding zero/a wire, and the other cases need h xtime steps
/// and popcount(constant)-1 accumulator XORs, where h is its highest set bit.
/// This function must never be called with a witness-derived host constant.
pub fn mul_const(builder: &CircuitBuilder, a: Wire, constant: u64) -> Wire {
    if constant == 0 {
        return builder.add_constant(Word::ZERO);
    }
    let mut remaining = constant;
    let mut power = a;
    let mut product = None;
    while remaining != 0 {
        if remaining & 1 != 0 {
            product = Some(match product {
                Some(previous) => builder.bxor(previous, power),
                None => power,
            });
        }
        remaining >>= 1;
        if remaining != 0 {
            power = xtime(builder, power);
        }
    }
    product.expect("nonzero public coefficient has a set bit")
}

/// Small scalar reference for PUBLIC test vectors and diagnostic controls.
///
/// This deliberately uses a different schedule from the word circuit:
/// construct the complete carry-less u128 product, then perform polynomial
/// long division from degree 126 down to 64. The final u64 conversion occurs
/// only AFTER exact GF64 reduction; it is not a GHASH or integer-product cast.
/// The branches are not a constant-time implementation for private host data.
pub fn reference_mul(a: u64, b: u64) -> u64 {
    let mut product = 0u128;
    for bit in 0..64 {
        if (b >> bit) & 1 != 0 {
            product ^= (a as u128) << bit;
        }
    }
    let modulus = (1u128 << 64) | MODULUS_LOW as u128;
    for degree in (64..=126).rev() {
        if (product >> degree) & 1 != 0 {
            product ^= modulus << (degree - 64);
        }
    }
    debug_assert!(product >> 64 == 0);
    product as u64
}

#[cfg(test)]
#[path = "gf64_tests.rs"]
mod tests;
