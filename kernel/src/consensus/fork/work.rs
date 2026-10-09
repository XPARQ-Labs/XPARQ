use crate::consensus::PoWTarget;
use borsh::{BorshDeserialize, BorshSerialize};
use std::ops::Add;
#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct Work([u64; 8]);

impl Work {
    pub const ZERO: Self = Self([0; 8]);
    pub const MAX: Self = Self([u64::MAX; 8]);

    pub fn to_be_limbs(self) -> [u64; 8] {
        self.0
    }

    pub const fn from_be_limbs(limbs: [u64; 8]) -> Self {
        Self(limbs)
    }

    pub fn pow2(exponent: u32) -> Self {
        if exponent >= 512 {
            return Self::MAX;
        }

        let limb_from_low = (exponent / 64) as usize;
        let bit = exponent % 64;
        let mut limbs = [0; 8];
        limbs[7 - limb_from_low] = 1_u64 << bit;
        Self(limbs)
    }

    pub fn saturating_add(self, rhs: Self) -> Self {
        let mut result = [0; 8];
        let mut carry = 0_u128;

        for index in (0..result.len()).rev() {
            let sum = self.0[index] as u128 + rhs.0[index] as u128 + carry;
            result[index] = sum as u64;
            carry = sum >> 64;
        }

        if carry > 0 { Self::MAX } else { Self(result) }
    }
}

impl Add for Work {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.saturating_add(rhs)
    }
}

pub fn block_work(target_bits: u32) -> Option<Work> {
    let target = PoWTarget::from_compact(target_bits)?;

    //
    // Bitcoin-style chainwork:
    //
    //     floor(2^256 / (target + 1))
    //
    // Work is 512 bits, while the PoW target is 256 bits. A 320-bit
    // temporary is enough to represent both 2^256 and target + 1
    // without overflow.
    //
    let mut denominator = [0_u64; 5];

    for (index, chunk) in target.as_bytes().as_chunks::<8>().0.iter().enumerate() {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        denominator[index + 1] = u64::from_be_bytes(bytes);
    }

    add_one_u320(&mut denominator);

    //
    // 2^256 represented as five big-endian u64 limbs.
    //
    let numerator = [1_u64, 0, 0, 0, 0];

    let quotient = divide_u320(numerator, denominator)?;

    Some(Work([
        0,
        0,
        0,
        quotient[0],
        quotient[1],
        quotient[2],
        quotient[3],
        quotient[4],
    ]))
}

fn add_one_u320(value: &mut [u64; 5]) {
    for index in (0..value.len()).rev() {
        let (next, overflow) = value[index].overflowing_add(1);
        value[index] = next;

        if !overflow {
            return;
        }
    }
}

fn divide_u320(numerator: [u64; 5], denominator: [u64; 5]) -> Option<[u64; 5]> {
    if denominator.iter().all(|limb| *limb == 0) {
        return None;
    }

    let mut quotient = [0_u64; 5];
    let mut remainder = [0_u64; 5];

    //
    // Binary long division, most-significant bit first.
    //
    for bit_index in 0..320 {
        shift_left_one_u320(&mut remainder);

        if bit_u320(&numerator, bit_index) {
            remainder[4] |= 1;
        }

        if remainder >= denominator {
            remainder = subtract_u320(remainder, denominator);
            set_bit_u320(&mut quotient, bit_index);
        }
    }

    Some(quotient)
}

fn shift_left_one_u320(value: &mut [u64; 5]) {
    let mut carry = 0_u64;

    for index in (0..value.len()).rev() {
        let next_carry = value[index] >> 63;

        value[index] = (value[index] << 1) | carry;

        carry = next_carry;
    }

    //
    // During division the remainder is bounded by the
    // 257-bit denominator, so a 320-bit temporary cannot overflow.
    //
    debug_assert_eq!(carry, 0);
}

fn bit_u320(value: &[u64; 5], bit_index: usize) -> bool {
    let limb = bit_index / 64;
    let offset = 63 - (bit_index % 64);

    ((value[limb] >> offset) & 1) != 0
}

fn set_bit_u320(value: &mut [u64; 5], bit_index: usize) {
    let limb = bit_index / 64;
    let offset = 63 - (bit_index % 64);

    value[limb] |= 1_u64 << offset;
}

fn subtract_u320(mut left: [u64; 5], right: [u64; 5]) -> [u64; 5] {
    debug_assert!(left >= right);

    let mut borrow = false;

    for index in (0..left.len()).rev() {
        let (value, first_borrow) = left[index].overflowing_sub(right[index]);

        let (value, second_borrow) = value.overflowing_sub(u64::from(borrow));

        left[index] = value;

        borrow = first_borrow || second_borrow;
    }

    debug_assert!(!borrow);

    left
}
