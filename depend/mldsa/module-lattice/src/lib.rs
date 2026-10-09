#![no_std]
#![allow(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]

#[cfg(feature = "alloc")]
extern crate alloc;

/// Linear algebra with degree-256 polynomials over a prime-order field, vectors of such
/// polynomials, and NTT polynomials / vectors.
mod algebra;

/// Packing of polynomials into coefficients with a specified number of bits.
mod encoding;

/// Support for optional heap offload gated on the `alloc` feature.
mod maybe_box;

/// Integer truncation support.
mod truncate;

pub use algebra::{
    Elem, Field, MultiplyNtt, NttMatrix, NttPolynomial, NttVector, Polynomial, Vector,
};
pub use encoding::{
    ArraySize, DecodedValue, Encode, EncodedPolynomial, EncodedPolynomialSize, EncodedVector,
    EncodedVectorSize, EncodingSize, VectorEncodingSize, byte_decode, byte_encode,
};
pub use maybe_box::MaybeBox;
pub use truncate::Truncate;

#[cfg(feature = "ctutils")]
pub use ctutils;
