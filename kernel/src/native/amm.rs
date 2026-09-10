use super::pool::{
    FEE_DENOMINATOR, Liquidity, PoolAmount, PoolError, ensure_amount, ensure_liquidity,
};

pub fn quote(
    amount: PoolAmount,
    reserve_in: PoolAmount,
    reserve_out: PoolAmount,
) -> Result<PoolAmount, PoolError> {
    ensure_amount(amount)?;
    ensure_amount(reserve_in)?;
    ensure_amount(reserve_out)?;
    let value = amount
        .as_raw()
        .checked_mul(reserve_out.as_raw())
        .ok_or(PoolError::ArithmeticOverflow)?
        / reserve_in.as_raw();
    nonzero(value)
}

/// Calculates constant-product swap output using parts-per-100,000 fees.
///
/// The fee scale is retained until the final division, avoiding precision loss
/// from an early integer division.
///
/// # Example
///
/// ```
/// use kernel::native::{PoolAmount, amm::amount_out};
///
/// let output = amount_out(
///     PoolAmount::from_raw(1_000_000),
///     PoolAmount::from_raw(10_000_000),
///     PoolAmount::from_raw(20_000_000),
///     300, // 0.30%
/// )?;
///
/// assert_eq!(output, PoolAmount::from_raw(1_813_221));
/// # Ok::<(), kernel::native::PoolError>(())
/// ```
pub fn amount_out(
    amount_in: PoolAmount,
    reserve_in: PoolAmount,
    reserve_out: PoolAmount,
    fee_units: u32,
) -> Result<PoolAmount, PoolError> {
    ensure_amount(amount_in)?;
    ensure_amount(reserve_in)?;
    ensure_amount(reserve_out)?;
    if fee_units >= FEE_DENOMINATOR {
        return Err(PoolError::InvalidFee);
    }

    let denominator = u128::from(FEE_DENOMINATOR);
    // Example for amount_in = 1_000_000 and fee_units = 300:
    // amount_in_with_fee = 1_000_000 * 99_700 = 99_700_000_000.
    // It is intentionally still scaled by FEE_DENOMINATOR, not 997_000.
    let amount_in_with_fee = amount_in
        .as_raw()
        .checked_mul(u128::from(FEE_DENOMINATOR - fee_units))
        .ok_or(PoolError::ArithmeticOverflow)?;
    let numerator = amount_in_with_fee
        .checked_mul(reserve_out.as_raw())
        .ok_or(PoolError::ArithmeticOverflow)?;
    let divisor = reserve_in
        .as_raw()
        .checked_mul(denominator)
        .and_then(|value| value.checked_add(amount_in_with_fee))
        .ok_or(PoolError::ArithmeticOverflow)?;
    nonzero(numerator / divisor)
}

pub fn initial_liquidity(
    amount_x: PoolAmount,
    amount_y: PoolAmount,
) -> Result<Liquidity, PoolError> {
    ensure_amount(amount_x)?;
    ensure_amount(amount_y)?;
    let product = amount_x
        .as_raw()
        .checked_mul(amount_y.as_raw())
        .ok_or(PoolError::ArithmeticOverflow)?;
    nonzero_liquidity(integer_sqrt(product))
}

pub fn liquidity_minted(
    amount_x: PoolAmount,
    amount_y: PoolAmount,
    reserve_x: PoolAmount,
    reserve_y: PoolAmount,
    total_liquidity: Liquidity,
) -> Result<Liquidity, PoolError> {
    for amount in [amount_x, amount_y, reserve_x, reserve_y] {
        ensure_amount(amount)?;
    }
    ensure_liquidity(total_liquidity)?;
    let from_x = amount_x
        .as_raw()
        .checked_mul(total_liquidity.as_raw())
        .ok_or(PoolError::ArithmeticOverflow)?
        / reserve_x.as_raw();
    let from_y = amount_y
        .as_raw()
        .checked_mul(total_liquidity.as_raw())
        .ok_or(PoolError::ArithmeticOverflow)?
        / reserve_y.as_raw();
    nonzero_liquidity(from_x.min(from_y))
}

pub fn liquidity_removed(
    liquidity: Liquidity,
    reserve_x: PoolAmount,
    reserve_y: PoolAmount,
    total_liquidity: Liquidity,
) -> Result<(PoolAmount, PoolAmount), PoolError> {
    for amount in [reserve_x, reserve_y] {
        ensure_amount(amount)?;
    }
    ensure_liquidity(liquidity)?;
    ensure_liquidity(total_liquidity)?;
    if liquidity > total_liquidity {
        return Err(PoolError::InsufficientLiquidity);
    }
    let amount_x = liquidity
        .as_raw()
        .checked_mul(reserve_x.as_raw())
        .ok_or(PoolError::ArithmeticOverflow)?
        / total_liquidity.as_raw();
    let amount_y = liquidity
        .as_raw()
        .checked_mul(reserve_y.as_raw())
        .ok_or(PoolError::ArithmeticOverflow)?
        / total_liquidity.as_raw();
    Ok((nonzero(amount_x)?, nonzero(amount_y)?))
}

fn nonzero(value: u128) -> Result<PoolAmount, PoolError> {
    if value == 0 {
        Err(PoolError::InsufficientOutput)
    } else {
        Ok(PoolAmount::from_raw(value))
    }
}

fn nonzero_liquidity(value: u128) -> Result<Liquidity, PoolError> {
    if value == 0 {
        Err(PoolError::InsufficientOutput)
    } else {
        Ok(Liquidity::from_raw(value))
    }
}

fn integer_sqrt(value: u128) -> u128 {
    if value < 2 {
        return value;
    }
    let mut x = value;
    let mut y = x / 2 + 1;
    while y < x {
        x = y;
        y = (x + value / x) / 2;
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;
    fn amount(value: u128) -> PoolAmount {
        PoolAmount::from_raw(value)
    }

    #[test]
    fn constant_product_swap_applies_fee() {
        assert_eq!(
            amount_out(amount(1_000), amount(10_000), amount(20_000), 300),
            Ok(amount(1_813))
        );
    }

    #[test]
    fn liquidity_math_uses_integer_rounding() {
        assert_eq!(
            initial_liquidity(amount(10_000), amount(40_000)),
            Ok(Liquidity::from_raw(20_000))
        );
        assert_eq!(
            liquidity_minted(
                amount(1_000),
                amount(2_000),
                amount(10_000),
                amount(20_000),
                Liquidity::from_raw(5_000)
            ),
            Ok(Liquidity::from_raw(500))
        );
        assert_eq!(
            liquidity_removed(
                Liquidity::from_raw(500),
                amount(11_000),
                amount(22_000),
                Liquidity::from_raw(5_500)
            ),
            Ok((amount(1_000), amount(2_000)))
        );
    }

    #[test]
    fn rejects_zero_and_overflow() {
        assert_eq!(
            quote(PoolAmount::ZERO, amount(1), amount(1)),
            Err(PoolError::InvalidAmount)
        );
        assert_eq!(
            initial_liquidity(amount(u128::MAX), amount(2)),
            Err(PoolError::ArithmeticOverflow)
        );
    }
}
