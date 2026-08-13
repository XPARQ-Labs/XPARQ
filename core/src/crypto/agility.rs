//! Consensus-facing cryptographic-agility registry and activation policy.
//!
//! Registration does not imply activation. Upgrade plans are deterministic
//! consensus data: nodes derive the same policy from the block height and the
//! protocol-approved plan.

use borsh::{BorshDeserialize, BorshSerialize};

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum SignatureScheme {
    MlDsa44 = 1,
    MlDsa65 = 2,
    MlDsa87 = 3,
    SqisignLevel5 = 4,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum HashScheme {
    Sha3_256 = 1,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum PoWScheme {
    Argon2id = 1,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoPrimitive {
    Signature(SignatureScheme),
    Hash(HashScheme),
    PoW(PoWScheme),
}

impl CryptoPrimitive {
    pub const fn family(self) -> CryptoPrimitiveFamily {
        match self {
            Self::Signature(_) => CryptoPrimitiveFamily::Signature,
            Self::Hash(_) => CryptoPrimitiveFamily::Hash,
            Self::PoW(_) => CryptoPrimitiveFamily::PoW,
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum CryptoPrimitiveFamily {
    Signature = 1,
    Hash = 2,
    PoW = 3,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoUpgradePlan {
    /// Protocol event or release record that authorized this upgrade.
    pub authorization_id: [u8; 32],
    pub from: CryptoPrimitive,
    pub to: CryptoPrimitive,
    /// First height at which both primitives are accepted.
    pub transition_height: u64,
    /// First height at which only the replacement primitive is accepted.
    pub activation_height: u64,
    /// XPARQ uses one canonical protocol format version.
    pub protocol_version: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoUpgradeError {
    PrimitiveFamilyMismatch,
    NoPrimitiveChange,
    InvalidActivationWindow,
    MissingAuthorization,
    UnsupportedProtocolVersion,
}

impl CryptoUpgradePlan {
    pub fn validate(self, current_protocol_version: u8) -> Result<(), CryptoUpgradeError> {
        if self.from.family() != self.to.family() {
            return Err(CryptoUpgradeError::PrimitiveFamilyMismatch);
        }
        if self.from == self.to {
            return Err(CryptoUpgradeError::NoPrimitiveChange);
        }
        if self.transition_height >= self.activation_height {
            return Err(CryptoUpgradeError::InvalidActivationWindow);
        }
        if self.authorization_id == [0; 32] {
            return Err(CryptoUpgradeError::MissingAuthorization);
        }
        if self.protocol_version != 1 || current_protocol_version != 1 {
            return Err(CryptoUpgradeError::UnsupportedProtocolVersion);
        }
        Ok(())
    }

    pub const fn phase_at(self, height: u64) -> CryptoUpgradePhase {
        if height < self.transition_height {
            CryptoUpgradePhase::LegacyOnly
        } else if height < self.activation_height {
            CryptoUpgradePhase::Transition
        } else {
            CryptoUpgradePhase::UpgradedOnly
        }
    }

    pub fn permits(self, primitive: CryptoPrimitive, height: u64) -> bool {
        match self.phase_at(height) {
            CryptoUpgradePhase::LegacyOnly => primitive == self.from,
            CryptoUpgradePhase::Transition => primitive == self.from || primitive == self.to,
            CryptoUpgradePhase::UpgradedOnly => primitive == self.to,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoUpgradePhase {
    LegacyOnly,
    Transition,
    UpgradedOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureSchemeStatus {
    Active,
    CandidateInactive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SignatureContext {
    ProtocolTransaction = 1,
    QCashTransaction = 2,
    RecoveryProof = 3,
}

#[cfg(not(feature = "sqisign-blockchain-test"))]
pub const INITIAL_SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::MlDsa44;
#[cfg(feature = "sqisign-blockchain-test")]
pub const INITIAL_SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::SqisignLevel5;

pub const fn signature_scheme_status(scheme: SignatureScheme) -> SignatureSchemeStatus {
    if scheme as u8 == INITIAL_SIGNATURE_SCHEME as u8 {
        SignatureSchemeStatus::Active
    } else {
        SignatureSchemeStatus::CandidateInactive
    }
}

/// Compatibility gate for chains without an authorized upgrade plan.
pub const fn signature_scheme_active_for_consensus(scheme: SignatureScheme) -> bool {
    matches!(
        signature_scheme_status(scheme),
        SignatureSchemeStatus::Active
    )
}

/// Height-aware consensus gate. The plan must already have passed
/// [`CryptoUpgradePlan::validate`] and protocol authorization checks.
pub fn signature_scheme_active_at_height(
    scheme: SignatureScheme,
    height: u64,
    plan: Option<CryptoUpgradePlan>,
) -> bool {
    match plan {
        Some(plan) => plan.permits(CryptoPrimitive::Signature(scheme), height),
        None => scheme as u8 == INITIAL_SIGNATURE_SCHEME as u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNATURE_UPGRADE: CryptoUpgradePlan = CryptoUpgradePlan {
        authorization_id: [7; 32],
        from: CryptoPrimitive::Signature(SignatureScheme::MlDsa44),
        to: CryptoPrimitive::Signature(SignatureScheme::MlDsa87),
        transition_height: 100,
        activation_height: 200,
        protocol_version: 1,
    };

    #[test]
    fn signature_upgrade_has_deterministic_three_phase_policy() {
        SIGNATURE_UPGRADE.validate(1).unwrap();
        assert_eq!(
            SIGNATURE_UPGRADE.phase_at(99),
            CryptoUpgradePhase::LegacyOnly
        );
        assert_eq!(
            SIGNATURE_UPGRADE.phase_at(100),
            CryptoUpgradePhase::Transition
        );
        assert_eq!(
            SIGNATURE_UPGRADE.phase_at(199),
            CryptoUpgradePhase::Transition
        );
        assert_eq!(
            SIGNATURE_UPGRADE.phase_at(200),
            CryptoUpgradePhase::UpgradedOnly
        );
        assert!(signature_scheme_active_at_height(
            SignatureScheme::MlDsa44,
            99,
            Some(SIGNATURE_UPGRADE)
        ));
        assert!(signature_scheme_active_at_height(
            SignatureScheme::MlDsa87,
            100,
            Some(SIGNATURE_UPGRADE)
        ));
        assert!(!signature_scheme_active_at_height(
            SignatureScheme::MlDsa44,
            200,
            Some(SIGNATURE_UPGRADE)
        ));
    }

    #[test]
    fn rejects_unsafe_or_ambiguous_upgrade_plans() {
        let mut plan = SIGNATURE_UPGRADE;
        plan.authorization_id = [0; 32];
        assert_eq!(
            plan.validate(1),
            Err(CryptoUpgradeError::MissingAuthorization)
        );

        let mut plan = SIGNATURE_UPGRADE;
        plan.activation_height = plan.transition_height;
        assert_eq!(
            plan.validate(1),
            Err(CryptoUpgradeError::InvalidActivationWindow)
        );

        let mut plan = SIGNATURE_UPGRADE;
        plan.to = CryptoPrimitive::Hash(HashScheme::Sha3_256);
        assert_eq!(
            plan.validate(1),
            Err(CryptoUpgradeError::PrimitiveFamilyMismatch)
        );
    }
}
