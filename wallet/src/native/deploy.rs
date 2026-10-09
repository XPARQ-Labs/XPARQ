use super::rpc::fetch_account;
use super::*;
use kernel::{
    operation::{AuthorizedDeployProgram, BlockOperation, BlockOperationRef},
    program::DeployProgram,
};

const MAX_DEPLOY_INPUTS: usize = 256;

pub(super) fn deploy_program(args: &[String]) -> Result<(), String> {
    if option(args, "--miner").is_some() {
        return Err("deploy miner fee is calculated automatically".into());
    }
    let code_path = option(args, "--code").ok_or("missing --code PATH")?;
    let nonce: u64 = option(args, "--nonce")
        .ok_or("missing --nonce")?
        .parse()
        .map_err(|_| "invalid --nonce")?;
    let code = fs::read(code_path).map_err(|e| format!("read {code_path}: {e}"))?;
    let wallet = load_wallet(option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH))?;
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let deploy = DeployProgram {
        owner: wallet.program_id(),
        nonce,
        code: code.into(),
    };
    deploy
        .validate_structure()
        .map_err(|e| format!("invalid XPVM program: {e:?}"))?;
    let program_id = kernel::crypto::program_id_to_string(&wallet.program_id());
    let account = fetch_account(rpc, &program_id)?;
    let mut candidates = account
        .utxos
        .into_iter()
        .filter(|utxo| !utxo.reserved)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        right
            .amount
            .cmp(&left.amount)
            .then_with(|| left.id.cmp(&right.id))
    });
    let mut inputs = Vec::new();
    let mut total = 0u64;
    for utxo in candidates.into_iter().take(MAX_DEPLOY_INPUTS) {
        inputs.push(
            utxo.id
                .parse::<CoinShare>()
                .map_err(|_| "node returned an invalid coin share")?,
        );
        total = total
            .checked_add(utxo.amount)
            .ok_or("selected coin amount overflow")?;
        if let Some((signed, quote, burn, fee)) =
            quote_selected(rpc, &wallet, &deploy, &inputs, total)?
        {
            drop(wallet);
            let bytes = canonical_bytes(&signed).map_err(|e| e.to_string())?;
            let operation = BlockOperation::DeployProgram(Box::new(signed));
            println!(
                "Program ID: {}",
                quote["program_id"].as_str().unwrap_or("?")
            );
            println!("Protocol burn: {burn} zeno");
            println!("Miner fee: {fee} zeno");
            if has_flag(args, "--offline") {
                println!("Deploy Borsh Hex: {}", hex::encode(&bytes));
            } else {
                let submitted: serde_json::Value = http_post_bytes(rpc, "/program/deploy", &bytes)?;
                let id = submitted["operation_id"]
                    .as_str()
                    .ok_or("node returned no operation ID")?;
                let expected = hex::encode(operation.id().map_err(|e| e.to_string())?.into_bytes());
                if id != expected {
                    return Err("node returned a different operation ID".into());
                }
                println!("Operation ID: {id}");
            }
            return Ok(());
        }
    }
    Err("insufficient available coins for deploy burn and miner fee".into())
}

fn quote_selected(
    rpc: &str,
    wallet: &LoadedWallet,
    deploy: &DeployProgram,
    inputs: &[CoinShare],
    total: u64,
) -> Result<Option<(AuthorizedDeployProgram, serde_json::Value, u64, u64)>, String> {
    let mut burn = 0u64;
    let mut fee = AUTOMATIC_FEE_ZENO_PER_BYTE;
    let mut tip: Option<(serde_json::Value, serde_json::Value)> = None;
    for _ in 0..MAX_FEE_CONVERGENCE_ROUNDS {
        let Some(change) = total.checked_sub(burn).and_then(|v| v.checked_sub(fee)) else {
            return Ok(None);
        };
        let outputs = if change == 0 {
            vec![]
        } else {
            vec![CoinOutput::new(
                wallet.program_id(),
                Zeno::from_zeno(change),
            )]
        };
        let payment = CoinTransition::coin_with_charges(
            wallet.program_id(),
            inputs.to_vec(),
            outputs,
            CoinCharges::new(Zeno::from_zeno(fee)),
        )
        .map_err(|e| e.to_string())?;
        let signed = wallet.0.sign_deploy_program(deploy.clone(), payment)?;
        let quote: serde_json::Value = http_post_bytes(
            rpc,
            "/program/deploy/quote",
            &canonical_bytes(&signed).map_err(|e| e.to_string())?,
        )?;
        let this_tip = (quote["height"].clone(), quote["tip_hash"].clone());
        if tip.as_ref().is_some_and(|previous| *previous != this_tip) {
            return Err("chain tip changed while quoting deploy; retry".into());
        }
        tip = Some(this_tip);
        let required_burn = quote["required_protocol_burn"]
            .as_u64()
            .ok_or("node returned invalid deploy burn")?;
        let required_fee =
            kernel::crypto::canonical_length(&BlockOperationRef::DeployProgram(&signed))
                .map_err(|e| e.to_string())?
                .checked_mul(AUTOMATIC_FEE_ZENO_PER_BYTE)
                .ok_or("deploy miner fee overflow")?;
        if required_burn == burn && required_fee == fee {
            let commitment = signed
                .commitment(kernel::genesis::chain_context().map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            if quote["authorization_commitment"].as_str()
                != Some(hex::encode(commitment.as_bytes()).as_str())
            {
                return Err("node quote commitment differs from wallet commitment".into());
            }
            return Ok(Some((signed, quote, burn, fee)));
        }
        burn = required_burn;
        fee = required_fee;
    }
    Err("deploy fee quote did not converge".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_deploy_signature_binds_code_and_payment() {
        let wallet = wallet::account_wallet_from_bip39_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            kernel::crypto::AccountSignatureScheme::MlDsa44,
        )
        .unwrap();
        let mut code = b"XPVM".to_vec();
        code.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0, 0]);
        code.push(1);
        code.extend_from_slice(&7i64.to_le_bytes());
        code.push(3);
        let program = DeployProgram {
            owner: wallet.program_id,
            nonce: 1,
            code: code.into(),
        };
        let payment = CoinTransition::coin_with_charges(
            wallet.program_id,
            vec![CoinShare::from_bytes([3; kernel::crypto::HASH_SIZE])],
            vec![CoinOutput::new(wallet.program_id, Zeno::from_zeno(90))],
            CoinCharges::new(Zeno::from_zeno(10)),
        )
        .unwrap();
        let mut signed = wallet.sign_deploy_program(program, payment).unwrap();
        let counted =
            kernel::crypto::canonical_length(&BlockOperationRef::DeployProgram(&signed)).unwrap();
        let historical = canonical_bytes(&BlockOperation::DeployProgram(Box::new(signed.clone())))
            .unwrap()
            .len() as u64;
        assert_eq!(
            counted * AUTOMATIC_FEE_ZENO_PER_BYTE,
            historical * AUTOMATIC_FEE_ZENO_PER_BYTE
        );
        let chain = kernel::genesis::chain_context().unwrap();
        let commitment = signed.commitment(chain).unwrap();
        assert!(
            signed
                .authorization
                .verify_commitment(wallet.program_id, &commitment, 1)
        );
        signed.deploy.nonce += 1;
        let changed = signed.commitment(chain).unwrap();
        assert!(
            !signed
                .authorization
                .verify_commitment(wallet.program_id, &changed, 1)
        );
    }
}
