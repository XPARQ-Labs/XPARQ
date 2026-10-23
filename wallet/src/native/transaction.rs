use super::rpc::fetch_account;
use super::*;

pub(super) fn sign_spend(args: &[String]) -> Result<(), String> {
    reject_manual_fee(args)?;
    if option(args, "--salt").is_some() {
        return Err(
            "sign-spend does not accept --salt; use --legacy-salt for one legacy transfer".into(),
        );
    }
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let (payment_outputs, total_amount) = coin_transfer_outputs(args)?;
    let created_coin_without_change = u64::try_from(payment_outputs.len())
        .map_err(|_| "coin output count overflow")?
        .checked_add(1)
        .ok_or("coin output count overflow")?;
    let inputs = repeated_options(args, "--input")
        .into_iter()
        .map(kernel::monetary::coin::CoinShare::from_str)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid --input coin id".to_string())?;
    let legacy_salt = option(args, "--legacy-salt")
        .map(wallet::transfer_salt32_from_string)
        .transpose()?;
    let mut wallet = if let Some(salt) = legacy_salt.as_ref() {
        load_wallet_for_legacy_transfer(path, salt)?
    } else {
        load_wallet(path)?
    };
    let legacy_program_id = legacy_salt
        .as_ref()
        .map(|salt| {
            kernel::crypto::program_id_from_public_key_with_authorization_salt(
                &wallet.0.public_key,
                salt,
            )
            .map_err(|error| error.to_string())
        })
        .transpose()?;
    let rpc = option(args, "--rpc").unwrap_or(default_rpc_addr());
    let explicit_change = option(args, "--change").map(parse_amount).transpose()?;
    let change_target = option(args, "--change-to")
        .map(|program_id| program_id_from_string(program_id).map_err(|error| error.to_string()))
        .transpose()?;
    if inputs.is_empty() && (explicit_change.is_some() || change_target.is_some()) {
        return Err("automatic input selection also calculates change automatically".into());
    }
    let account_candidates = if inputs.is_empty() && legacy_salt.is_none() {
        Some(wallet_account_input_candidates(rpc, &wallet)?)
    } else {
        None
    };
    let legacy_candidates = if inputs.is_empty() {
        legacy_program_id
            .map(|program_id| account_input_candidates_for_program(rpc, program_id))
            .transpose()?
    } else {
        None
    };
    let initially_active_salt = wallet.0.account_salt;
    let transaction = automatic_fee_transaction(|fee, archival_burn| {
        let required = total_amount
            .checked_add(fee)
            .ok_or("transaction amount plus fee overflow")?;
        let (selected, change, _state_burn, change_program_id, signer) = if inputs.is_empty() {
            if let Some(legacy_program_id) = legacy_program_id {
                let candidates = legacy_candidates
                    .as_ref()
                    .ok_or("legacy transfer account candidates are unavailable")?;
                let available = candidates.iter().try_fold(0_u64, |total, utxo| {
                    total
                        .checked_add(utxo.amount)
                        .ok_or_else(|| "available account balance overflow".to_string())
                })?;
                let (selected, _total, state_burn, change) = select_inputs_from_candidates(
                    candidates,
                    required,
                    created_coin_without_change,
                    0,
                    archival_burn,
                    0,
                )?
                .ok_or_else(|| {
                    format!(
                        "insufficient available balance in legacy transfer account: available {available} units"
                    )
                })?;
                (
                    selected,
                    change,
                    state_burn,
                    legacy_program_id,
                    legacy_program_id,
                )
            } else {
                let account_candidates = account_candidates
                    .as_ref()
                    .ok_or("wallet account candidates are unavailable")?;
                let (salt, program_id, selected, _total, state_burn, change) =
                    select_wallet_account_inputs_with_state_burn(
                        account_candidates,
                        required,
                        created_coin_without_change,
                        0,
                        archival_burn,
                        initially_active_salt,
                    )?;
                wallet.0.select_account(salt)?;
                (selected, change, state_burn, program_id, program_id)
            }
        } else {
            let gross_change = explicit_change.map_or(0, Zeno::as_zeno);
            let created = created_coin_without_change + u64::from(gross_change > fee);
            let state_burn = StateTransitionWeight {
                created_coin_utxos: created,
                consumed_coin_utxos: u64::try_from(inputs.len())
                    .map_err(|_| "coin input count overflow")?,
                ..StateTransitionWeight::default()
            }
            .state_growth_burn()
            .map_err(|error| error.to_string())?
            .as_zeno()
            .checked_add(archival_burn)
            .ok_or("state burn plus transaction archival burn overflow")?;
            let change = gross_change
                .checked_sub(fee)
                .and_then(|change| change.checked_sub(state_burn))
                .ok_or("explicit change is smaller than the automatic fee and state burn")?;
            let signer = legacy_program_id.unwrap_or(wallet.program_id());
            (
                inputs.clone(),
                change,
                state_burn,
                change_target.unwrap_or(signer),
                signer,
            )
        };
        let mut outputs = payment_outputs.clone();
        if change > 0 {
            outputs.push(CoinOutput::new(change_program_id, Zeno::from_zeno(change)));
        }
        let intent = CoinTransition::coin_with_charges(
            signer,
            selected,
            outputs,
            CoinCharges::new(Zeno::from_zeno(fee)),
        )
        .map_err(|error| error.to_string())?;
        let signed = if let Some(salt) = legacy_salt {
            wallet.sign_legacy_onchain_spend(salt, intent)?
        } else {
            wallet.sign_onchain_spend(intent)?
        };
        Ok(AuthorizedProgramEnvelope::Program(Box::new(signed)))
    })?;
    let AuthorizedProgramEnvelope::Program(invocation) = &transaction;
    if legacy_salt.is_some() {
        println!("Using legacy 32-byte salt for this XPQ transfer");
    } else {
        println!("Using wallet Program ID: {}", invocation.signer);
    }
    drop(wallet);
    if has_flag(args, "--offline") {
        let AuthorizedProgramEnvelope::Program(tx) = &transaction;
        let fee = tx.payment.charges.miner_fee.as_zeno();
        let state_burn = StateTransitionWeight {
            created_coin_utxos: tx.payment.outputs.len() as u64 + u64::from(fee > 0),
            consumed_coin_utxos: tx.payment.inputs.len() as u64,
            ..StateTransitionWeight::default()
        }
        .state_growth_burn()
        .map_err(|e| e.to_string())?
        .as_zeno();
        let archival_burn = kernel::crypto::canonical_length(&transaction)
            .map_err(|e| e.to_string())?
            .checked_mul(kernel::consensus::STATE_BURN_RATE_ZENO_PER_BYTE)
            .ok_or("transaction burn overflow")?;
        let burn = archival_burn
            .checked_add(state_burn)
            .ok_or("transaction burn overflow")?;
        println!("Miner Fee: {}", format_amount(fee));
        println!("Protocol Burn: {}", format_amount(burn));
    }
    submit_or_print_transaction(args, &transaction)
}

fn coin_transfer_outputs(args: &[String]) -> Result<(Vec<CoinOutput>, u64), String> {
    let entries = repeated_options(args, "--output");
    if entries.is_empty() {
        let recipient = option(args, "--to")
            .map(super::util::parse_owner)
            .transpose()?
            .ok_or("missing --to or --output")?;
        let amount = parse_amount(option(args, "--amount").ok_or("missing --amount")?)?;
        let outputs = vec![CoinOutput::to_owner(recipient, amount)];
        let total = amount.as_zeno();
        return Ok((outputs, total));
    }
    if option(args, "--to").is_some() || option(args, "--amount").is_some() {
        return Err("do not combine --output with --to or --amount".into());
    }
    parse_coin_output_options(args, "--output")
}

pub(super) fn parse_coin_output_options(
    args: &[String],
    option_name: &str,
) -> Result<(Vec<CoinOutput>, u64), String> {
    let entries = repeated_options(args, option_name);
    if entries.len() > MAX_BATCH_TRANSFER_OUTPUTS {
        return Err(format!(
            "coin batch transfer supports at most {MAX_BATCH_TRANSFER_OUTPUTS} recipients"
        ));
    }
    let outputs = entries
        .into_iter()
        .map(|entry| {
            let (recipient, amount) = entry
                .split_once('=')
                .ok_or_else(|| format!("{option_name} must use PROGRAM_ID=AMOUNT"))?;
            if recipient.is_empty() || amount.is_empty() {
                return Err(format!("{option_name} must use PROGRAM_ID=AMOUNT"));
            }
            let recipient = program_id_from_string(recipient).map_err(|error| error.to_string())?;
            let amount = parse_amount(amount)?;
            Ok(CoinOutput::new(recipient, amount))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let total = outputs.iter().try_fold(0_u64, |total, output| {
        total
            .checked_add(output.amount.as_zeno())
            .ok_or_else(|| "coin batch transfer total overflow".to_string())
    })?;
    Ok((outputs, total))
}

pub(super) fn consolidate_coin_utxos(args: &[String]) -> Result<(), String> {
    reject_manual_fee(args)?;
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let rpc = option(args, "--rpc").unwrap_or(default_rpc_addr());
    let wallet = load_wallet(path)?;
    let mut candidates = account_input_candidates(rpc, &wallet)?;
    if candidates.len() < 2 {
        return Err("consolidation requires at least two available CoinShare UTXOs".into());
    }
    candidates.sort_by(|left, right| {
        left.amount
            .cmp(&right.amount)
            .then_with(|| left.id.cmp(&right.id))
    });
    candidates.truncate(MAX_CONSOLIDATION_INPUTS);
    let inputs = candidates
        .iter()
        .map(|utxo| {
            kernel::monetary::coin::CoinShare::from_str(&utxo.id)
                .map_err(|_| "node returned an invalid coin id".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let total = candidates.iter().try_fold(0_u64, |total, utxo| {
        total
            .checked_add(utxo.amount)
            .ok_or_else(|| "consolidation input amount overflow".to_string())
    })?;
    let consumed_coin_utxos =
        u64::try_from(inputs.len()).map_err(|_| "coin input count overflow")?;

    let transaction = automatic_fee_transaction(|fee, archival_burn| {
        let state_growth_burn = StateTransitionWeight {
            created_coin_utxos: 2,
            consumed_coin_utxos,
            ..StateTransitionWeight::default()
        }
        .state_growth_burn()
        .map_err(|error| error.to_string())?
        .as_zeno();
        let protocol_burn = archival_burn
            .checked_add(state_growth_burn)
            .ok_or("consolidation protocol burn overflow")?;
        let consolidated = total
            .checked_sub(fee)
            .and_then(|amount| amount.checked_sub(protocol_burn))
            .filter(|amount| *amount > 0)
            .ok_or("UTXO total is insufficient for consolidation fee and protocol burn")?;
        let outputs = vec![CoinOutput::new(
            wallet.program_id(),
            Zeno::from_zeno(consolidated),
        )];
        let intent = CoinTransition::coin_with_charges(
            wallet.program_id(),
            inputs.clone(),
            outputs,
            CoinCharges::new(Zeno::from_zeno(fee)),
        )
        .map_err(|error| error.to_string())?;
        let signed = wallet.sign_onchain_spend(intent)?;
        Ok(AuthorizedProgramEnvelope::Program(Box::new(signed)))
    })?;
    drop(wallet);
    submit_or_print_transaction(args, &transaction)
}

pub(super) struct LegacyMigrationPreview {
    pub(super) transaction: AuthorizedProgramEnvelope,
    pub(super) source_program_id: ProgramId,
    pub(super) destination_program_id: ProgramId,
    pub(super) available: u64,
    pub(super) destination_amount: u64,
    pub(super) miner_fee: u64,
    pub(super) protocol_burn: u64,
}

pub(super) fn prepare_legacy_migration(args: &[String]) -> Result<LegacyMigrationPreview, String> {
    reject_manual_fee(args)?;
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let salt = wallet::transfer_salt32_from_string(
        option(args, "--legacy-salt").ok_or("missing --legacy-salt HEX64")?,
    )?;
    let destination = option(args, "--to")
        .map(|value| program_id_from_string(value).map_err(|error| error.to_string()))
        .transpose()?
        .ok_or("missing destination --to PROGRAM_ID")?;
    let rpc = option(args, "--rpc").unwrap_or(default_rpc_addr());
    let wallet = load_wallet_for_legacy_transfer(path, &salt)?;
    let signer = kernel::crypto::program_id_from_public_key_with_authorization_salt(
        &wallet.0.public_key,
        &salt,
    )
    .map_err(|error| error.to_string())?;
    let candidates = account_input_candidates_for_program(rpc, signer)?;
    if candidates.is_empty() {
        return Err("legacy account has no available XPQ coins to migrate".into());
    }
    let total = candidates.iter().try_fold(0_u64, |total, utxo| {
        total
            .checked_add(utxo.amount)
            .ok_or_else(|| "legacy account balance overflow".to_string())
    })?;
    let inputs = candidates
        .iter()
        .map(|utxo| {
            kernel::monetary::coin::CoinShare::from_str(&utxo.id)
                .map_err(|_| "node returned an invalid coin id".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let consumed_coin_utxos =
        u64::try_from(inputs.len()).map_err(|_| "coin input count overflow")?;

    let mut destination_amount = 0_u64;
    let transaction = automatic_fee_transaction(|fee, archival_burn| {
        let state_burn = StateTransitionWeight {
            created_coin_utxos: 2,
            consumed_coin_utxos,
            ..StateTransitionWeight::default()
        }
        .state_growth_burn()
        .map_err(|error| error.to_string())?
        .as_zeno();
        let amount = total
            .checked_sub(fee)
            .and_then(|amount| amount.checked_sub(state_burn))
            .and_then(|amount| amount.checked_sub(archival_burn))
            .filter(|amount| *amount > 0)
            .ok_or("legacy account balance cannot cover the automatic fee and protocol burn")?;
        destination_amount = amount;
        let intent = CoinTransition::coin_with_charges(
            signer,
            inputs.clone(),
            vec![CoinOutput::new(destination, Zeno::from_zeno(amount))],
            CoinCharges::new(Zeno::from_zeno(fee)),
        )
        .map_err(|error| error.to_string())?;
        wallet
            .sign_legacy_onchain_spend(salt, intent)
            .map(|invocation| AuthorizedProgramEnvelope::Program(Box::new(invocation)))
    })?;
    let miner_fee = match &transaction {
        AuthorizedProgramEnvelope::Program(invocation) => {
            invocation.payment.charges.miner_fee.as_zeno()
        }
    };
    let protocol_burn = total
        .checked_sub(destination_amount)
        .and_then(|remaining| remaining.checked_sub(miner_fee))
        .ok_or("migration cost calculation underflow")?;
    drop(wallet);
    Ok(LegacyMigrationPreview {
        transaction,
        source_program_id: signer,
        destination_program_id: destination,
        available: total,
        destination_amount,
        miner_fee,
        protocol_burn,
    })
}

fn account_input_candidates(rpc: &str, wallet: &LoadedWallet) -> Result<Vec<AccountUtxo>, String> {
    account_input_candidates_for_program(rpc, wallet.program_id())
}

fn account_input_candidates_for_program(
    rpc: &str,
    program_id: ProgramId,
) -> Result<Vec<AccountUtxo>, String> {
    let program_id = kernel::crypto::program_id_to_string(&program_id);
    let response = fetch_account(rpc, &program_id)?;
    let mut candidates = response
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
    Ok(candidates)
}

fn wallet_account_input_candidates(
    rpc: &str,
    wallet: &LoadedWallet,
) -> Result<Vec<WalletAccountInputCandidates>, String> {
    wallet
        .0
        .account_salts
        .iter()
        .map(|salt| {
            let program_id =
                kernel::crypto::program_id_from_public_key_with_salt(&wallet.0.public_key, salt)
                    .map_err(|error| error.to_string())?;
            let utxos = account_input_candidates_for_program(rpc, program_id)?;
            Ok(WalletAccountInputCandidates {
                salt: *salt,
                program_id,
                utxos,
            })
        })
        .collect()
}

fn select_wallet_account_inputs_with_state_burn(
    accounts: &[WalletAccountInputCandidates],
    base_required: u64,
    created_coin_without_change: u64,
    created_state_weight: u64,
    archival_burn: u64,
    active_salt: kernel::crypto::AccountSalt,
) -> Result<
    (
        kernel::crypto::AccountSalt,
        ProgramId,
        Vec<kernel::monetary::coin::CoinShare>,
        u64,
        u64,
        u64,
    ),
    String,
> {
    let mut best: Option<(usize, Vec<kernel::monetary::coin::CoinShare>, u64, u64, u64)> = None;
    let mut balances = Vec::with_capacity(accounts.len());

    for (index, account) in accounts.iter().enumerate() {
        let available = account.utxos.iter().try_fold(0_u64, |total, utxo| {
            total
                .checked_add(utxo.amount)
                .ok_or_else(|| "available account balance overflow".to_string())
        })?;
        balances.push((account.program_id, available));

        let Some((selected, total, burn, change)) = select_inputs_from_candidates(
            &account.utxos,
            base_required,
            created_coin_without_change,
            created_state_weight,
            archival_burn,
            0,
        )?
        else {
            continue;
        };

        let preference = (change, selected.len(), account.salt != active_salt);
        let is_better =
            best.as_ref()
                .is_none_or(|(best_index, best_selected, _, _, best_change)| {
                    preference
                        < (
                            *best_change,
                            best_selected.len(),
                            accounts[*best_index].salt != active_salt,
                        )
                });
        if is_better {
            best = Some((index, selected, total, burn, change));
        }
    }

    if let Some((index, selected, total, burn, change)) = best {
        let account = &accounts[index];
        return Ok((
            account.salt,
            account.program_id,
            selected,
            total,
            burn,
            change,
        ));
    }

    let accounts = balances
        .iter()
        .map(|(program_id, balance)| format!("{program_id}: {balance} units"))
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "no single wallet account has enough available balance for amount, fee, and state burn; available by account: {accounts}"
    ))
}

pub(super) fn select_account_inputs_with_state_burn(
    rpc: &str,
    wallet: &LoadedWallet,
    base_required: u64,
    created_coin_without_change: u64,
    created_state_weight: u64,
    archival_burn: u64,
) -> Result<(Vec<kernel::monetary::coin::CoinShare>, u64, u64, u64), String> {
    select_account_inputs_with_vm_state_burn(
        rpc,
        wallet,
        base_required,
        created_coin_without_change,
        created_state_weight,
        archival_burn,
        0,
    )
}

pub(super) fn select_account_inputs_with_vm_state_burn(
    rpc: &str,
    wallet: &LoadedWallet,
    base_required: u64,
    created_coin_without_change: u64,
    created_state_weight: u64,
    archival_burn: u64,
    vm_consumed_coin_utxos: u64,
) -> Result<(Vec<kernel::monetary::coin::CoinShare>, u64, u64, u64), String> {
    let candidates = account_input_candidates(rpc, wallet)?;
    let available = candidates.iter().try_fold(0_u64, |total, utxo| {
        total
            .checked_add(utxo.amount)
            .ok_or_else(|| "available account balance overflow".to_string())
    })?;
    select_inputs_from_candidates(
        &candidates,
        base_required,
        created_coin_without_change,
        created_state_weight,
        archival_burn,
        vm_consumed_coin_utxos,
    )?
    .ok_or_else(|| {
        format!(
            "insufficient available balance for amount, fee, and state burn: available {available} units"
        )
    })
}

fn select_inputs_from_candidates(
    candidates: &[AccountUtxo],
    base_required: u64,
    created_coin_without_change: u64,
    created_state_weight: u64,
    archival_burn: u64,
    vm_consumed_coin_utxos: u64,
) -> Result<Option<(Vec<kernel::monetary::coin::CoinShare>, u64, u64, u64)>, String> {
    let mut selected = Vec::new();
    let mut total = 0_u64;
    for utxo in candidates {
        selected.push(
            kernel::monetary::coin::CoinShare::from_str(&utxo.id)
                .map_err(|_| "node returned an invalid coin id".to_string())?,
        );
        total = total
            .checked_add(utxo.amount)
            .ok_or_else(|| "selected input amount overflow".to_string())?;
        for has_change in [false, true] {
            let created = created_coin_without_change
                .checked_add(u64::from(has_change))
                .ok_or("state output count overflow")?;
            let ledger_burn = StateTransitionWeight {
                created_coin_utxos: created,
                consumed_coin_utxos: u64::try_from(selected.len())
                    .map_err(|_| "coin input count overflow")?
                    .checked_add(vm_consumed_coin_utxos)
                    .ok_or("VM input count overflow")?,
                created_state_weight,
                ..StateTransitionWeight::default()
            }
            .state_growth_burn()
            .map_err(|error| error.to_string())?
            .as_zeno();
            let burn = ledger_burn
                .checked_add(archival_burn)
                .ok_or("state burn plus transaction archival burn overflow")?;
            let required = base_required
                .checked_add(burn)
                .ok_or("required amount plus state burn overflow")?;
            let valid = if has_change {
                total > required
            } else {
                total == required
            };
            if valid {
                return Ok(Some((selected, total, burn, total - required)));
            }
        }
    }
    Ok(None)
}

pub(super) fn reject_manual_fee(args: &[String]) -> Result<(), String> {
    if option(args, "--miner").is_some() {
        return Err(format!(
            "--miner is no longer supported; wallet fee is automatic at {AUTOMATIC_FEE_ZENO_PER_BYTE} zeno/byte"
        ));
    }
    Ok(())
}

pub(super) fn automatic_fee_transaction(
    build: impl FnMut(u64, u64) -> Result<AuthorizedProgramEnvelope, String>,
) -> Result<AuthorizedProgramEnvelope, String> {
    automatic_fee_transaction_at_rates(
        build,
        AUTOMATIC_FEE_ZENO_PER_BYTE,
        kernel::consensus::STATE_BURN_RATE_ZENO_PER_BYTE,
    )
}

fn automatic_fee_transaction_at_rates(
    mut build: impl FnMut(u64, u64) -> Result<AuthorizedProgramEnvelope, String>,
    miner_fee_rate: u64,
    archival_burn_rate: u64,
) -> Result<AuthorizedProgramEnvelope, String> {
    let mut fee = miner_fee_rate;
    let mut archival_burn = 0_u64;
    for _ in 0..MAX_FEE_CONVERGENCE_ROUNDS {
        let transaction = build(fee, archival_burn)?;
        let size =
            kernel::crypto::canonical_length(&transaction).map_err(|error| error.to_string())?;
        let required_fee = size
            .checked_mul(miner_fee_rate)
            .ok_or("automatic transaction fee overflow")?;
        let required_archival = size
            .checked_mul(archival_burn_rate)
            .ok_or("transaction archival burn overflow")?;
        if required_fee == fee && required_archival == archival_burn {
            return Ok(transaction);
        }
        fee = required_fee;
        archival_burn = required_archival;
    }
    Err("automatic transaction fee did not converge".into())
}

pub(super) fn submit_or_print_transaction(
    args: &[String],
    transaction: &AuthorizedProgramEnvelope,
) -> Result<(), String> {
    let chain = kernel::genesis::chain_context().map_err(|error| error.to_string())?;

    let authorization_valid = transaction
        .verify_authorizations(chain, 0)
        .map_err(|error| format!("local authorization verification failed: {error}"))?;

    println!("Local Authorization Valid: {authorization_valid}");

    if !authorization_valid {
        return Err("wallet produced an invalid transaction authorization".into());
    }

    let transaction_bytes = canonical_bytes(transaction).map_err(|error| error.to_string())?;

    if has_flag(args, "--offline") {
        println!("Transaction Hex: {}", hex::encode(&transaction_bytes));
        println!("Bytes: {}", transaction_bytes.len());
        return Ok(());
    }

    let rpc = option(args, "--rpc").unwrap_or(default_rpc_addr());
    let response: SubmitTransactionResponse =
        http_post_bytes(rpc, "/transaction", &transaction_bytes)?;

    println!("Tx Hash: {}", response.hash);
    println!("Bytes: {}", transaction_bytes.len());
    Ok(())
}

#[cfg(test)]
mod state_burn_tests {
    use super::*;

    fn wallet() -> AccountWallet {
        wallet::account_wallet_from_bip39_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Signature::MlDsa44,
        ).unwrap()
    }

    fn build(
        wallet: &AccountWallet,
        fee: u64,
        archival: u64,
    ) -> Result<AuthorizedProgramEnvelope, String> {
        let change = 1_000_000u64
            .checked_sub(fee)
            .and_then(|v| v.checked_sub(archival))
            .ok_or("insufficient fixture funds")?;
        let payment = CoinTransition::coin_with_charges(
            wallet.program_id,
            vec![CoinShare::from_bytes([3; CoinShare::SIZE])],
            vec![CoinOutput::new(wallet.program_id, Zeno::from_zeno(change))],
            CoinCharges::new(Zeno::from_zeno(fee)),
        )
        .map_err(|error| error.to_string())?;
        Ok(AuthorizedProgramEnvelope::Program(Box::new(
            wallet.sign_xpq_transfer(payment)?,
        )))
    }

    #[test]
    fn automatic_transaction_converges_with_independent_fee_and_burn_rates() {
        let wallet = wallet();
        for (fee_rate, burn_rate) in [(8, 1), (1, 8), (8, 8)] {
            let tx = automatic_fee_transaction_at_rates(
                |fee, archival| build(&wallet, fee, archival),
                fee_rate,
                burn_rate,
            )
            .unwrap();
            let size = canonical_bytes(&tx).unwrap().len() as u64;
            let AuthorizedProgramEnvelope::Program(invocation) = &tx;
            assert_eq!(
                canonical_bytes(&kernel::operation::BlockOperation::ProgramCall(
                    invocation.clone()
                ))
                .unwrap()
                .len() as u64,
                size
            );
            assert_eq!(
                invocation.payment.charges.miner_fee.as_zeno(),
                size * fee_rate
            );
            let output = invocation.payment.coin_parts().unwrap().1[0]
                .amount
                .as_zeno();
            assert_eq!(
                1_000_000 - output - invocation.payment.charges.miner_fee.as_zeno(),
                size * burn_rate
            );
            assert!(
                tx.verify_authorizations(kernel::genesis::chain_context().unwrap(), 0)
                    .unwrap()
            );
        }
        let tx = automatic_fee_transaction(|fee, archival| build(&wallet, fee, archival)).unwrap();
        let size = canonical_bytes(&tx).unwrap().len() as u64;
        let AuthorizedProgramEnvelope::Program(invocation) = &tx;
        assert_eq!(
            invocation.payment.charges.miner_fee.as_zeno(),
            size * AUTOMATIC_FEE_ZENO_PER_BYTE
        );
        assert_eq!(
            1_000_000
                - invocation.payment.coin_parts().unwrap().1[0]
                    .amount
                    .as_zeno()
                - invocation.payment.charges.miner_fee.as_zeno(),
            size * kernel::consensus::STATE_BURN_RATE_ZENO_PER_BYTE
        );
    }

    #[test]
    fn automatic_transaction_rejects_fee_and_archival_overflow() {
        let fixture = build(&wallet(), 0, 0).unwrap();
        let fee = automatic_fee_transaction_at_rates(|_, _| Ok(fixture.clone()), u64::MAX, 1)
            .unwrap_err();
        assert!(fee.contains("transaction fee overflow"));
        let burn = automatic_fee_transaction_at_rates(|_, _| Ok(fixture.clone()), 1, u64::MAX)
            .unwrap_err();
        assert!(burn.contains("archival burn overflow"));
    }
}
