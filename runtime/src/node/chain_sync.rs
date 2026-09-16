use super::*;
use super::{gossip::*, mempool::*, protocol::*, state::*};

pub(super) fn synchronize_headers(
    database: &Path,
    stream: &mut TcpStream,
    peer: &Handshake,
) -> Result<HeaderSyncResult, String> {
    let local_headers = cached_chain_headers(database)?
        .into_iter()
        .map(|(height, header)| kernel::consensus::HeaderAtHeight::new(height, header))
        .collect::<Vec<_>>();
    let locator = header_locator(&local_headers)?;
    let mut validation_state = None;
    let mut ancestor_height = None;
    let mut ancestor_hash = None;
    let mut downloaded = Vec::new();
    let mut request_locator = locator;
    let mut verified_headers = 0_usize;
    let mut pow_memory = None;

    loop {
        write_frame(stream, &encode_locator(&request_locator)?)?;
        let response = read_frame(stream, 33 + MAX_HEADER_CHAIN_CHUNK_SIZE)?;
        let (&message, body) = response.split_first().ok_or("empty header response")?;
        let ancestor: [u8; 32] = body
            .get(..32)
            .ok_or("header response has no ancestor")?
            .try_into()
            .map_err(|_| "invalid ancestor hash")?;
        if message == HEADERS_COMPLETE_MESSAGE {
            let state = match validation_state.take() {
                Some(state) => state,
                None => local_header_state_at_hash(&local_headers, ancestor)?
                    .ok_or("common ancestor is not canonical locally")?,
            };
            if state.header.hash().map_err(|error| error.to_string())?.0 != ancestor {
                return Err("peer completion does not match verified header tip".into());
            }
            if state.header.hash().map_err(|error| error.to_string())?.0 != peer.tip_hash
                || state.cumulative_work.to_be_limbs() != peer.cumulative_work
                || state.cumulative_weight != peer.cumulative_weight
            {
                return Err("peer handshake tip/work does not match verified headers".into());
            }
            let local = validated_header_state(&local_headers)?;
            let peer_work = state.cumulative_work;
            let peer_weight = state.cumulative_weight;
            let local_hash = local.header.hash().map_err(|error| error.to_string())?.0;
            let preferred = compare_chain_tips(
                peer_work,
                peer_weight,
                BlockHash(peer.tip_hash),
                local.cumulative_work,
                local.cumulative_weight,
                BlockHash(local_hash),
            )
            .is_gt();
            return Ok(HeaderSyncResult {
                ancestor_height: ancestor_height.unwrap_or(state.height),
                ancestor_hash: BlockHash(ancestor_hash.unwrap_or(ancestor)),
                headers: downloaded,
                peer_work,
                peer_weight,
                preferred,
            });
        }
        if message != HEADERS_MESSAGE {
            return Err("unexpected P2P message during header sync".into());
        }
        let chunk = decode_header_chain_chunk(&body[32..]).map_err(|error| error.to_string())?;
        let current = match validation_state.take() {
            Some(current) => {
                if current.header.hash().map_err(|error| error.to_string())?.0 != ancestor {
                    return Err("peer changed common ancestor during header sync".into());
                }
                current
            }
            None => local_header_state_at_hash(&local_headers, ancestor)?
                .ok_or("peer response ancestor is not canonical locally")?,
        };
        if ancestor_height.is_none() {
            ancestor_height = Some(current.height);
            ancestor_hash = Some(ancestor);
        }
        let advanced = kernel::consensus::advance_header_validation_state_with_memory(
            &current,
            &chunk.headers,
            pow_memory.get_or_insert_with(new_pow_memory),
        )
        .map_err(map_peer_header_error)?;
        verified_headers = verified_headers
            .checked_add(chunk.headers.len())
            .ok_or("verified header count overflow")?;
        if verified_headers > MAX_SYNC_HEADERS {
            return Err("header synchronization exceeds session limit".into());
        }
        if verified_headers.is_multiple_of(256) {
            println!(
                "sync_progress: verified_headers={verified_headers} peer_height={}",
                peer.tip_height.0
            );
        }
        let tip_hash = advanced.header.hash().map_err(|error| error.to_string())?.0;
        downloaded.extend(chunk.headers);
        validation_state = Some(advanced);
        request_locator = vec![tip_hash, EXPECTED_GENESIS_HASH.0];
    }
}

pub(super) fn map_peer_header_error(error: kernel::consensus::HeaderChainError) -> String {
    let invalid_pow = matches!(
        error,
        kernel::consensus::HeaderChainError::InvalidHeaderChain(
            kernel::consensus::ForkChoiceError::InvalidProofOfWork(_)
        )
    );
    if invalid_pow {
        format!("{INVALID_POW_ERROR_PREFIX} {error}")
    } else {
        format!("peer header extension is invalid: {error}")
    }
}

pub(super) fn reconnect_delay_for_error(error: &str, failures: u32, peer: &str) -> Duration {
    if error.starts_with(INVALID_POW_ERROR_PREFIX) {
        INVALID_POW_COOLDOWN
    } else {
        let exponent = failures.saturating_sub(1).min(5);
        let base = RECONNECT_INTERVAL.as_secs() * (1_u64 << exponent);
        let jitter = peer.bytes().fold(failures as u64, |value, byte| {
            value.wrapping_mul(33) ^ byte as u64
        }) % 10;
        Duration::from_secs((base + jitter).min(300))
    }
}

pub(super) fn synchronize_blocks(
    database: &Path,
    stream: &mut TcpStream,
    sync: HeaderSyncResult,
) -> Result<usize, String> {
    let count = sync.headers.len();
    let mut blocks = Vec::with_capacity(count);
    for expected in &sync.headers {
        let expected_hash = expected.hash().map_err(|error| error.to_string())?;
        let mut request = Vec::with_capacity(33);
        request.push(GET_BLOCK_MESSAGE);
        request.extend_from_slice(&expected_hash.0);
        write_frame(stream, &request)?;
        let response = read_frame(stream, 1 + MAX_STORED_BLOCK_SIZE)?;
        if response.first() != Some(&BLOCK_MESSAGE) {
            return Err("peer returned an unexpected block response".into());
        }
        let block =
            decode_block(&response[1..]).map_err(|error| format!("invalid peer block: {error}"))?;
        if block.height() != expected.height
            || block.header != expected.header
            || block.hash().map_err(|error| error.to_string())? != expected_hash
        {
            return Err("peer block body does not match the verified header".into());
        }
        blocks.push(block);
    }
    let included = blocks
        .iter()
        .flat_map(|block| block.transactions())
        .map(|transaction| transaction.id().map_err(|error| error.to_string()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let _mutation = state_mutation_lock()?
        .lock()
        .map_err(|_| "state mutation lock is poisoned")?;
    let mut staged = load_or_initialize_owned(database)?;
    let old_tip = staged.tip_hash();
    let new_tip = blocks
        .last()
        .map(Block::hash)
        .transpose()
        .map_err(|error| error.to_string())?
        .unwrap_or(sync.ancestor_hash);
    let current_headers = staged
        .chain
        .chain_headers()
        .into_iter()
        .map(|(height, header)| kernel::consensus::HeaderAtHeight::new(height, header))
        .collect::<Vec<_>>();
    let current_state = validated_header_state(&current_headers)?;
    let current_tip = old_tip.ok_or("canonical chain has no tip during reorg")?;
    if !compare_chain_tips(
        sync.peer_work,
        sync.peer_weight,
        new_tip,
        current_state.cumulative_work,
        current_state.cumulative_weight,
        current_tip,
    )
    .is_gt()
    {
        println!("sync: downloaded peer branch is no longer preferred after local tip advanced");
        return Ok(0);
    }
    let mut disconnect = Vec::new();
    let mut height = staged.tip_height();
    while height.is_some_and(|height| height > sync.ancestor_height) {
        let current = height.expect("height was checked above");
        disconnect.push(
            staged
                .chain
                .block(&current)
                .cloned()
                .ok_or("reorg disconnect block is missing from canonical chain")?,
        );
        height = current.0.checked_sub(1).map(Height);
    }
    let ancestor = staged
        .chain
        .block(&sync.ancestor_height)
        .ok_or("reorg ancestor is missing from canonical chain")?;
    if ancestor.hash().map_err(|error| error.to_string())? != sync.ancestor_hash {
        return Err("reorg ancestor hash does not match canonical chain".into());
    }
    let plan = ReorgPlan::new(sync.ancestor_hash, old_tip, new_tip, disconnect, blocks)
        .map_err(|error| format!("invalid canonical reorg plan: {error}"))?;
    let ancestor = plan.ancestor();
    let (disconnect, apply) = plan.into_branches();
    let disconnected_blocks = disconnect.len();
    let disconnected_transactions = disconnect
        .iter()
        .rev()
        .flat_map(|block| block.transactions().iter().cloned())
        .collect::<Vec<_>>();
    let disconnected_hash = disconnected_transactions
        .iter()
        .map(|transaction| transaction.id().map_err(|error| error.to_string()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    for expected in disconnect {
        let removed = staged
            .rollback_tip()
            .map_err(|error| format!("rollback canonical tip: {error}"))?;
        if removed.hash().map_err(|error| error.to_string())?
            != expected.hash().map_err(|error| error.to_string())?
        {
            return Err("rollback removed a block outside the reorg disconnect plan".into());
        }
    }
    if staged.tip_hash() != Some(ancestor) {
        return Err("rollback did not stop at the planned common ancestor".into());
    }
    for block in apply {
        apply_block(&mut staged, block)
            .map_err(|error| format!("apply synchronized block: {error}"))?;
    }
    let mut mempool_candidates = disconnected_transactions;
    mempool_candidates.extend(read_mempool(database)?);
    let mempool = reconcile_mempool(&staged, mempool_candidates, &included);
    let requeued_transactions = mempool
        .iter()
        .filter_map(|transaction| transaction.id().ok())
        .filter(|hash| disconnected_hash.contains(hash))
        .count();
    persist_chain_and_mempool(database, &staged, &mempool)?;
    let staged = update_ledger_cache(database, staged)?;
    if let Err(error) = crate::snapshot::write_after_large_sync(database, &staged, count) {
        eprintln!("node: post-sync snapshot write failed: {error}");
    }
    notify_gossip();
    if disconnected_blocks > 0 {
        println!(
            "reorg: disconnected_blocks={disconnected_blocks} disconnected_transactions={} requeued_transactions={requeued_transactions}",
            disconnected_hash.len(),
        );
    }
    Ok(count)
}

pub(super) fn header_locator(
    headers: &[kernel::consensus::HeaderAtHeight],
) -> Result<Vec<[u8; 32]>, String> {
    if headers.is_empty() {
        return Err("local header chain is empty".into());
    }
    let mut locator = Vec::new();
    let mut index = headers.len() - 1;
    let mut step = 1_usize;
    loop {
        locator.push(headers[index].hash().map_err(|error| error.to_string())?.0);
        if index == 0 || locator.len() == MAX_LOCATOR_HASHES - 1 {
            break;
        }
        index = index.saturating_sub(step);
        if locator.len() >= 10 {
            step = step.saturating_mul(2);
        }
    }
    if locator.last() != Some(&EXPECTED_GENESIS_HASH.0) {
        locator.push(EXPECTED_GENESIS_HASH.0);
    }
    Ok(locator)
}

pub(super) fn local_header_state_at_hash(
    headers: &[kernel::consensus::HeaderAtHeight],
    hash: [u8; 32],
) -> Result<Option<kernel::consensus::HeaderValidationState>, String> {
    let Some(index) = headers
        .iter()
        .position(|header| header.hash().is_ok_and(|candidate| candidate.0 == hash))
    else {
        return Ok(None);
    };
    validated_header_state(&headers[..=index]).map(Some)
}

pub(super) fn validated_header_state(
    headers: &[kernel::consensus::HeaderAtHeight],
) -> Result<kernel::consensus::HeaderValidationState, String> {
    let tip = headers.last().ok_or("validated header chain is empty")?;
    if headers[0].height != Height(0)
        || headers[0].hash().map_err(|error| error.to_string())? != EXPECTED_GENESIS_HASH
    {
        return Err("validated header chain has the wrong genesis".into());
    }
    let cumulative_work = headers.iter().skip(1).try_fold(
        kernel::consensus::Work::ZERO,
        |work, header| -> Result<_, String> {
            let block_work =
                kernel::consensus::block_work(header.header.target_bits).ok_or_else(|| {
                    format!(
                        "invalid target bits {:08x} at height {}",
                        header.header.target_bits, header.height.0,
                    )
                })?;

            Ok(work.saturating_add(block_work))
        },
    )?;
    let cumulative_weight = headers.iter().skip(1).fold(0_u64, |total, header| {
        total.saturating_add(u64::from(header.header.block_weight))
    });
    let start = headers
        .len()
        .saturating_sub(kernel::consensus::RECENT_HEADER_WINDOW);
    Ok(kernel::consensus::HeaderValidationState {
        height: tip.height,
        header: tip.header.clone(),
        cumulative_work,
        cumulative_weight,
        difficulty_anchor: headers[usize::from(tip.height.0 > 0)].clone(),
        recent_headers: headers[start..].to_vec(),
    })
}

pub(super) fn encode_locator(locator: &[[u8; 32]]) -> Result<Vec<u8>, String> {
    if locator.is_empty() || locator.len() > MAX_LOCATOR_HASHES {
        return Err("header locator count is outside allowed range".into());
    }
    let mut bytes = Vec::with_capacity(2 + locator.len() * 32);
    bytes.push(GET_HEADERS_MESSAGE);
    bytes.push(locator.len() as u8);
    for hash in locator {
        bytes.extend_from_slice(hash);
    }
    Ok(bytes)
}

pub(super) fn decode_locator(bytes: &[u8]) -> Result<Vec<[u8; 32]>, String> {
    if bytes.first() != Some(&GET_HEADERS_MESSAGE) {
        return Err("expected get-headers message".into());
    }
    let count = bytes.get(1).copied().ok_or("missing locator count")? as usize;
    if count == 0 || count > MAX_LOCATOR_HASHES || bytes.len() != 2 + count * 32 {
        return Err("invalid header locator size".into());
    }
    bytes[2..]
        .chunks_exact(32)
        .map(|chunk| {
            chunk
                .try_into()
                .map_err(|_| "invalid locator hash".to_string())
        })
        .collect()
}
