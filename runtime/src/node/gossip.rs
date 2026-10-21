use super::*;
use super::{chain_sync::*, mempool::*, p2p::*, protocol::*, state::*};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Mutex, OnceLock},
    time::Instant,
};

pub(super) type ShortId = [u8; 6];
const MAX_EARLY_RELAY_BLOCKS: usize = 16;
static EARLY_RELAY_BLOCKS: OnceLock<Mutex<VecDeque<Block>>> = OnceLock::new();

pub(super) fn queue_early_relay_block(block: Block) -> Result<(), String> {
    let blocks = EARLY_RELAY_BLOCKS.get_or_init(|| Mutex::new(VecDeque::new()));
    let mut blocks = blocks
        .lock()
        .map_err(|_| "early relay block queue is poisoned")?;
    let hash = block.hash().map_err(|error| error.to_string())?.0;
    if blocks
        .iter()
        .any(|candidate| candidate.hash().is_ok_and(|candidate| candidate.0 == hash))
    {
        return Ok(());
    }
    blocks.push_back(block);
    while blocks.len() > MAX_EARLY_RELAY_BLOCKS {
        blocks.pop_front();
    }
    Ok(())
}

fn early_relay_blocks() -> Result<Vec<Block>, String> {
    EARLY_RELAY_BLOCKS
        .get_or_init(|| Mutex::new(VecDeque::new()))
        .lock()
        .map(|blocks| blocks.iter().cloned().collect())
        .map_err(|_| "early relay block queue is poisoned".into())
}

pub(super) fn match_short_ids<T: Clone>(
    short_ids: &[ShortId],
    index: &BTreeMap<ShortId, Vec<T>>,
) -> (Vec<Option<T>>, Vec<u32>) {
    let mut found = Vec::with_capacity(short_ids.len());
    let mut missing = Vec::new();
    for (position, id) in short_ids.iter().enumerate() {
        match index.get(id).map(Vec::as_slice) {
            Some([only]) => found.push(Some(only.clone())),
            _ => {
                found.push(None);
                missing.push(position as u32);
            }
        }
    }
    (found, missing)
}

pub(super) fn short_id_keys(block_hash: &[u8; 32], salt: u64) -> (u64, u64) {
    let label = b"xparq:compact-block-key:v1";
    let mut material = Vec::with_capacity(label.len() + 40);
    material.extend_from_slice(label);
    material.extend_from_slice(block_hash);
    material.extend_from_slice(&salt.to_le_bytes());
    let digest =
        kernel::crypto::domain(kernel::crypto::HashDomain::CompactBlockKey, &material).into_bytes();
    (
        u64::from_le_bytes(digest[..8].try_into().expect("eight byte key")),
        u64::from_le_bytes(digest[8..16].try_into().expect("eight byte key")),
    )
}

pub(super) fn compact_short_id(keys: (u64, u64), operation_id: &[u8; 32]) -> ShortId {
    let value = siphash24(keys, operation_id);
    value.to_le_bytes()[..6]
        .try_into()
        .expect("six byte short ID")
}

fn siphash24(keys: (u64, u64), input: &[u8]) -> u64 {
    #[inline]
    fn round(v: &mut [u64; 4]) {
        v[0] = v[0].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(13);
        v[1] ^= v[0];
        v[0] = v[0].rotate_left(32);
        v[2] = v[2].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(16);
        v[3] ^= v[2];
        v[0] = v[0].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(21);
        v[3] ^= v[0];
        v[2] = v[2].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(17);
        v[1] ^= v[2];
        v[2] = v[2].rotate_left(32);
    }

    let mut v = [
        0x736f6d6570736575 ^ keys.0,
        0x646f72616e646f6d ^ keys.1,
        0x6c7967656e657261 ^ keys.0,
        0x7465646279746573 ^ keys.1,
    ];
    let mut chunks = input.chunks_exact(8);
    for chunk in &mut chunks {
        let word = u64::from_le_bytes(chunk.try_into().expect("eight byte message word"));
        v[3] ^= word;
        round(&mut v);
        round(&mut v);
        v[0] ^= word;
    }
    let mut final_word = (input.len() as u64) << 56;
    for (shift, byte) in chunks.remainder().iter().enumerate() {
        final_word |= u64::from(*byte) << (shift * 8);
    }
    v[3] ^= final_word;
    round(&mut v);
    round(&mut v);
    v[0] ^= final_word;
    v[2] ^= 0xff;
    for _ in 0..4 {
        round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

#[cfg(test)]
mod compact_short_id_tests {
    use super::*;

    #[test]
    fn siphash24_matches_reference_empty_message_vector() {
        assert_eq!(
            siphash24((0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908), b""),
            0x726f_db47_dd0e_0e31
        );
    }

    #[test]
    fn compact_short_ids_are_salted_by_block_and_salt() {
        let operation = [7_u8; 32];
        let first = compact_short_id(short_id_keys(&[1; 32], 1), &operation);
        assert_eq!(
            first,
            compact_short_id(short_id_keys(&[1; 32], 1), &operation)
        );
        assert_ne!(
            first,
            compact_short_id(short_id_keys(&[1; 32], 2), &operation)
        );
        assert_ne!(
            first,
            compact_short_id(short_id_keys(&[2; 32], 1), &operation)
        );
        assert_eq!(first.len(), 6);
    }
}

pub(super) fn gossip_inventory(database: &Path) -> Result<GossipInventory, String> {
    let (ledger, _header_checkpoints, cumulative_work, cumulative_weight) =
        load_or_initialize_header_snapshot(database)?;
    let tip_height = ledger.tip_height().ok_or("canonical genesis is missing")?;
    let tip_hash = ledger.tip_hash().ok_or("canonical genesis is missing")?.0;
    let transactions = read_mempool(database)?;
    let start = transactions
        .len()
        .saturating_sub(MAX_GOSSIP_INVENTORY_ITEMS);
    let hash = transactions[start..]
        .iter()
        .map(|transaction| transaction.id().map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(GossipInventory {
        tip_height,
        tip_hash,
        cumulative_work: cumulative_work.to_be_limbs(),
        cumulative_weight,
        hash,
    })
}

pub(super) fn gossip_tip(database: &Path) -> Result<TipAnnouncement, String> {
    let (ledger, _checkpoints, cumulative_work, cumulative_weight) =
        load_or_initialize_header_snapshot(database)?;
    Ok(TipAnnouncement {
        tip_height: ledger.tip_height().ok_or("canonical genesis is missing")?,
        tip_hash: ledger.tip_hash().ok_or("canonical genesis is missing")?.0,
        cumulative_work: cumulative_work.to_be_limbs(),
        cumulative_weight,
    })
}

fn exchange_tip_announcement(
    database: &Path,
    stream: &mut TcpStream,
) -> Result<TipAnnouncement, String> {
    let announcement = gossip_tip(database)?;
    let encoded = canonical_bytes(&announcement).map_err(|error| error.to_string())?;
    let mut message = Vec::with_capacity(1 + encoded.len());
    message.push(ANNOUNCE_TIP_MESSAGE);
    message.extend_from_slice(&encoded);
    write_frame(stream, &message)?;
    let response = read_frame(stream, 1 + 128)?;
    if response.first() != Some(&ANNOUNCE_TIP_MESSAGE) {
        return Err("peer returned an unexpected tip announcement".into());
    }
    canonical_decode(&response[1..]).map_err(|error| format!("decode peer tip: {error}"))
}

pub(super) fn inventory_preferred(candidate: &GossipInventory, current: &GossipInventory) -> bool {
    compare_chain_tips(
        Work::from_be_limbs(candidate.cumulative_work),
        candidate.cumulative_weight,
        BlockHash(candidate.tip_hash),
        Work::from_be_limbs(current.cumulative_work),
        current.cumulative_weight,
        BlockHash(current.tip_hash),
    )
    .is_gt()
}

pub(super) fn handshake_from_inventory(
    handshake: &Handshake,
    inventory: &GossipInventory,
) -> Handshake {
    let mut current = handshake.clone();
    current.tip_height = inventory.tip_height;
    current.tip_hash = inventory.tip_hash;
    current.cumulative_work = inventory.cumulative_work;
    current.cumulative_weight = inventory.cumulative_weight;
    current
}

pub(super) fn decode_gossip_inventory(bytes: &[u8]) -> Result<GossipInventory, String> {
    if bytes.len() > MAX_GOSSIP_INVENTORY_SIZE {
        return Err("gossip inventory exceeds size limit".into());
    }
    let declared = bytes
        .get(112..116)
        .and_then(|count| count.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or("gossip inventory is truncated")? as usize;
    if declared > MAX_GOSSIP_INVENTORY_ITEMS {
        return Err("gossip inventory item count exceeds limit".into());
    }
    let inventory: GossipInventory =
        canonical_decode(bytes).map_err(|error| format!("decode gossip inventory: {error}"))?;
    if inventory.hash.len() > MAX_GOSSIP_INVENTORY_ITEMS {
        return Err("gossip inventory item count exceeds limit".into());
    }
    Ok(inventory)
}

pub(super) fn request_discovered_peers(stream: &mut TcpStream) -> Result<Vec<PeerAddress>, String> {
    write_frame(stream, &[GET_PEERS_MESSAGE])?;
    let response = read_frame(stream, 1 + MAX_PEERS_RESPONSE_SIZE)?;
    if response.first() != Some(&PEERS_MESSAGE) {
        return Err("peer returned an unexpected discovery response".into());
    }
    decode_peer_addresses(&response[1..], MAX_DISCOVERED_PEERS)
        .map_err(|error| format!("decode discovered peers: {error}"))
}

pub(super) fn decode_peer_addresses(
    bytes: &[u8],
    maximum_count: usize,
) -> Result<Vec<PeerAddress>, String> {
    if bytes.len() > MAX_PEERS_RESPONSE_SIZE {
        return Err("peer address list exceeds size limit".into());
    }
    let peers = decode_peer_endpoints(bytes, maximum_count)
        .map_err(|error| format!("decode peer address list: {error}"))?;
    let mut unique = BTreeSet::new();
    Ok(peers
        .into_iter()
        .map(PeerAddress::from)
        .filter(PeerAddress::is_admissible)
        .filter(|peer| unique.insert(peer.clone()))
        .collect())
}

pub(super) fn relay_mempool(database: &Path, stream: &mut TcpStream) -> Result<(), String> {
    for transaction in read_mempool(database)?
        .into_iter()
        .take(MAX_RELAY_ITEMS_PER_SESSION)
    {
        let encoded = canonical_bytes(&transaction).map_err(|error| error.to_string())?;
        let mut message = Vec::with_capacity(1 + encoded.len());
        message.push(SUBMIT_TRANSACTION_MESSAGE);
        message.extend_from_slice(&encoded);
        write_frame(stream, &message)?;
        read_relay_result(stream)?;
    }
    Ok(())
}

pub(super) fn gossip_outbound_session(
    database: &Path,
    stream: &mut TcpStream,
    peer: &Handshake,
) -> Result<(), String> {
    let supports_data_relay = peer.capabilities & CAPABILITY_RELAY != 0;
    let supports_peer_relay = peer.capabilities & CAPABILITY_PEER_RELAY != 0;
    if !supports_data_relay && !supports_peer_relay {
        write_frame(stream, &[SYNC_COMPLETE_MESSAGE])?;
        return Ok(());
    }

    let mut generation = gossip_generation()?;
    let mut last_peer_refresh = Instant::now();
    let mut last_full_inventory = Instant::now() - GOSSIP_FULL_INVENTORY_INTERVAL;
    let mut last_local_tip = None;
    let mut last_remote_tip = None;
    let mut force_inventory = true;
    let mut last_tip_exchange: Option<Instant> = None;

    loop {
        if supports_peer_relay && last_peer_refresh.elapsed() >= PEER_RELAY_REFRESH_INTERVAL {
            refresh_peer_addresses(database, stream, peer)?;
            last_peer_refresh = Instant::now();
        }

        if !supports_data_relay {
            generation = wait_for_gossip(generation)?;
            continue;
        }

        if let Some(last) = last_tip_exchange {
            let remaining = GOSSIP_HEARTBEAT.saturating_sub(last.elapsed());
            if !remaining.is_zero() {
                std::thread::sleep(remaining);
            }
        }

        let local_tip = gossip_tip(database)?;
        let remote_tip = exchange_tip_announcement(database, stream)?;
        last_tip_exchange = Some(Instant::now());
        if peer.capabilities & CAPABILITY_RELAY != 0 {
            let mut next_peer_tip = remote_tip.tip_hash;
            for block in early_relay_blocks()? {
                if block.previous_hash().0 != next_peer_tip {
                    continue;
                }
                if peer.capabilities & CAPABILITY_COMPACT_BLOCK_RELAY_V2 != 0 {
                    relay_compact_block(stream, &block)?;
                } else {
                    let encoded = block_bytes(&block).map_err(|error| error.to_string())?;
                    let mut message = Vec::with_capacity(1 + encoded.len());
                    message.push(SUBMIT_BLOCK_MESSAGE);
                    message.extend_from_slice(&encoded);
                    write_frame(stream, &message)?;
                    read_relay_result(stream)?;
                }
                next_peer_tip = block.hash().map_err(|error| error.to_string())?.0;
            }
        }
        let local_tip_changed = last_local_tip.as_ref() != Some(&local_tip);
        let remote_tip_changed = last_remote_tip.as_ref() != Some(&remote_tip);
        last_local_tip = Some(local_tip);
        last_remote_tip = Some(remote_tip);
        let exchange_inventory = force_inventory
            || local_tip_changed
            || remote_tip_changed
            || last_full_inventory.elapsed() >= GOSSIP_FULL_INVENTORY_INTERVAL;
        force_inventory = false;

        if !exchange_inventory {
            let previous_generation = generation;
            generation = wait_for_gossip(generation)?;
            force_inventory = generation != previous_generation;
            continue;
        }

        let local_before = gossip_inventory(database)?;
        last_full_inventory = Instant::now();
        let encoded = canonical_bytes(&local_before).map_err(|error| error.to_string())?;

        let mut message = Vec::with_capacity(1 + encoded.len());
        message.push(INVENTORY_MESSAGE);
        message.extend_from_slice(&encoded);
        write_frame(stream, &message)?;

        let response = read_frame(stream, 1 + MAX_GOSSIP_INVENTORY_SIZE)?;

        if response.first() != Some(&INVENTORY_MESSAGE) {
            return Err("peer returned an unexpected gossip inventory response".into());
        }

        let remote = decode_gossip_inventory(&response[1..])?;

        if remote.tip_hash != local_before.tip_hash {
            let remote_allowed = super::chain_minimums::allows(
                database,
                Work::from_be_limbs(remote.cumulative_work),
                remote.cumulative_weight,
            )?;
            if remote_allowed && inventory_preferred(&remote, &local_before) {
                if try_shallow_gossip_reorg(database, stream, &remote)?.is_some() {
                    generation = gossip_generation()?;
                    continue;
                }

                return Err(format!(
                    "{GOSSIP_RESYNC_PREFIX} peer announced a preferred chain"
                ));
            }

            if inventory_preferred(&local_before, &remote) {
                let ledger = load_or_initialize(database)?;
                let tip_height = local_before.tip_height;

                let advertised_tip_matches = ledger
                    .chain
                    .block(&tip_height)
                    .and_then(|block| block.hash().ok())
                    .is_some_and(|hash| hash.0 == local_before.tip_hash);

                if !advertised_tip_matches {
                    return Err(format!(
                        "{GOSSIP_RESYNC_PREFIX} advertised local tip changed before reverse sync"
                    ));
                }

                match serve_peer_requests_through(database, stream, &ledger, tip_height)? {
                    PeerSessionOutcome::Complete => return Ok(()),
                    PeerSessionOutcome::ReverseSync(_) => {
                        return Err("peer requested nested reverse synchronization".into());
                    }
                }
            }

            if !remote_allowed {
                generation = wait_for_gossip(generation)?;
                continue;
            }
            return Err(format!(
                "{GOSSIP_RESYNC_PREFIX} tips diverged; reconnecting for verified header sync"
            ));
        }

        exchange_gossip_transactions(database, stream, &remote)?;
        let previous_generation = generation;
        generation = wait_for_gossip(generation)?;
        force_inventory = generation != previous_generation;
    }
}

pub(super) fn request_and_accept_gossip_block(
    database: &Path,
    stream: &mut TcpStream,
    block_hash: [u8; 32],
) -> Result<(), String> {
    let mut request = Vec::with_capacity(33);
    request.push(GET_BLOCK_MESSAGE);
    request.extend_from_slice(&block_hash);
    write_frame(stream, &request)?;
    let response = read_frame(stream, 1 + MAX_STORED_BLOCK_SIZE)?;
    if response.first() != Some(&BLOCK_MESSAGE) {
        return Err("peer returned an unexpected gossip block response".into());
    }
    let block = decode_block(&response[1..])
        .map_err(|error| format!("invalid gossip block response: {error}"))?;
    if block.hash().map_err(|error| error.to_string())?.0 != block_hash {
        return Err("gossip block body does not match announced hash".into());
    }
    accept_relayed_block(database, &response[1..])
}

pub(super) fn request_and_accept_compact_gossip_block(
    database: &Path,
    stream: &mut TcpStream,
    block_hash: [u8; 32],
) -> Result<(), String> {
    let mut request = Vec::with_capacity(33);
    request.push(GET_COMPACT_BLOCK_MESSAGE);
    request.extend_from_slice(&block_hash);
    write_frame(stream, &request)?;
    let response = read_frame(stream, 1 + MAX_STORED_BLOCK_SIZE)?;
    if response.first() != Some(&COMPACT_BLOCK_MESSAGE) {
        return Err("peer returned an unexpected compact gossip response".into());
    }
    let result = accept_compact_block(database, stream, &response[1..]);
    if result
        .as_ref()
        .is_err_and(|error| error.starts_with(GOSSIP_RESYNC_PREFIX))
    {
        // The compact payload is valid but extends a different parent. Acknowledge
        // receipt so the same session remains available for bounded fork recovery.
        write_frame(stream, &[ACCEPTED_MESSAGE])?;
        return result;
    }
    write_relay_result(stream, result.clone())?;
    result
}

const MAX_SHALLOW_GOSSIP_FORK_DEPTH: usize = 8;

/// Resolve a short preferred fork with block requests on the current session.
/// Returning `None` means the peer's branch does not meet the local chain in
/// the bounded window and should use the full header synchronization path.
pub(super) fn try_shallow_gossip_reorg(
    database: &Path,
    stream: &mut TcpStream,
    remote: &GossipInventory,
) -> Result<Option<usize>, String> {
    let (ledger, checkpoints, local_work, local_weight) =
        load_or_initialize_header_snapshot(database)?;
    let local_tip_height = ledger.tip_height().ok_or("local chain has no tip")?;
    if !inventory_preferred(remote, &gossip_inventory(database)?) {
        return Ok(Some(0));
    }

    if remote.tip_height.0 == ledger.tip_height().unwrap_or(Height(0)).0.saturating_add(1) {
        match request_and_accept_compact_gossip_block(database, stream, remote.tip_hash) {
            Ok(()) => return Ok(Some(1)),
            Err(error) if error.starts_with(GOSSIP_RESYNC_PREFIX) => {}
            Err(error) => return Err(error),
        }
    }

    let mut requested_hash = remote.tip_hash;
    let mut descending = Vec::new();
    for _ in 0..MAX_SHALLOW_GOSSIP_FORK_DEPTH {
        let block = request_gossip_block(stream, requested_hash)?;
        if block.hash().map_err(|error| error.to_string())?.0 != requested_hash {
            return Err("gossip block body does not match requested hash".into());
        }
        if descending.is_empty() && block.height() != remote.tip_height {
            return Err("gossip tip block height does not match announcement".into());
        }
        if block.height().0 == 0 {
            return Ok(None);
        }

        let ancestor_height = Height(block.height().0 - 1);
        if ancestor_height > local_tip_height {
            requested_hash = block.previous_hash().0;
            descending.push(block);
            continue;
        }
        let ancestor = ledger
            .chain
            .header(&ancestor_height)
            .ok_or("local header is missing below the canonical tip while checking shallow fork")?;
        if ancestor.hash().map_err(|error| error.to_string())?.0 == block.previous_hash().0 {
            descending.push(block);
            descending.reverse();

            let ancestor_hash = BlockHash(blocks_previous_hash(&descending[0]));
            let mut validation =
                ledger_header_state_at_height(&ledger, checkpoints.as_slice(), ancestor_height)?;
            let mut pow_memory = new_pow_memory();
            let headers = descending
                .iter()
                .map(|block| {
                    kernel::consensus::HeaderAtHeight::new(block.height(), block.header.clone())
                })
                .collect::<Vec<_>>();
            validation = kernel::consensus::advance_header_validation_state_with_memory(
                &validation,
                &headers,
                &mut pow_memory,
            )
            .map_err(super::chain_sync::map_peer_header_error)?;
            if validation
                .header
                .hash()
                .map_err(|error| error.to_string())?
                .0
                != remote.tip_hash
                || validation.cumulative_work.to_be_limbs() != remote.cumulative_work
                || validation.cumulative_weight != remote.cumulative_weight
            {
                return Err("shallow gossip branch does not match announced tip/work".into());
            }
            if !super::chain_minimums::allows(
                database,
                validation.cumulative_work,
                validation.cumulative_weight,
            )? || !compare_chain_tips(
                validation.cumulative_work,
                validation.cumulative_weight,
                BlockHash(remote.tip_hash),
                local_work,
                local_weight,
                BlockHash(ledger.tip_hash().ok_or("local chain has no tip")?.0),
            )
            .is_gt()
            {
                return Ok(Some(0));
            }

            let sync = HeaderSyncResult {
                ancestor_height,
                ancestor_hash,
                headers,
                peer_work: validation.cumulative_work,
                peer_weight: validation.cumulative_weight,
                preferred: true,
            };
            return apply_verified_branch(database, sync, descending).map(Some);
        }

        requested_hash = block.previous_hash().0;
        descending.push(block);
    }
    Ok(None)
}

fn request_gossip_block(stream: &mut TcpStream, hash: [u8; 32]) -> Result<Block, String> {
    let mut request = Vec::with_capacity(33);
    request.push(GET_BLOCK_MESSAGE);
    request.extend_from_slice(&hash);
    write_frame(stream, &request)?;
    let response = read_frame(stream, 1 + MAX_STORED_BLOCK_SIZE)?;
    if response.first() != Some(&BLOCK_MESSAGE) {
        return Err("peer returned an unexpected gossip block response".into());
    }
    let block = decode_block(&response[1..])
        .map_err(|error| format!("invalid gossip block response: {error}"))?;
    if block.hash().map_err(|error| error.to_string())?.0 != hash {
        return Err("gossip block body does not match requested hash".into());
    }
    Ok(block)
}

fn blocks_previous_hash(block: &Block) -> [u8; 32] {
    block.previous_hash().0
}

pub(super) fn exchange_gossip_transactions(
    database: &Path,
    stream: &mut TcpStream,
    remote: &GossipInventory,
) -> Result<(), String> {
    let local = gossip_inventory(database)?;
    let local_ids = local.hash.iter().copied().collect::<BTreeSet<_>>();
    for hash in remote
        .hash
        .iter()
        .filter(|hash| !local_ids.contains(*hash))
        .take(MAX_RELAY_ITEMS_PER_SESSION)
    {
        let mut request = Vec::with_capacity(33);
        request.push(GET_TRANSACTION_MESSAGE);
        request.extend_from_slice(hash);
        write_frame(stream, &request)?;
        let response = read_frame(stream, 1 + MAX_STORED_TRANSACTION_SIZE)?;
        if response.first() != Some(&TRANSACTION_MESSAGE) {
            return Err("peer returned an unexpected transaction response".into());
        }
        let transaction: Transaction = canonical_decode(&response[1..])
            .map_err(|error| format!("invalid gossip transaction: {error}"))?;
        if transaction.id().map_err(|error| error.to_string())? != *hash {
            return Err("gossip transaction body does not match announced ID".into());
        }
        accept_relayed_transaction(database, &response[1..])?;
    }

    let remote_ids = remote.hash.iter().copied().collect::<BTreeSet<_>>();
    for transaction in read_mempool(database)?
        .into_iter()
        .filter(|transaction| {
            transaction
                .id()
                .is_ok_and(|hash| !remote_ids.contains(&hash))
        })
        .take(MAX_RELAY_ITEMS_PER_SESSION)
    {
        let encoded = canonical_bytes(&transaction).map_err(|error| error.to_string())?;
        let mut message = Vec::with_capacity(1 + encoded.len());
        message.push(SUBMIT_TRANSACTION_MESSAGE);
        message.extend_from_slice(&encoded);
        write_frame(stream, &message)?;
        read_relay_result(stream)?;
    }
    Ok(())
}

pub(super) fn gossip_notifier() -> &'static (Mutex<u64>, Condvar) {
    GOSSIP_NOTIFIER.get_or_init(|| (Mutex::new(0), Condvar::new()))
}

pub(super) fn gossip_generation() -> Result<u64, String> {
    gossip_notifier()
        .0
        .lock()
        .map(|generation| *generation)
        .map_err(|_| "gossip notifier lock is poisoned".into())
}

pub(super) fn notify_gossip() {
    let (generation, wake) = gossip_notifier();
    if let Ok(mut generation) = generation.lock() {
        *generation = generation.wrapping_add(1);
        wake.notify_all();
    }
}

pub(super) fn wait_for_gossip(previous: u64) -> Result<u64, String> {
    let (generation, wake) = gossip_notifier();
    let generation = generation
        .lock()
        .map_err(|_| "gossip notifier lock is poisoned")?;
    if *generation != previous {
        return Ok(*generation);
    }
    let (generation, _) = wake
        .wait_timeout(generation, GOSSIP_HEARTBEAT)
        .map_err(|_| "gossip notifier lock is poisoned")?;
    Ok(*generation)
}

pub(super) fn gossip_error_is_malicious(error: &str) -> bool {
    error.contains("invalid gossip")
        || error.contains("does not match announced")
        || error.contains("exceeds")
        || error.contains("invalid relayed")
        || error.contains("unexpected gossip")
}

pub(super) fn relay_next_block(
    database: &Path,
    stream: &mut TcpStream,
    peer_height: Height,
    peer_tip_hash: [u8; 32],
    compact_relay: bool,
) -> Result<bool, String> {
    let ledger = load_or_initialize(database)?;
    let Some(local_height) = ledger.tip_height() else {
        return Ok(false);
    };
    if local_height.0 != peer_height.0.saturating_add(1) {
        return Ok(false);
    }
    let block = ledger
        .chain
        .block(&local_height)
        .ok_or("local relay tip block is missing")?;
    if block.previous_hash().0 != peer_tip_hash {
        return Ok(false);
    }
    if !compact_relay {
        let encoded = block_bytes(block).map_err(|error| error.to_string())?;
        let mut message = Vec::with_capacity(1 + encoded.len());
        message.push(SUBMIT_BLOCK_MESSAGE);
        message.extend_from_slice(&encoded);
        write_frame(stream, &message)?;
        read_relay_result(stream)?;
        return Ok(true);
    }
    relay_compact_block(stream, block)?;
    Ok(true)
}

pub(super) fn relay_compact_block(stream: &mut TcpStream, block: &Block) -> Result<(), String> {
    let hash = block.hash().map_err(|error| error.to_string())?.0;
    let compact = compact_block(block)?;
    let encoded = canonical_bytes(&compact).map_err(|error| error.to_string())?;
    let mut message = Vec::with_capacity(1 + encoded.len());
    message.push(COMPACT_BLOCK_MESSAGE);
    message.extend_from_slice(&encoded);
    write_frame(stream, &message)?;
    let mut served_operations = false;
    let mut served_block = false;
    loop {
        let response = read_frame(stream, 1 + MAX_STORED_BLOCK_SIZE)?;
        match response.first() {
            Some(&ACCEPTED_MESSAGE) => return Ok(()),
            Some(&REJECTED_MESSAGE) => {
                return Err(String::from_utf8_lossy(&response[1..]).into_owned());
            }
            Some(&GET_BLOCK_OPERATIONS_MESSAGE) if !served_operations && !served_block => {
                let missing: MissingBlockOperations = canonical_decode(&response[1..])
                    .map_err(|error| format!("invalid compact block request: {error}"))?;
                if missing.block_hash != hash
                    || missing.indices.len() > kernel::block::MAX_BLOCK_OPERATIONS
                {
                    return Err("invalid compact block operation request".into());
                }
                let operations = missing
                    .indices
                    .iter()
                    .map(|index| {
                        block
                            .operations()
                            .get(*index as usize)
                            .map(|operation| (*index, operation.clone()))
                            .ok_or_else(|| {
                                "compact block operation index is out of range".to_string()
                            })
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                let body = RequestedBlockOperations {
                    block_hash: hash,
                    operations,
                };
                let encoded = canonical_bytes(&body).map_err(|error| error.to_string())?;
                let mut reply = Vec::with_capacity(1 + encoded.len());
                reply.push(BLOCK_OPERATIONS_MESSAGE);
                reply.extend_from_slice(&encoded);
                write_frame(stream, &reply)?;
                served_operations = true;
            }
            Some(&GET_BLOCK_MESSAGE) if !served_block => {
                if response[1..] != hash {
                    return Err("compact block fallback requested a different block".into());
                }
                let encoded = block_bytes(block).map_err(|error| error.to_string())?;
                let mut reply = Vec::with_capacity(1 + encoded.len());
                reply.push(BLOCK_MESSAGE);
                reply.extend_from_slice(&encoded);
                write_frame(stream, &reply)?;
                served_block = true;
            }
            _ => return Err("peer returned an unexpected compact block response".into()),
        }
    }
}

pub(super) fn accept_compact_block(
    database: &Path,
    stream: &mut TcpStream,
    bytes: &[u8],
) -> Result<(), String> {
    if bytes.len() > MAX_STORED_BLOCK_SIZE {
        return Err("compact block exceeds size limit".into());
    }
    let compact: CompactBlock =
        canonical_decode(bytes).map_err(|error| format!("invalid compact block: {error}"))?;
    if compact.short_ids.len() > kernel::block::MAX_BLOCK_OPERATIONS {
        return Err("compact block operation count exceeds limit".into());
    }
    let mut unique = BTreeSet::new();
    if !compact.short_ids.iter().all(|id| unique.insert(*id)) {
        return request_and_accept_gossip_block(database, stream, compact.block_hash);
    }
    let keys = short_id_keys(&compact.block_hash, compact.salt);
    let transactions = read_mempool(database)?;
    let mut by_short_id = BTreeMap::<ShortId, Vec<BlockOperation>>::new();
    for transaction in transactions {
        let operation: BlockOperation = transaction.into();
        let id = operation
            .id()
            .map_err(|error| error.to_string())?
            .into_bytes();
        by_short_id
            .entry(compact_short_id(keys, &id))
            .or_default()
            .push(operation);
    }
    let (mut operations, missing) = match_short_ids(&compact.short_ids, &by_short_id);
    if !missing.is_empty() {
        let request = MissingBlockOperations {
            block_hash: compact.block_hash,
            indices: missing.clone(),
        };
        let encoded = canonical_bytes(&request).map_err(|error| error.to_string())?;
        let mut message = Vec::with_capacity(1 + encoded.len());
        message.push(GET_BLOCK_OPERATIONS_MESSAGE);
        message.extend_from_slice(&encoded);
        write_frame(stream, &message)?;
        let response = read_frame(stream, 1 + MAX_STORED_BLOCK_SIZE + 32 * 1024)?;
        if response.first() != Some(&BLOCK_OPERATIONS_MESSAGE) {
            return request_and_accept_gossip_block(database, stream, compact.block_hash);
        }
        let Ok(response) = canonical_decode::<RequestedBlockOperations>(&response[1..]) else {
            return request_and_accept_gossip_block(database, stream, compact.block_hash);
        };
        if response.block_hash != compact.block_hash || response.operations.len() != missing.len() {
            return request_and_accept_gossip_block(database, stream, compact.block_hash);
        }
        for (expected, (index, operation)) in missing.iter().zip(response.operations) {
            if expected != &index || index as usize >= operations.len() {
                return request_and_accept_gossip_block(database, stream, compact.block_hash);
            }
            let Ok(id) = operation.id().map(|id| id.into_bytes()) else {
                return request_and_accept_gossip_block(database, stream, compact.block_hash);
            };
            if compact_short_id(keys, &id) != compact.short_ids[index as usize] {
                return request_and_accept_gossip_block(database, stream, compact.block_hash);
            }
            operations[index as usize] = Some(operation);
        }
    }
    let Some(block) = reconstruct_compact_block(&compact, operations) else {
        return request_and_accept_gossip_block(database, stream, compact.block_hash);
    };
    let encoded = block_bytes(&block).map_err(|error| error.to_string())?;
    accept_relayed_block(database, &encoded)
}

fn compact_block(block: &Block) -> Result<CompactBlock, String> {
    let block_hash = block.hash().map_err(|error| error.to_string())?.0;
    let mut salt_bytes = [0_u8; 8];
    getrandom::fill(&mut salt_bytes)
        .map_err(|error| format!("generate compact block salt: {error}"))?;
    let salt = u64::from_le_bytes(salt_bytes);
    let keys = short_id_keys(&block_hash, salt);
    Ok(CompactBlock {
        block_hash,
        header: block.header.clone(),
        height: block.height,
        emission: block.emission().cloned(),
        salt,
        short_ids: block
            .operations()
            .iter()
            .map(|operation| {
                operation
                    .id()
                    .map(|id| compact_short_id(keys, &id.into_bytes()))
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn reconstruct_compact_block(
    compact: &CompactBlock,
    operations: Vec<Option<BlockOperation>>,
) -> Option<Block> {
    let operations = operations.into_iter().collect::<Option<Vec<_>>>()?;
    let mut block = Block::from_protocol_operations(
        compact.height,
        compact.header.previous_hash.clone(),
        compact.header.target_bits,
        compact.header.nonce,
        compact.emission.clone(),
        operations,
    )
    .ok()?;
    block.header = compact.header.clone();
    (block.hash().ok()?.0 == compact.block_hash).then_some(block)
}

pub(super) fn read_relay_result(stream: &mut TcpStream) -> Result<(), String> {
    let response = read_frame(stream, 1024)?;
    match response.first() {
        Some(&ACCEPTED_MESSAGE) => Ok(()),
        Some(&REJECTED_MESSAGE) => Err(String::from_utf8_lossy(&response[1..]).into_owned()),
        _ => Err("peer returned an invalid relay response".into()),
    }
}

pub(super) fn write_relay_result(
    stream: &mut TcpStream,
    result: Result<(), String>,
) -> Result<(), String> {
    match result {
        Ok(()) => write_frame(stream, &[ACCEPTED_MESSAGE]),
        Err(error) => {
            let mut response = Vec::with_capacity(1 + error.len().min(1023));
            response.push(REJECTED_MESSAGE);
            response.extend_from_slice(&error.as_bytes()[..error.len().min(1023)]);
            write_frame(stream, &response)
        }
    }
}

pub(super) fn accept_relayed_block(database: &Path, bytes: &[u8]) -> Result<(), String> {
    let block = decode_block(bytes).map_err(|error| format!("invalid relayed block: {error}"))?;
    let hash = block.hash().map_err(|error| error.to_string())?;
    let _mutation = state_mutation_lock()?
        .lock()
        .map_err(|_| "state mutation lock is poisoned")?;
    let (_, _, current_work, current_weight) = load_or_initialize_header_snapshot(database)?;
    let mut ledger = load_or_initialize_owned(database)?;
    if ledger.tip_hash() == Some(hash) {
        return Ok(());
    }
    if ledger.tip_hash().map(|tip| tip.0) != Some(block.previous_hash().0) {
        return Err(format!(
            "{GOSSIP_RESYNC_PREFIX} relayed block does not directly extend the canonical tip"
        ));
    }
    let block_work = kernel::consensus::block_work(block.header.target_bits)
        .ok_or("relayed block has invalid target bits")?;
    let next_work = current_work.saturating_add(block_work);
    let next_weight = current_weight.saturating_add(u64::from(block.header.block_weight));
    if !super::chain_minimums::allows(database, next_work, next_weight)? {
        return Err("relayed chain is below configured work/weight minimums".into());
    }
    // Above-floor advertised totals never bypass PoW, weight or execution checks.
    apply_block(&mut ledger, block.clone())
        .map_err(|error| format!("invalid relayed block: {error}"))?;
    let included = block
        .operations()
        .iter()
        .map(|operation| {
            operation
                .id()
                .map(|id| id.into_bytes())
                .map_err(|error| error.to_string())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mempool =
        reconcile_pending_operations(&ledger, read_pending_operations(database)?, &included);
    persist_block_and_pending(database, &block, &mempool)?;
    let _ = update_ledger_cache(database, ledger)?;
    notify_gossip();
    Ok(())
}

#[cfg(test)]
mod discovery_tests {
    use super::*;

    #[test]
    fn discovery_accepts_dns_strings_without_resolving_and_filters_private_ips() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(read_frame(&mut stream, 1).unwrap(), [GET_PEERS_MESSAGE]);
            let endpoints = vec![
                "node.example.invalid:6677",
                "[2606:4700::1111]:6677",
                "127.0.0.1:6677",
                "node.local:6677",
                "bad host:6677",
            ];
            let mut response = vec![PEERS_MESSAGE];
            response.extend(canonical_bytes(&endpoints).unwrap());
            write_frame(&mut stream, &response).unwrap();
        });
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let peers = request_discovered_peers(&mut stream).unwrap();
        assert_eq!(
            peers.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["node.example.invalid:6677", "[2606:4700::1111]:6677"]
        );
        server.join().unwrap();
    }
}

#[cfg(test)]
mod compact_relay_tests {
    use super::*;
    use std::{
        net::{TcpListener, TcpStream},
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    fn test_database(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "xparq-compact-relay-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    fn next_block(database: &Path) -> Block {
        let ledger = load_or_initialize(database).unwrap();
        let mut block = super::super::mining::candidate_operation_block(
            &ledger,
            ProgramId([0xa1; kernel::crypto::PROGRAM_ID_SIZE]),
            vec![],
        )
        .unwrap();
        assert!(
            crate::miner::mine_range(
                &mut block,
                crate::miner::MiningRange {
                    start_nonce: 0,
                    attempts: 1_000_000,
                },
                &mut new_pow_memory(),
            )
            .unwrap()
            .is_some(),
            "test block should find a nonce"
        );
        block
    }

    fn mine_database_tip(database: &Path) -> Block {
        mine_database_tip_with_miner(database, ProgramId([0xa2; kernel::crypto::PROGRAM_ID_SIZE]))
    }

    fn mine_database_tip_with_miner(database: &Path, miner: ProgramId) -> Block {
        load_or_initialize(database).unwrap();
        let mut memory = new_pow_memory();
        let mut nonce = 0;
        loop {
            match super::super::mining::mine_block_database(
                database,
                miner,
                nonce,
                1_000_000,
                &mut memory,
            )
            .unwrap()
            {
                super::super::mining::MiningAttempt::Mined => break,
                super::super::mining::MiningAttempt::Exhausted { next } => nonce = next,
            }
        }
        load_or_initialize(database)
            .unwrap()
            .chain
            .block(&Height(1))
            .unwrap()
            .clone()
    }

    fn mine_additional_blocks(database: &Path, count: usize) {
        let mut memory = new_pow_memory();
        let mut nonce = 0;
        for _ in 0..count {
            loop {
                match super::super::mining::mine_block_database(
                    database,
                    ProgramId([0xa3; kernel::crypto::PROGRAM_ID_SIZE]),
                    nonce,
                    1_000_000,
                    &mut memory,
                )
                .unwrap()
                {
                    super::super::mining::MiningAttempt::Mined => {
                        nonce = 0;
                        break;
                    }
                    super::super::mining::MiningAttempt::Exhausted { next } => nonce = next,
                }
            }
        }
    }

    fn scripted_peer<F>(script: F) -> (std::net::SocketAddr, thread::JoinHandle<()>)
    where
        F: FnOnce(TcpStream) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            script(stream);
        });
        (address, handle)
    }

    fn connect(address: std::net::SocketAddr) -> TcpStream {
        let stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
    }

    #[test]
    fn ambiguous_or_absent_short_ids_are_requested_not_guessed() {
        let (unique, collision, absent): (ShortId, ShortId, ShortId) = ([1; 6], [2; 6], [3; 6]);
        let index = BTreeMap::from([(unique, vec!["one"]), (collision, vec!["two", "three"])]);
        let (found, missing) = match_short_ids(&[unique, collision, absent], &index);
        assert_eq!(found, vec![Some("one"), None, None]);
        assert_eq!(missing, vec![1, 2]);
    }

    #[test]
    fn sender_serves_full_block_when_receiver_requests_fallback() {
        let database = test_database("sender-fallback");
        let block = mine_database_tip(&database);
        let hash = block.hash().unwrap().0;
        let (address, peer) = scripted_peer(move |mut stream| {
            let message = read_frame(&mut stream, 1 + MAX_STORED_BLOCK_SIZE).unwrap();
            assert_eq!(message[0], COMPACT_BLOCK_MESSAGE);
            let compact: CompactBlock = canonical_decode(&message[1..]).unwrap();
            assert_eq!(compact.block_hash, hash);

            let mut request = vec![GET_BLOCK_MESSAGE];
            request.extend_from_slice(&hash);
            write_frame(&mut stream, &request).unwrap();
            let response = read_frame(&mut stream, 1 + MAX_STORED_BLOCK_SIZE).unwrap();
            assert_eq!(response[0], BLOCK_MESSAGE);
            assert_eq!(
                decode_block(&response[1..]).unwrap().hash().unwrap().0,
                hash
            );
            write_frame(&mut stream, &[ACCEPTED_MESSAGE]).unwrap();
        });
        let mut stream = connect(address);
        assert!(
            relay_next_block(
                &database,
                &mut stream,
                Height(0),
                EXPECTED_GENESIS_HASH.0,
                true
            )
            .unwrap()
        );
        peer.join().unwrap();
        crate::storage::release_cached_database(&database);
        std::fs::remove_dir_all(database).unwrap();
    }

    #[test]
    fn gossip_loop_can_pull_and_accept_a_compact_extension() {
        let source = test_database("compact-pull-source");
        let receiver = test_database("compact-pull-receiver");
        let block = mine_database_tip(&source);
        load_or_initialize(&receiver).unwrap();
        let hash = block.hash().unwrap().0;
        let (address, peer) = scripted_peer(move |mut stream| {
            let request = read_frame(&mut stream, 33).unwrap();
            assert_eq!(request[0], GET_COMPACT_BLOCK_MESSAGE);
            assert_eq!(&request[1..], &hash);
            relay_compact_block(&mut stream, &block).unwrap();
        });
        let mut stream = connect(address);
        assert!(request_and_accept_compact_gossip_block(&receiver, &mut stream, hash).is_ok());
        peer.join().unwrap();
        assert_eq!(
            load_or_initialize(&receiver).unwrap().tip_hash().unwrap().0,
            hash
        );
        crate::storage::release_cached_database(&source);
        crate::storage::release_cached_database(&receiver);
        std::fs::remove_dir_all(source).unwrap();
        std::fs::remove_dir_all(receiver).unwrap();
    }

    #[test]
    fn shallow_gossip_fork_reorgs_on_the_existing_session() {
        let local = test_database("shallow-local");
        let remote = test_database("shallow-remote");
        let local_block = mine_database_tip(&local);
        mine_additional_blocks(&local, 1);
        let remote_block_1 = mine_database_tip_with_miner(
            &remote,
            ProgramId([0xa4; kernel::crypto::PROGRAM_ID_SIZE]),
        );
        mine_additional_blocks(&remote, 3);
        let remote_ledger = load_or_initialize(&remote).unwrap();
        let remote_block_2 = remote_ledger.chain.block(&Height(2)).unwrap().clone();
        let remote_block_3 = remote_ledger.chain.block(&Height(3)).unwrap().clone();
        let remote_block_4 = remote_ledger.chain.block(&Height(4)).unwrap().clone();
        let remote_inventory = gossip_inventory(&remote).unwrap();
        let blocks = BTreeMap::from([
            (
                remote_block_1.hash().unwrap().0,
                block_bytes(&remote_block_1).unwrap(),
            ),
            (
                remote_block_2.hash().unwrap().0,
                block_bytes(&remote_block_2).unwrap(),
            ),
            (
                remote_block_3.hash().unwrap().0,
                block_bytes(&remote_block_3).unwrap(),
            ),
            (
                remote_block_4.hash().unwrap().0,
                block_bytes(&remote_block_4).unwrap(),
            ),
        ]);
        let (address, peer) = scripted_peer(move |mut stream| {
            for _ in 0..4 {
                let request = read_frame(&mut stream, 33).unwrap();
                assert_eq!(request[0], GET_BLOCK_MESSAGE);
                let hash: [u8; 32] = request[1..].try_into().unwrap();
                let mut response = vec![BLOCK_MESSAGE];
                response.extend_from_slice(blocks.get(&hash).expect("requested branch block"));
                write_frame(&mut stream, &response).unwrap();
            }
        });
        let mut stream = connect(address);
        assert_eq!(
            try_shallow_gossip_reorg(&local, &mut stream, &remote_inventory).unwrap(),
            Some(4)
        );
        peer.join().unwrap();
        assert_ne!(local_block.hash().unwrap(), remote_block_1.hash().unwrap());
        assert_eq!(
            load_or_initialize(&local).unwrap().tip_hash().unwrap().0,
            remote_inventory.tip_hash
        );
        crate::storage::release_cached_database(&local);
        crate::storage::release_cached_database(&remote);
        std::fs::remove_dir_all(local).unwrap();
        std::fs::remove_dir_all(remote).unwrap();
    }

    #[test]
    fn duplicate_short_ids_fall_back_to_and_accept_the_full_block() {
        let database = test_database("receiver-fallback");
        load_or_initialize(&database).unwrap();
        let block = next_block(&database);
        let hash = block.hash().unwrap().0;
        let mut compact = compact_block(&block).unwrap();
        compact.short_ids = vec![[9; 6], [9; 6]];
        let encoded = canonical_bytes(&compact).unwrap();
        let full_block = block_bytes(&block).unwrap();
        let (address, peer) = scripted_peer(move |mut stream| {
            let request = read_frame(&mut stream, 33).unwrap();
            assert_eq!(request[0], GET_BLOCK_MESSAGE);
            assert_eq!(&request[1..], &hash);
            let mut response = vec![BLOCK_MESSAGE];
            response.extend_from_slice(&full_block);
            write_frame(&mut stream, &response).unwrap();
        });
        let mut stream = connect(address);
        assert!(accept_compact_block(&database, &mut stream, &encoded).is_ok());
        peer.join().unwrap();
        assert_eq!(
            load_or_initialize(&database).unwrap().tip_hash().unwrap().0,
            hash
        );
        crate::storage::release_cached_database(&database);
        std::fs::remove_dir_all(database).unwrap();
    }

    #[test]
    fn invalid_full_block_from_fallback_is_returned_as_an_error() {
        let database = test_database("receiver-invalid-fallback");
        load_or_initialize(&database).unwrap();
        let block = next_block(&database);
        let compact = compact_block(&block).unwrap();
        let encoded = canonical_bytes(&CompactBlock {
            short_ids: vec![[7; 6], [7; 6]],
            ..compact
        })
        .unwrap();
        let mut full_block = block_bytes(&block).unwrap();
        let last = full_block.len() - 1;
        full_block[last] ^= 1;
        let (address, peer) = scripted_peer(move |mut stream| {
            let _ = read_frame(&mut stream, 33).unwrap();
            let mut response = vec![BLOCK_MESSAGE];
            response.extend_from_slice(&full_block);
            write_frame(&mut stream, &response).unwrap();
        });
        let mut stream = connect(address);
        assert!(accept_compact_block(&database, &mut stream, &encoded).is_err());
        peer.join().unwrap();
        assert_eq!(
            load_or_initialize(&database).unwrap().tip_height(),
            Some(Height(0))
        );
        crate::storage::release_cached_database(&database);
        std::fs::remove_dir_all(database).unwrap();
    }
}
