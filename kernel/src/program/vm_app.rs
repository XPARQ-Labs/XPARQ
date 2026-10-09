//! XPVM v4: bounded application bytecode executed with kernel-created call frames.
//! No instruction can supply its own caller identity or mutate another program's storage.
use crate::{
    common::Owner,
    ledger::{CoinRollbackJournal, LedgerState},
    monetary::{
        asset::{AssetContract, AssetOutput, Unit},
        coin::{CoinShare, Zeno},
    },
    program::{
        AuthorizationCommitment, AuthorizedProgramInvocation, ProgramId, ProgramJournal,
        application::ApplicationExecutor,
        system::asset_program::{
            state::{AssetJournal, ExecutionContext},
            type_::{AssetCall, Burn, Transfer},
        },
        vm::{self, CodeError, ExecutionError, ValidatedCode},
    },
};
use borsh::BorshDeserialize;
use crypto::canonical_bytes;
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    io::{Error, ErrorKind, Read},
};

pub const MAX_DATA_BYTES: usize = 4096;
pub const MAX_CODE_BYTES: usize = 65_536;
pub const MAX_INSTRUCTIONS: usize = 4096;
pub const MAX_KEY_BYTES: usize = 128;
pub const MAX_STORAGE_ENTRIES: usize = 4096;
pub const MAX_STORAGE_BYTES: usize = 1_048_576;
pub const MAX_CALL_DEPTH: usize = 8;
pub const MAX_CALLS: usize = 64;
pub const MAX_ACTIONS: usize = 256;
pub const CALL_COST: u64 = 20;
const HEADER: usize = 13;
type Storage = BTreeMap<Vec<u8>, Vec<u8>>;
type CoinAccount = (u64, BTreeSet<(Reverse<u64>, CoinShare)>);
type AssetAccount = (
    u128,
    BTreeSet<(Reverse<u128>, crate::monetary::asset::Share)>,
);

pub fn valid_storage(storage: &Storage) -> bool {
    storage.len() <= MAX_STORAGE_ENTRIES
        && storage.iter().all(|(k, v)| {
            !k.is_empty() && k.len() <= MAX_KEY_BYTES && !v.is_empty() && v.len() <= MAX_DATA_BYTES
        })
        && storage
            .iter()
            .map(|(k, v)| 8 + k.len() + v.len())
            .sum::<usize>()
            + 4
            <= MAX_STORAGE_BYTES
}
pub(crate) fn read_storage<R: Read>(reader: &mut R) -> std::io::Result<Storage> {
    fn bytes<R: Read>(r: &mut R, max: usize) -> std::io::Result<Vec<u8>> {
        let n = u32::deserialize_reader(r)? as usize;
        if n == 0 || n > max {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "invalid VM storage length",
            ));
        }
        let mut value = vec![0; n];
        r.read_exact(&mut value)?;
        Ok(value)
    }
    let count = u32::deserialize_reader(reader)? as usize;
    if count > MAX_STORAGE_ENTRIES {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "too many VM storage entries",
        ));
    }
    let mut map = Storage::new();
    let mut size = 4usize;
    for _ in 0..count {
        let key = bytes(reader, MAX_KEY_BYTES)?;
        if map.last_key_value().is_some_and(|(last, _)| last >= &key) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "noncanonical VM storage keys",
            ));
        }
        let value = bytes(reader, MAX_DATA_BYTES)?;
        size += 8 + key.len() + value.len();
        if size > MAX_STORAGE_BYTES {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "VM storage exceeds limit",
            ));
        }
        map.insert(key, value);
    }
    Ok(map)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Int(u128),
    Bytes(Vec<u8>),
    Owner(Owner),
}
impl Value {
    fn int(self) -> Result<u128, ExecutionError> {
        if let Self::Int(v) = self {
            Ok(v)
        } else {
            Err(ExecutionError::InvalidOperand)
        }
    }
    fn bytes(self) -> Result<Vec<u8>, ExecutionError> {
        if let Self::Bytes(v) = self {
            Ok(v)
        } else {
            Err(ExecutionError::InvalidOperand)
        }
    }
    fn owner(self) -> Result<Owner, ExecutionError> {
        if let Self::Owner(v) = self {
            Ok(v)
        } else {
            Err(ExecutionError::InvalidOperand)
        }
    }
    fn size(&self) -> usize {
        match self {
            Self::Int(_) => 16,
            Self::Owner(_) => 33,
            Self::Bytes(v) => v.len(),
        }
    }
}
#[derive(Clone)]
struct Instruction {
    op: u8,
    immediate: Vec<u8>,
    next: usize,
}
fn instructions(code: &[u8]) -> Result<BTreeMap<usize, Instruction>, CodeError> {
    if code.len() < HEADER || code[..4] != vm::MAGIC || code[4] != vm::APPLICATION_VERSION {
        return Err(CodeError::InvalidHeader);
    }
    if code.len() > MAX_CODE_BYTES {
        return Err(CodeError::InvalidLimit);
    }
    let mut pc = HEADER;
    let mut decoded = BTreeMap::new();
    let mut has_return = false;
    while pc < code.len() {
        if decoded.len() >= MAX_INSTRUCTIONS {
            return Err(CodeError::InvalidLimit);
        }
        let start = pc;
        let op = code[pc];
        pc += 1;
        let n = match op {
            0x01 => 16,
            0x11 => 33,
            0x20 | 0x21 => 4,
            0x10 => {
                let prefix = code.get(pc..pc + 2).ok_or(CodeError::InvalidInstruction)?;
                pc += 2;
                let len = u16::from_le_bytes(prefix.try_into().unwrap()) as usize;
                if len > MAX_DATA_BYTES {
                    return Err(CodeError::InvalidLimit);
                }
                len
            }
            0x00 | 0x02..=0x05 | 0x12..=0x19 | 0x22..=0x2b | 0x30..=0x37 | 0x40..=0x4b => 0,
            _ => return Err(CodeError::InvalidInstruction),
        };
        let immediate = code
            .get(pc..pc + n)
            .ok_or(CodeError::InvalidInstruction)?
            .to_vec();
        pc += n;
        if op == 0x11 {
            Owner::try_from_slice(&immediate).map_err(|_| CodeError::InvalidInstruction)?;
        }
        has_return |= op == 0x03;
        decoded.insert(
            start,
            Instruction {
                op,
                immediate,
                next: pc,
            },
        );
    }
    for i in decoded.values().filter(|i| i.op == 0x20 || i.op == 0x21) {
        let target = HEADER
            .checked_add(u32::from_le_bytes(i.immediate[..].try_into().unwrap()) as usize)
            .ok_or(CodeError::InvalidEntry)?;
        if !decoded.contains_key(&target) {
            return Err(CodeError::InvalidEntry);
        }
    }
    if !has_return {
        return Err(CodeError::MissingReturn);
    }
    Ok(decoded)
}
pub fn validate_code(code: &[u8]) -> Result<ValidatedCode, CodeError> {
    let decoded = instructions(code)?;
    let stack = u16::from_le_bytes([code[5], code[6]]);
    let pages = u16::from_le_bytes([code[7], code[8]]);
    if stack == 0 || stack > vm::MAX_STACK_ITEMS || pages == 0 || pages > vm::MAX_MEMORY_PAGES {
        return Err(CodeError::InvalidLimit);
    }
    let entry = u32::from_le_bytes(code[9..13].try_into().unwrap());
    if entry != 0 || !decoded.contains_key(&HEADER) {
        return Err(CodeError::InvalidEntry);
    }
    Ok(ValidatedCode {
        entry,
        max_stack: stack,
        memory_pages: pages,
        instruction_count: decoded.len() as u32,
        instruction_fuel: 0,
    })
}

pub struct AppliedVm {
    pub value: u128,
    pub fuel_used: u64,
    pub quote: super::vm_transfer::TransferQuote,
    pub(crate) coin: CoinRollbackJournal,
    pub(crate) asset: Option<AssetJournal>,
    pub(crate) program: Option<ProgramJournal>,
}
struct Engine<'a> {
    state: &'a mut LedgerState,
    apps: &'a dyn ApplicationExecutor,
    signer: ProgramId,
    height: u64,
    commitment: AuthorizationCommitment,
    fuel: u64,
    calls: usize,
    actions: usize,
    active: Vec<ProgramId>,
    accounts_ready: BTreeSet<ProgramId>,
    // Per-invocation lookup cache, rebuilt from canonical state. Never serialized.
    coins: BTreeMap<ProgramId, CoinAccount>,
    assets: BTreeMap<(ProgramId, AssetContract), AssetAccount>,
    consumed: BTreeMap<CoinShare, crate::ledger::CoinUtxo>,
    created: BTreeSet<CoinShare>,
    asset: Option<AssetJournal>,
    states: BTreeMap<ProgramId, i64>,
    storage: BTreeMap<(ProgramId, Vec<u8>), Option<Vec<u8>>>,
}
impl Engine<'_> {
    fn ensure_accounts(&mut self, id: ProgramId) -> Result<(), ExecutionError> {
        if self.accounts_ready.contains(&id) {
            return Ok(());
        }
        for (share, value) in self.state.utxos.coins_by_owner(Owner::Program(id)) {
            let account = self.coins.entry(id).or_default();
            account.0 = account
                .0
                .checked_add(value.amount.as_zeno())
                .ok_or(ExecutionError::ArithmeticOverflow)?;
            account.1.insert((Reverse(value.amount.as_zeno()), share));
        }
        for (share, value) in self
            .state
            .extensions
            .assets
            .shares_by_owner(Owner::Program(id))
        {
            let account = self.assets.entry((id, value.asset)).or_default();
            account.0 = account
                .0
                .checked_add(value.amount.as_units())
                .ok_or(ExecutionError::ArithmeticOverflow)?;
            account.1.insert((Reverse(value.amount.as_units()), share));
        }
        self.accounts_ready.insert(id);
        Ok(())
    }
    fn charge(&mut self, n: u64) -> Result<(), ExecutionError> {
        self.fuel = self.fuel.checked_sub(n).ok_or(ExecutionError::OutOfFuel)?;
        Ok(())
    }
    fn action(&mut self) -> Result<(), ExecutionError> {
        self.actions += 1;
        if self.actions > MAX_ACTIONS {
            Err(ExecutionError::ResourceLimit)
        } else {
            Ok(())
        }
    }
    fn merge_asset(&mut self, journal: AssetJournal) -> Result<(), ExecutionError> {
        for (share, previous) in journal.share_changes() {
            if let Some(value) = previous
                && self.accounts_ready.contains(&value.owner.program())
            {
                let id = value.owner.program();
                let account = self.assets.entry((id, value.asset)).or_default();
                account.0 = account
                    .0
                    .checked_sub(value.amount.as_units())
                    .ok_or(ExecutionError::SettlementFailed)?;
                account.1.remove(&(Reverse(value.amount.as_units()), share));
            }
            if let Some(value) = self.state.extensions.assets.shares().get(&share)
                && self.accounts_ready.contains(&value.owner.program())
            {
                let id = value.owner.program();
                let account = self.assets.entry((id, value.asset)).or_default();
                account.0 = account
                    .0
                    .checked_add(value.amount.as_units())
                    .ok_or(ExecutionError::ArithmeticOverflow)?;
                account.1.insert((Reverse(value.amount.as_units()), share));
            }
        }
        self.asset = Some(match self.asset.take() {
            Some(previous) => previous.merge(journal),
            None => journal,
        });
        Ok(())
    }
    fn settle(
        &mut self,
        id: ProgramId,
        result: &vm::ExecutionResult,
        legacy_root: bool,
    ) -> Result<(), ExecutionError> {
        self.ensure_accounts(id)?;
        let mut selected = Vec::new();
        if let Some(request) = result.coin_transfer {
            let mut total = 0u64;
            // v4 selects largest amounts first, then share ID. Fee changes alter newly created IDs,
            // but cannot alter selected amounts/counts and make quotes oscillate.
            let candidates = if legacy_root {
                self.state
                    .utxos
                    .coins_by_owner(Owner::Program(id))
                    .take(super::vm_transfer::MAX_TRANSFER_INPUTS)
                    .map(|(share, _)| share)
                    .collect::<Vec<_>>()
            } else {
                self.coins
                    .get(&id)
                    .map(|v| {
                        v.1.iter()
                            .take(super::vm_transfer::MAX_TRANSFER_INPUTS)
                            .map(|(_, share)| *share)
                            .collect()
                    })
                    .unwrap_or_default()
            };
            for share in candidates {
                let value = self
                    .state
                    .utxos
                    .coin(&share)
                    .ok_or(ExecutionError::SettlementFailed)?;
                selected.push(share);
                total = total
                    .checked_add(value.amount.as_zeno())
                    .ok_or(ExecutionError::ArithmeticOverflow)?;
                if total >= request.amount {
                    break;
                }
            }
            if !legacy_root {
                self.charge(selected.len() as u64)?;
            }
        }
        self.action()?;
        let commitment = if legacy_root {
            self.commitment
        } else {
            let bytes =
                canonical_bytes(&(b"xparq:vm-effects:v4", self.commitment, self.actions as u64))
                    .map_err(|_| ExecutionError::SettlementFailed)?;
            AuthorizationCommitment::from_bytes(
                crypto::domain(crypto::HashDomain::AssetIntent, &bytes).into_bytes(),
            )
        };
        let (coin, asset) = super::vm_transfer::settle_with_inputs(
            self.state,
            id,
            result,
            commitment,
            self.apps,
            Some(&selected),
        )
        .map_err(|_| ExecutionError::SettlementFailed)?;
        for (share, value) in coin.consumed_coins {
            if self.accounts_ready.contains(&value.owner.program()) {
                let id = value.owner.program();
                let account = self.coins.entry(id).or_default();
                account.0 = account
                    .0
                    .checked_sub(value.amount.as_zeno())
                    .ok_or(ExecutionError::SettlementFailed)?;
                account.1.remove(&(Reverse(value.amount.as_zeno()), share));
            }
            if !self.created.remove(&share) {
                self.consumed.entry(share).or_insert(value);
            }
        }
        for share in coin.created_coin_ids {
            let value = self
                .state
                .utxos
                .coin(&share)
                .ok_or(ExecutionError::SettlementFailed)?;
            if self.accounts_ready.contains(&value.owner.program()) {
                let id = value.owner.program();
                let account = self.coins.entry(id).or_default();
                account.0 = account
                    .0
                    .checked_add(value.amount.as_zeno())
                    .ok_or(ExecutionError::ArithmeticOverflow)?;
                account.1.insert((Reverse(value.amount.as_zeno()), share));
            }
            self.created.insert(share);
        }
        if let Some(asset) = asset {
            self.merge_asset(asset)?;
        }
        Ok(())
    }
    fn transfer_asset(
        &mut self,
        id: ProgramId,
        asset: AssetContract,
        recipient: Owner,
        amount: u128,
    ) -> Result<(), ExecutionError> {
        self.ensure_accounts(id)?;
        if amount == 0 {
            return Err(ExecutionError::InvalidOperand);
        }
        self.action()?;
        let actor = Owner::Program(id);
        let mut inputs = Vec::new();
        let mut total = 0u128;
        if let Some(account) = self.assets.get(&(id, asset)) {
            for (_, share) in account
                .1
                .iter()
                .take(super::vm_transfer::MAX_TRANSFER_INPUTS)
            {
                let value = self
                    .state
                    .extensions
                    .assets
                    .shares()
                    .get(share)
                    .ok_or(ExecutionError::SettlementFailed)?;
                inputs.push(*share);
                total = total
                    .checked_add(value.amount.as_units())
                    .ok_or(ExecutionError::ArithmeticOverflow)?;
                if total >= amount {
                    break;
                }
            }
        }
        self.charge(inputs.len() as u64)?;
        let change = total
            .checked_sub(amount)
            .ok_or(ExecutionError::SettlementFailed)?;
        let mut outputs = vec![AssetOutput::new(recipient, Unit::from_units(amount))];
        if change != 0 {
            outputs.push(AssetOutput::new(actor, Unit::from_units(change)));
        }
        let bytes = canonical_bytes(&(
            b"xparq:vm-asset-transfer:v4",
            self.commitment,
            self.actions as u64,
        ))
        .map_err(|_| ExecutionError::SettlementFailed)?;
        let journal = super::asset_host::execute_asset(
            self.apps,
            &mut self.state.extensions.assets,
            &AssetCall::Transfer(Transfer {
                asset,
                inputs,
                outputs,
            }),
            ExecutionContext {
                actor,
                commitment: crypto::domain(crypto::HashDomain::AssetIntent, &bytes).into_bytes(),
            },
        )
        .map_err(|_| ExecutionError::SettlementFailed)?;
        self.merge_asset(journal)?;
        Ok(())
    }
    fn burn_asset(
        &mut self,
        id: ProgramId,
        asset: AssetContract,
        amount: u128,
    ) -> Result<(), ExecutionError> {
        self.ensure_accounts(id)?;
        if amount == 0 {
            return Err(ExecutionError::InvalidOperand);
        }
        self.action()?;
        let mut inputs = Vec::new();
        let mut total = 0u128;
        if let Some(account) = self.assets.get(&(id, asset)) {
            for (_, share) in account
                .1
                .iter()
                .take(super::vm_transfer::MAX_TRANSFER_INPUTS)
            {
                let value = self
                    .state
                    .extensions
                    .assets
                    .shares()
                    .get(share)
                    .ok_or(ExecutionError::SettlementFailed)?;
                inputs.push(*share);
                total = total
                    .checked_add(value.amount.as_units())
                    .ok_or(ExecutionError::ArithmeticOverflow)?;
                if total >= amount {
                    break;
                }
            }
        }
        self.charge(inputs.len() as u64)?;
        let output = total
            .checked_sub(amount)
            .ok_or(ExecutionError::SettlementFailed)?;
        let bytes = canonical_bytes(&(
            b"xparq:vm-asset-burn:v4",
            self.commitment,
            self.actions as u64,
        ))
        .map_err(|_| ExecutionError::SettlementFailed)?;
        let journal = super::asset_host::execute_asset(
            self.apps,
            &mut self.state.extensions.assets,
            &AssetCall::Burn(Burn {
                asset,
                inputs,
                amount: Unit::from_units(amount),
                output: Unit::from_units(output),
            }),
            ExecutionContext {
                actor: Owner::Program(id),
                commitment: crypto::domain(crypto::HashDomain::AssetIntent, &bytes).into_bytes(),
            },
        )
        .map_err(|_| ExecutionError::SettlementFailed)?;
        self.merge_asset(journal)
    }
    fn call(
        &mut self,
        id: ProgramId,
        caller: Owner,
        data: &[u8],
        deposit: u64,
    ) -> Result<u128, ExecutionError> {
        if data.len() > MAX_DATA_BYTES
            || self.active.len() >= MAX_CALL_DEPTH
            || self.calls >= MAX_CALLS
        {
            return Err(ExecutionError::ResourceLimit);
        }
        if self.active.contains(&id) {
            return Err(ExecutionError::ReentrantCall);
        }
        let record = self
            .state
            .programs
            .program(&id)
            .ok_or(ExecutionError::UnknownProgram)?;
        let code = record.code.clone();
        self.calls += 1;
        self.active.push(id);
        let result = if code[4] != vm::APPLICATION_VERSION {
            if !data.is_empty() {
                return Err(ExecutionError::InvalidOperand);
            }
            let result = vm::execute_registered(&self.state.programs, id, self.fuel)?;
            self.charge(result.fuel_used)?;
            let root = self.active.len() == 1;
            if result.has_monetary_effects() {
                self.settle(id, &result, root)?;
            }
            if let Some(vm::VmEffect::ProgramState(value)) = result.proposed_effect {
                let before = self
                    .state
                    .programs
                    .set_state(id, value)
                    .ok_or(ExecutionError::UnknownProgram)?;
                self.states.entry(id).or_insert(before);
            }
            Ok(result.value as u128)
        } else {
            self.interpret(id, caller, data, deposit, &code)
        };
        self.active.pop();
        result
    }
    fn interpret(
        &mut self,
        id: ProgramId,
        caller: Owner,
        data: &[u8],
        deposit: u64,
        code: &[u8],
    ) -> Result<u128, ExecutionError> {
        let limits = validate_code(code).map_err(ExecutionError::InvalidCode)?;
        let decoded = instructions(code).map_err(ExecutionError::InvalidCode)?;
        self.charge(u64::from(limits.memory_pages) * vm::MEMORY_PAGE_COST)?;
        let mut stack: Vec<Value> = Vec::new();
        let mut pc = HEADER;
        fn pop(stack: &mut Vec<Value>) -> Result<Value, ExecutionError> {
            stack.pop().ok_or(ExecutionError::InvalidOperand)
        }
        loop {
            let i = decoded.get(&pc).ok_or(ExecutionError::InvalidOperand)?;
            self.charge(match i.op {
                0x30 => vm::STATE_READ_COST,
                0x31 | 0x32 => vm::STATE_WRITE_COST,
                0x40..=0x42 | 0x4b => vm::TRANSFER_COST,
                0x43 => CALL_COST,
                _ => vm::INSTRUCTION_COST,
            })?;
            pc = i.next;
            match i.op {
                0x00 => {}
                0x01 => stack.push(Value::Int(u128::from_le_bytes(
                    i.immediate[..].try_into().unwrap(),
                ))),
                0x02 | 0x24..=0x28 => {
                    let right = pop(&mut stack)?.int()?;
                    let left = pop(&mut stack)?.int()?;
                    let value = match i.op {
                        0x02 => left.checked_add(right),
                        0x24 => left.checked_sub(right),
                        0x25 => left.checked_mul(right),
                        0x26 => left.checked_div(right),
                        0x27 => Some(u128::from(left < right)),
                        _ => Some(u128::from(left <= right)),
                    }
                    .ok_or(ExecutionError::ArithmeticOverflow)?;
                    stack.push(Value::Int(value));
                }
                0x03 => {
                    if stack.len() != 1 {
                        return Err(ExecutionError::InvalidOperand);
                    }
                    return pop(&mut stack)?.int();
                }
                0x04 => stack.push(Value::Int(
                    self.state.programs.program(&id).unwrap().state_value as u128,
                )),
                0x05 => {
                    self.action()?;
                    let n = i64::try_from(pop(&mut stack)?.int()?)
                        .map_err(|_| ExecutionError::ArithmeticOverflow)?;
                    let before = self.state.programs.set_state(id, n).unwrap();
                    self.states.entry(id).or_insert(before);
                }
                0x10 => {
                    self.charge(i.immediate.len() as u64)?;
                    stack.push(Value::Bytes(i.immediate.clone()));
                }
                0x11 => stack.push(Value::Owner(Owner::try_from_slice(&i.immediate).unwrap())),
                0x12 => stack.push(Value::Owner(caller)),
                0x13 => stack.push(Value::Owner(Owner::Program(id))),
                0x14 => stack.push(Value::Owner(Owner::Program(self.signer))),
                0x15 => {
                    self.charge(data.len() as u64)?;
                    stack.push(Value::Bytes(data.to_vec()));
                }
                0x16 => {
                    let value = stack.last().ok_or(ExecutionError::InvalidOperand)?.clone();
                    if let Value::Bytes(bytes) = &value {
                        self.charge(bytes.len() as u64)?;
                    }
                    stack.push(value);
                }
                0x17 => {
                    pop(&mut stack)?;
                }
                0x18 => {
                    let n = stack.len();
                    if n < 2 {
                        return Err(ExecutionError::InvalidOperand);
                    }
                    stack.swap(n - 1, n - 2);
                }
                0x19 => {
                    let r = pop(&mut stack)?;
                    let l = pop(&mut stack)?;
                    stack.push(Value::Int(u128::from(l == r)));
                }
                0x20 => {
                    pc = HEADER + u32::from_le_bytes(i.immediate[..].try_into().unwrap()) as usize
                }
                0x21 => {
                    if pop(&mut stack)?.int()? == 0 {
                        pc = HEADER
                            + u32::from_le_bytes(i.immediate[..].try_into().unwrap()) as usize;
                    }
                }
                0x22 => {
                    if pop(&mut stack)?.int()? == 0 {
                        return Err(ExecutionError::Reverted);
                    }
                }
                0x23 => return Err(ExecutionError::Reverted),
                0x29 => {
                    let bytes = pop(&mut stack)?.bytes()?;
                    let n = if bytes.is_empty() {
                        0
                    } else {
                        u128::from_le_bytes(
                            bytes
                                .try_into()
                                .map_err(|_| ExecutionError::InvalidOperand)?,
                        )
                    };
                    stack.push(Value::Int(n));
                }
                0x2a => {
                    let n = pop(&mut stack)?.int()?;
                    stack.push(Value::Bytes(n.to_le_bytes().to_vec()));
                }
                0x2b => {
                    let right = pop(&mut stack)?.bytes()?;
                    let mut left = pop(&mut stack)?.bytes()?;
                    if left.len() + right.len() > MAX_DATA_BYTES {
                        return Err(ExecutionError::ResourceLimit);
                    }
                    self.charge((left.len() + right.len()) as u64)?;
                    left.extend(right);
                    stack.push(Value::Bytes(left));
                }
                0x30 => {
                    let key = pop(&mut stack)?.bytes()?;
                    check_key(&key)?;
                    let value = self
                        .state
                        .programs
                        .program(&id)
                        .unwrap()
                        .storage
                        .get(&key)
                        .cloned()
                        .unwrap_or_default();
                    self.charge((key.len() + value.len()) as u64)?;
                    stack.push(Value::Bytes(value));
                }
                0x31 | 0x32 => {
                    let value = if i.op == 0x31 {
                        Some(pop(&mut stack)?.bytes()?)
                    } else {
                        None
                    };
                    let key = pop(&mut stack)?.bytes()?;
                    check_key(&key)?;
                    if value
                        .as_ref()
                        .is_some_and(|v| v.is_empty() || v.len() > MAX_DATA_BYTES)
                    {
                        return Err(ExecutionError::InvalidOperand);
                    }
                    self.charge((key.len() + value.as_ref().map_or(0, Vec::len)) as u64)?;
                    self.action()?;
                    let previous = self
                        .state
                        .programs
                        .program(&id)
                        .unwrap()
                        .storage
                        .get(&key)
                        .cloned();
                    self.storage.entry((id, key.clone())).or_insert(previous);
                    self.state
                        .programs
                        .set_storage(id, key, value)
                        .map_err(|_| ExecutionError::SettlementFailed)?;
                    if !valid_storage(&self.state.programs.program(&id).unwrap().storage) {
                        return Err(ExecutionError::ResourceLimit);
                    }
                }
                0x33 => {
                    let value = pop(&mut stack)?.owner()?;
                    stack.push(Value::Bytes(
                        canonical_bytes(&value).map_err(|_| ExecutionError::InvalidOperand)?,
                    ));
                }
                0x34 => {
                    let bytes = pop(&mut stack)?.bytes()?;
                    stack.push(Value::Owner(
                        Owner::try_from_slice(&bytes)
                            .map_err(|_| ExecutionError::InvalidOperand)?,
                    ));
                }
                0x35 => {
                    let len = usize::try_from(pop(&mut stack)?.int()?)
                        .map_err(|_| ExecutionError::InvalidOperand)?;
                    let start = usize::try_from(pop(&mut stack)?.int()?)
                        .map_err(|_| ExecutionError::InvalidOperand)?;
                    let bytes = pop(&mut stack)?.bytes()?;
                    let end = start
                        .checked_add(len)
                        .ok_or(ExecutionError::InvalidOperand)?;
                    let slice = bytes
                        .get(start..end)
                        .ok_or(ExecutionError::InvalidOperand)?;
                    self.charge(len as u64)?;
                    stack.push(Value::Bytes(slice.to_vec()));
                }
                0x36 => {
                    let bytes = pop(&mut stack)?.bytes()?;
                    stack.push(Value::Int(bytes.len() as u128));
                }
                0x37 => {
                    let bytes = pop(&mut stack)?.bytes()?;
                    self.charge(bytes.len() as u64)?;
                    stack.push(Value::Bytes(
                        crypto::hash_bytes(&bytes).into_bytes().to_vec(),
                    ));
                }
                0x45 => {
                    let bytes = pop(&mut stack)?.bytes()?;
                    self.charge(bytes.len() as u64 + vm::ASSET_REGISTER_COST)?;
                    let mut reader = &bytes[..];
                    let request = vm::decode_register_request(&mut reader)
                        .map_err(ExecutionError::InvalidCode)?;
                    if !reader.is_empty() {
                        return Err(ExecutionError::InvalidOperand);
                    }
                    let actor = Owner::Program(id);
                    let metadata = crate::monetary::asset::Metadata::new(
                        request.name.clone(),
                        request.max_supply,
                        actor,
                        actor,
                    )
                    .map_err(|_| ExecutionError::InvalidOperand)?;
                    let asset = AssetContract::derive(&metadata, request.nonce)
                        .map_err(|_| ExecutionError::InvalidOperand)?;
                    self.settle(
                        id,
                        &vm::ExecutionResult {
                            value: 0,
                            fuel_used: 0,
                            proposed_effect: None,
                            coin_transfer: None,
                            asset_transfer: None,
                            asset_register: Some(request),
                            asset_mint: None,
                        },
                        false,
                    )?;
                    stack.push(Value::Bytes(
                        canonical_bytes(&asset).map_err(|_| ExecutionError::InvalidOperand)?,
                    ));
                }
                0x46 => {
                    self.ensure_accounts(id)?;
                    let asset = asset_id(pop(&mut stack)?.bytes()?)?;
                    stack.push(Value::Int(self.assets.get(&(id, asset)).map_or(0, |v| v.0)));
                }
                0x47 => {
                    self.ensure_accounts(id)?;
                    stack.push(Value::Int(u128::from(
                        self.coins.get(&id).map_or(0, |v| v.0),
                    )));
                }
                0x40 => {
                    let amount = u64::try_from(pop(&mut stack)?.int()?)
                        .map_err(|_| ExecutionError::ArithmeticOverflow)?;
                    let recipient = pop(&mut stack)?.owner()?;
                    if amount == 0 {
                        return Err(ExecutionError::InvalidOperand);
                    }
                    self.settle(
                        id,
                        &vm::ExecutionResult {
                            value: 0,
                            fuel_used: 0,
                            proposed_effect: None,
                            coin_transfer: Some(vm::TransferRequest { recipient, amount }),
                            asset_transfer: None,
                            asset_register: None,
                            asset_mint: None,
                        },
                        false,
                    )?;
                }
                0x41 => {
                    let amount = pop(&mut stack)?.int()?;
                    let recipient = pop(&mut stack)?.owner()?;
                    let asset = asset_id(pop(&mut stack)?.bytes()?)?;
                    self.transfer_asset(id, asset, recipient, amount)?;
                }
                0x42 => {
                    let amount = pop(&mut stack)?.int()?;
                    let recipient = pop(&mut stack)?.owner()?;
                    let asset = asset_id(pop(&mut stack)?.bytes()?)?;
                    self.settle(
                        id,
                        &vm::ExecutionResult {
                            value: 0,
                            fuel_used: 0,
                            proposed_effect: None,
                            coin_transfer: None,
                            asset_transfer: None,
                            asset_register: None,
                            asset_mint: Some(vm::MintAssetRequest {
                                asset: vm::MintAssetTarget::Existing(asset),
                                recipient,
                                amount: Unit::from_units(amount),
                            }),
                        },
                        false,
                    )?;
                }
                0x43 => {
                    let input = pop(&mut stack)?.bytes()?;
                    let target = pop(&mut stack)?.owner()?.program();
                    self.charge(input.len() as u64)?;
                    let value = self.call(target, Owner::Program(id), &input, 0)?;
                    stack.push(Value::Int(value));
                }
                0x48 => {
                    let amount = u64::try_from(pop(&mut stack)?.int()?)
                        .map_err(|_| ExecutionError::ArithmeticOverflow)?;
                    let input = pop(&mut stack)?.bytes()?;
                    let target = pop(&mut stack)?.owner()?.program();
                    self.charge(CALL_COST + vm::TRANSFER_COST + input.len() as u64)?;
                    if amount == 0 {
                        return Err(ExecutionError::InvalidOperand);
                    }
                    self.settle(
                        id,
                        &vm::ExecutionResult {
                            value: 0,
                            fuel_used: 0,
                            proposed_effect: None,
                            coin_transfer: Some(vm::TransferRequest {
                                recipient: Owner::Program(target),
                                amount,
                            }),
                            asset_transfer: None,
                            asset_register: None,
                            asset_mint: None,
                        },
                        false,
                    )?;
                    let value = self.call(target, Owner::Program(id), &input, amount)?;
                    stack.push(Value::Int(value));
                }
                0x4b => {
                    let amount = pop(&mut stack)?.int()?;
                    let asset = asset_id(pop(&mut stack)?.bytes()?)?;
                    self.burn_asset(id, asset, amount)?;
                }
                0x4a => stack.push(Value::Owner(Owner::Program(
                    self.state.programs.program(&id).unwrap().owner,
                ))),
                0x49 => stack.push(Value::Int(u128::from(self.height))),
                0x44 => stack.push(Value::Int(u128::from(deposit))),
                _ => return Err(ExecutionError::InvalidOperand),
            }
            if stack.len() > usize::from(limits.max_stack)
                || stack.iter().map(Value::size).sum::<usize>()
                    > usize::from(limits.memory_pages) * vm::PAGE_BYTES
            {
                return Err(ExecutionError::ResourceLimit);
            }
        }
    }
}
fn check_key(key: &[u8]) -> Result<(), ExecutionError> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        Err(ExecutionError::InvalidOperand)
    } else {
        Ok(())
    }
}
fn asset_id(bytes: Vec<u8>) -> Result<AssetContract, ExecutionError> {
    AssetContract::try_from_slice(&bytes).map_err(|_| ExecutionError::InvalidOperand)
}

/// Root identity and deposits are derived from the signed envelope, never calldata.
/// Used only on a disposable preview or the kernel's atomic staging state.
pub(crate) fn apply(
    state: &mut LedgerState,
    tx: &AuthorizedProgramInvocation,
    height: u64,
    commitment: AuthorizationCommitment,
    apps: &dyn ApplicationExecutor,
) -> Result<AppliedVm, ExecutionError> {
    let (id, data) = call_input(&tx.call).map_err(|_| ExecutionError::InvalidOperand)?;
    let deposit = tx
        .payment
        .coin_parts()
        .ok_or(ExecutionError::InvalidOperand)?
        .1
        .iter()
        .filter(|o| o.output == Owner::Program(id))
        .try_fold(0u64, |sum, o| sum.checked_add(o.amount.as_zeno()))
        .ok_or(ExecutionError::ArithmeticOverflow)?;
    let mut engine = Engine {
        state,
        apps,
        signer: tx.signer,
        height,
        commitment,
        fuel: vm::MAX_CALL_FUEL,
        calls: 0,
        actions: 0,
        active: Vec::new(),
        accounts_ready: BTreeSet::new(),
        coins: BTreeMap::new(),
        assets: BTreeMap::new(),
        consumed: BTreeMap::new(),
        created: BTreeSet::new(),
        asset: None,
        states: BTreeMap::new(),
        storage: BTreeMap::new(),
    };
    let value = engine.call(id, Owner::Program(tx.signer), data, deposit)?;
    let mut delta = if let Some(journal) = engine.asset.as_ref() {
        journal
            .canonical_delta(&engine.state.extensions.assets)
            .map_err(|_| ExecutionError::SettlementFailed)?
    } else {
        0
    };
    for ((id, key), previous) in &engine.storage {
        let record = engine
            .state
            .programs
            .program(id)
            .ok_or(ExecutionError::UnknownProgram)?;
        let width = |value: Option<&Vec<u8>>| value.map_or(0, |v| 8 + key.len() + v.len()) as i128;
        delta = delta
            .checked_add(width(record.storage.get(key)) - width(previous.as_ref()))
            .ok_or(ExecutionError::ArithmeticOverflow)?;
    }
    let quote = super::vm_transfer::TransferQuote {
        created_coin_utxos: engine.created.len() as u64,
        consumed_coin_utxos: engine.consumed.len() as u64,
        created_state_weight: u64::try_from(delta.max(0))
            .map_err(|_| ExecutionError::ResourceLimit)?,
    };
    let program = if engine.states.is_empty() && engine.storage.is_empty() {
        None
    } else if engine.states.len() == 1 && engine.storage.is_empty() {
        let (program_id, previous) = engine.states.into_iter().next().unwrap();
        Some(ProgramJournal::State {
            program_id,
            previous,
        })
    } else {
        Some(ProgramJournal::Calls {
            states: engine.states.into_iter().collect(),
            storage: engine
                .storage
                .into_iter()
                .map(|((id, key), v)| (id, key, v))
                .collect(),
        })
    };
    Ok(AppliedVm {
        value,
        fuel_used: vm::MAX_CALL_FUEL - engine.fuel,
        quote,
        coin: CoinRollbackJournal {
            consumed_coins: engine.consumed.into_iter().collect(),
            created_coin_ids: engine.created.into_iter().collect(),
            burned: Zeno::ZERO,
            mined: Zeno::ZERO,
        },
        asset: engine.asset,
        program,
    })
}

pub fn preview(
    state: &LedgerState,
    tx: &AuthorizedProgramInvocation,
    height: u64,
    commitment: AuthorizationCommitment,
    apps: &dyn ApplicationExecutor,
) -> Result<AppliedVm, ExecutionError> {
    let (id, data) = call_input(&tx.call).map_err(|_| ExecutionError::InvalidOperand)?;
    let record = state
        .programs
        .program(&id)
        .ok_or(ExecutionError::UnknownProgram)?;
    if record.code[4] != vm::APPLICATION_VERSION {
        if !data.is_empty() {
            return Err(ExecutionError::InvalidOperand);
        }
        let result = vm::execute_registered(&state.programs, id, vm::MAX_CALL_FUEL)?;
        if !result.has_monetary_effects() {
            // Retain the historical scalar-only quote path without cloning global state.
            return Ok(AppliedVm {
                value: result.value as u128,
                fuel_used: result.fuel_used,
                quote: Default::default(),
                coin: Default::default(),
                asset: None,
                program: None,
            });
        }
    }
    let mut staged = state.clone();
    apply(&mut staged, tx, height, commitment, apps)
}
/// Opcode 0 keeps the historical ID-only envelope. Opcode 1 adds up to 4096 data bytes.
pub fn call_input(
    call: &super::system::script::call::ProgramCall,
) -> Result<(ProgramId, &[u8]), CodeError> {
    use super::system::script::call::SystemProgramId;
    if call.program != SystemProgramId::VM
        || !matches!(call.opcode, 0 | 1)
        || call.payload.len() < 32
        || call.payload.len() > 32 + MAX_DATA_BYTES
        || (call.opcode == 0 && call.payload.len() != 32)
    {
        return Err(CodeError::InvalidInstruction);
    }
    Ok((
        ProgramId::from_bytes(call.payload[..32].try_into().unwrap()),
        &call.payload[32..],
    ))
}

#[cfg(test)]
mod tests;
