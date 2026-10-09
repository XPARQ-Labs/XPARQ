//! Typed application stack and metered opcode execution.

use super::super::{
    CALL_COST, MAX_DATA_BYTES,
    storage::check_key,
    valid_storage, validate_code,
    validation::{HEADER, instructions},
};
use super::Engine;
use crate::{
    common::Owner,
    monetary::asset::{AssetContract, Unit},
    program::{
        ProgramId,
        vm::{self, ExecutionError},
    },
};
use borsh::BorshDeserialize;
use crypto::canonical_bytes;

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

impl Engine<'_> {
    pub(super) fn interpret(
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

fn asset_id(bytes: Vec<u8>) -> Result<AssetContract, ExecutionError> {
    AssetContract::try_from_slice(&bytes).map_err(|_| ExecutionError::InvalidOperand)
}
