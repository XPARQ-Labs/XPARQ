(module
  (import "xparq" "coin_transfer"
    (func $coin_transfer (param i32 i64) (result i32)))
  (import "xparq" "coin_transfer_extension"
    (func $coin_transfer_extension (param i32 i64) (result i32)))

  ;; ABI v3 requires exactly 16 initial and 16 maximum 64-KiB pages.
  (memory (export "memory") 16 16)

  ;; The host copies each call payload here before validate/apply.
  (func (export "xparq_alloc") (param $length i32) (result i32)
    local.get $length
    i32.const 64
    i32.gt_u
    if
      i32.const 0
      return
    end
    i32.const 1024)

  ;; Payload 0x01: opcode || address[20] || amount_le_u64
  ;; Payload 0x02: opcode || extension_hash[32] || amount_le_u64
  (func $validate (export "xparq_validate")
    (param $payload_ptr i32)
    (param $payload_len i32)
    (param $height i64)
    (result i32)
    (local $opcode i32)
    local.get $payload_len
    i32.const 1
    i32.lt_u
    if
      i32.const 1
      return
    end
    local.get $payload_ptr
    i32.load8_u
    local.set $opcode

    local.get $opcode
    i32.const 1
    i32.eq
    if
      local.get $payload_len
      i32.const 29
      i32.ne
      if i32.const 1 return end
      local.get $payload_ptr
      i32.const 21
      i32.add
      i64.load
      i64.eqz
      if i32.const 1 return end
      i32.const 0
      return
    end

    local.get $opcode
    i32.const 2
    i32.eq
    if
      local.get $payload_len
      i32.const 41
      i32.ne
      if i32.const 1 return end
      local.get $payload_ptr
      i32.const 33
      i32.add
      i64.load
      i64.eqz
      if i32.const 1 return end
      i32.const 0
      return
    end

    i32.const 1)

  (func (export "xparq_apply")
    (param $payload_ptr i32)
    (param $payload_len i32)
    (param $height i64)
    (result i32)
    local.get $payload_ptr
    local.get $payload_len
    local.get $height
    call $validate
    if
      i32.const 1
      return
    end

    local.get $payload_ptr
    i32.load8_u
    i32.const 1
    i32.eq
    if
      local.get $payload_ptr
      i32.const 1
      i32.add
      local.get $payload_ptr
      i32.const 21
      i32.add
      i64.load
      call $coin_transfer
      return
    end

    local.get $payload_ptr
    i32.const 1
    i32.add
    local.get $payload_ptr
    i32.const 33
    i32.add
    i64.load
    call $coin_transfer_extension)
)
