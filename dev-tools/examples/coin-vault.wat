(module
  (import "xparq" "caller" (func $caller (param i32) (result i32)))
  (import "xparq" "attached_coin" (func $attached_coin (result i64)))
  (import "xparq" "state_get" (func $state_get (param i32 i32 i32 i32) (result i32)))
  (import "xparq" "state_put" (func $state_put (param i32 i32 i32 i32) (result i32)))
  (import "xparq" "coin_transfer" (func $coin_transfer (param i32 i64) (result i32)))
  (import "xparq" "coin_transfer_extension" (func $coin_transfer_extension (param i32 i64) (result i32)))
  (memory (export "memory") 16 16)
  ;; Per-user balance key: 'b' || authenticated caller address.
  (data (i32.const 100) "b")

  (func (export "xparq_alloc") (param $length i32) (result i32)
    local.get $length i32.const 64 i32.gt_u
    if i32.const 0 return end
    i32.const 1024)

  ;; Returns -2 on caller/state failure, -1 for a new user, or 8.
  (func $load_balance (result i32)
    i32.const 101 call $caller i32.eqz
    if else i32.const -2 return end
    i32.const 100 i32.const 21 i32.const 200 i32.const 8 call $state_get)

  ;; 00 = deposit; 01 = withdraw to address; 02 = withdraw to extension.
  (func $validate (export "xparq_validate")
    (param $ptr i32) (param $len i32) (param $height i64) (result i32)
    (local $op i32) (local $amount i64)
    local.get $len i32.const 1 i32.lt_u
    if i32.const 1 return end
    local.get $ptr i32.load8_u local.set $op
    local.get $op i32.eqz
    if
      local.get $len i32.const 1 i32.ne
      if i32.const 1 return end
      call $attached_coin i64.eqz
      if i32.const 1 return end
      i32.const 0 return
    end
    call $attached_coin i64.eqz
    if else i32.const 1 return end
    local.get $op i32.const 1 i32.eq
    if
      local.get $len i32.const 29 i32.ne
      if i32.const 1 return end
      local.get $ptr i32.const 21 i32.add i64.load local.set $amount
    else
      local.get $op i32.const 2 i32.ne
      if i32.const 1 return end
      local.get $len i32.const 41 i32.ne
      if i32.const 1 return end
      local.get $ptr i32.const 33 i32.add i64.load local.set $amount
    end
    local.get $amount i64.eqz
    if i32.const 1 return end
    call $load_balance i32.const 8 i32.ne
    if i32.const 1 return end
    i32.const 200 i64.load local.get $amount i64.lt_u
    if i32.const 1 return end
    i32.const 0)

  (func (export "xparq_apply")
    (param $ptr i32) (param $len i32) (param $height i64) (result i32)
    (local $op i32) (local $amount i64) (local $old i64) (local $new i64)
    local.get $ptr local.get $len local.get $height call $validate
    if i32.const 1 return end
    local.get $ptr i32.load8_u local.set $op
    local.get $op i32.eqz
    if
      call $load_balance
      i32.const -2 i32.eq
      if i32.const 1 return end
      i32.const 200 i64.load local.set $old
      local.get $old call $attached_coin i64.add local.set $new
      local.get $new local.get $old i64.lt_u
      if i32.const 1 return end
      i32.const 200 local.get $new i64.store
      i32.const 100 i32.const 21 i32.const 200 i32.const 8 call $state_put
      return
    end

    call $load_balance drop
    local.get $op i32.const 1 i32.eq
    if
      local.get $ptr i32.const 21 i32.add i64.load local.set $amount
    else
      local.get $ptr i32.const 33 i32.add i64.load local.set $amount
    end
    i32.const 200
    i32.const 200 i64.load local.get $amount i64.sub
    i64.store
    i32.const 100 i32.const 21 i32.const 200 i32.const 8 call $state_put
    if i32.const 1 return end
    local.get $op i32.const 1 i32.eq
    if
      local.get $ptr i32.const 1 i32.add local.get $amount call $coin_transfer return
    end
    local.get $ptr i32.const 1 i32.add local.get $amount call $coin_transfer_extension)
)
