(module
  (import "xparq" "state_put"
    (func $state_put (param i32 i32 i32 i32) (result i32)))

  ;; ABI v1 requires exactly 16 initial and 16 maximum 64-KiB pages.
  (memory (export "memory") 16 16)
  (data (i32.const 0) "value")

  ;; This minimal test example reserves offset 1024 for a small payload.
  ;; A production allocator must reject requests that exceed linear memory.
  (func (export "xparq_alloc") (param $length i32) (result i32)
    (i32.const 1024))

  ;; Reject an empty payload; accept every non-empty payload.
  (func (export "xparq_validate")
    (param $payload_ptr i32)
    (param $payload_len i32)
    (param $height i64)
    (result i32)
    local.get $payload_len
    i32.eqz
    if
      i32.const 1
      return
    end
    i32.const 0)

  ;; Store the accepted payload under the extension-local key `value`.
  (func (export "xparq_apply")
    (param $payload_ptr i32)
    (param $payload_len i32)
    (param $height i64)
    (result i32)
    i32.const 0
    i32.const 5
    local.get $payload_ptr
    local.get $payload_len
    call $state_put))
