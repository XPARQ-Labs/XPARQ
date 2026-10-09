#!/usr/bin/env python3
"""Build a bounded XPVM v2 contract with fixed coin/asset payouts."""
import argparse
import pathlib
import struct

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--recipient-hex', required=True, help='32-byte Program ID, as hex')
parser.add_argument('--coin-units', type=int, default=0, help='native zeno per invocation')
parser.add_argument('--asset-id', help='32-byte asset contract ID, as hex')
parser.add_argument('--asset-units', type=int, default=0, help='asset base units per invocation')
parser.add_argument('--output', default='vault.xpvm')
args = parser.parse_args()

def hash_bytes(value):
    try:
        result = bytes.fromhex(value)
    except ValueError:
        parser.error('identifiers must be hexadecimal')
    if len(result) != 32:
        parser.error('identifiers must contain exactly 32 bytes')
    return result

if not (0 <= args.coin_units < 2**64 and 0 <= args.asset_units < 2**64):
    parser.error('amounts must fit unsigned 64-bit base units')
if bool(args.asset_id) != bool(args.asset_units):
    parser.error('--asset-id and positive --asset-units must be supplied together')
if not args.coin_units and not args.asset_units:
    parser.error('at least one positive payout is required')
recipient = b'\x00' + hash_bytes(args.recipient_hex)  # Owner::Program
code = bytearray(b'XPVM' + struct.pack('<BHHI', 2, 1, 0, 0))
if args.coin_units:
    code += b'\x06' + recipient + struct.pack('<Q', args.coin_units)
if args.asset_units:
    code += b'\x07' + hash_bytes(args.asset_id) + recipient + struct.pack('<Q', args.asset_units)
code += b'\x01' + struct.pack('<q', 0) + b'\x03'
pathlib.Path(args.output).write_bytes(code)
print(f'Wrote {len(code)} bytes to {args.output}')
