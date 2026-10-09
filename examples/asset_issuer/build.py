#!/usr/bin/env python3
"""Build XPVM v3 code that registers its asset once and mints a fixed amount per call."""
import argparse
import pathlib
import struct

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--recipient-hex', required=True, help='raw 32-byte Program ID')
parser.add_argument('--name', required=True)
parser.add_argument('--max-supply-units', type=int, required=True)
parser.add_argument('--initial-mint-units', type=int, required=True, help='initial supply retained by contract')
parser.add_argument('--mint-units', type=int, required=True, help='base units minted to recipient per call')
parser.add_argument('--asset-nonce', type=int, default=1)
parser.add_argument('--output', default='asset_issuer.xpvm')
args = parser.parse_args()
try:
    recipient = bytes.fromhex(args.recipient_hex)
except ValueError:
    parser.error('recipient must be hexadecimal')
if len(recipient) != 32:
    parser.error('recipient must contain exactly 32 bytes')
try:
    name = args.name.encode('ascii')
except UnicodeEncodeError:
    parser.error('asset name must contain printable ASCII')
if not 1 <= len(name) <= 64 or args.name.strip() != args.name or any(b < 32 or b > 126 for b in name):
    parser.error('asset name must be 1–64 printable ASCII bytes without outer whitespace')
for amount in [args.max_supply_units, args.initial_mint_units, args.mint_units]:
    if not 0 < amount < 2**128:
        parser.error('amounts must be positive unsigned 128-bit base units')
if args.initial_mint_units + args.mint_units > args.max_supply_units:
    parser.error('initial supply plus first mint must not exceed maximum supply')
if not 0 <= args.asset_nonce < 2**64:
    parser.error('asset nonce must fit unsigned 64 bits')
code = bytearray(b'XPVM' + struct.pack('<BHHI', 3, 1, 0, 0))
code += b'\x08' + struct.pack('<I', len(name)) + name
code += args.max_supply_units.to_bytes(16, 'little')
code += args.initial_mint_units.to_bytes(16, 'little')
code += struct.pack('<Q', args.asset_nonce) + b'\x01'  # skip_if_exists
code += b'\x09\x01\x00' + recipient  # MintAssetTarget::Registered, Owner::Program
code += args.mint_units.to_bytes(16, 'little')
code += b'\x01' + struct.pack('<q', 0) + b'\x03'
pathlib.Path(args.output).write_bytes(code)
print(f'Wrote {len(code)} bytes to {args.output}')
