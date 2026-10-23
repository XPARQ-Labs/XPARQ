#!/usr/bin/env python3
"""Encode XPVM asset.transfer.outputs calldata as hexadecimal."""
import argparse


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--asset', required=True, help='64-hex AssetContract')
parser.add_argument(
    '--output',
    action='append',
    required=True,
    metavar='PROGRAM_ID=UNITS',
    help='recipient Program ID and positive raw asset units; repeat for each recipient',
)
args = parser.parse_args()

asset = args.asset.removeprefix('0x')
try:
    asset_bytes = bytes.fromhex(asset)
except ValueError:
    parser.error('--asset must be hexadecimal')
if len(asset_bytes) != 32:
    parser.error('--asset must contain exactly 32 bytes')
if not 1 <= len(args.output) <= 82:
    parser.error('provide between 1 and 82 outputs')

payload = bytearray(asset_bytes)
payload += len(args.output).to_bytes(4, 'little')
for output in args.output:
    try:
        recipient, amount_text = output.split('=', 1)
        recipient = recipient.removeprefix('program:').removeprefix('0x')
        recipient_bytes = bytes.fromhex(recipient)
        amount = int(amount_text, 10)
    except (ValueError, TypeError):
        parser.error(f'invalid output {output!r}; use PROGRAM_ID=POSITIVE_RAW_UNITS')
    if len(recipient_bytes) != 32:
        parser.error(f'recipient in {output!r} must contain exactly 32 bytes')
    if not 0 < amount < 1 << 128:
        parser.error(f'amount in {output!r} must be a positive u128')
    payload.append(0)  # Borsh Owner::Program tag
    payload += recipient_bytes
    payload += amount.to_bytes(16, 'little')
if len(payload) > 4096:
    parser.error('encoded outputs exceed the 4096-byte VM input limit')
print(payload.hex())
