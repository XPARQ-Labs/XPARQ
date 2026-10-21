#!/usr/bin/env python3
"""Encode calldata for the owner-controlled XPVM v4 vault example."""
import argparse


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('kind', choices=('coin', 'asset'))
parser.add_argument('--recipient-hex', required=True, help='32-byte recipient Program ID')
parser.add_argument('--amount', required=True, type=int, help='base units (coin: zeno)')
parser.add_argument('--asset-id', help='32-byte asset contract ID; required for asset')
args = parser.parse_args()


def identifier(value, label):
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        parser.error(f'{label} must be hexadecimal')
    if len(decoded) != 32:
        parser.error(f'{label} must contain exactly 32 bytes')
    return decoded


if not 0 < args.amount < 2**128:
    parser.error('--amount must be between 1 and 2^128-1')
recipient = b'\x00' + identifier(args.recipient_hex, '--recipient-hex')
if args.kind == 'coin':
    if args.asset_id is not None:
        parser.error('--asset-id is only valid with kind=asset')
    if args.amount >= 2**64:
        parser.error('coin amount must fit u64 zeno')
    calldata = b'\x00' + recipient + args.amount.to_bytes(16, 'little')
else:
    if args.asset_id is None:
        parser.error('--asset-id is required with kind=asset')
    calldata = (
        b'\x01'
        + identifier(args.asset_id, '--asset-id')
        + recipient
        + args.amount.to_bytes(16, 'little')
    )
print(calldata.hex())
