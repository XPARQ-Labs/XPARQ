#!/usr/bin/env python3
"""Build an owner-controlled XPVM v4 vault for XPQ and existing assets."""
import argparse
import pathlib
import struct


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', default='vault.xpvm')
args = parser.parse_args()


def integer(value):
    return b'\x01' + value.to_bytes(16, 'little')


def transfer_asset():
    body = bytearray()
    body += b'\x17'  # Drop calldata retained during selector dispatch.
    body += b'\x15' + integer(1) + integer(32) + b'\x35'  # asset ID
    body += b'\x15' + integer(33) + integer(33) + b'\x35\x34'  # recipient Owner
    body += b'\x15' + integer(66) + integer(16) + b'\x35\x29'  # amount
    body += b'\x41'  # asset.transfer
    body += integer(0) + b'\x03'
    return body


def build():
    # XPVM v4 header: stack limit 8, one memory page, entry point 0.
    body = bytearray()

    # The root caller must be the ProgramId that deployed this vault.
    body += b'\x12\x4a\x19\x22'

    # Calldata selector 0 means XPQ; selector 1 means asset.
    body += b'\x15\x16' + integer(0) + integer(1) + b'\x35'
    body += b'\x10\x01\x00\x00\x19\x21'
    jump_to_asset = len(body)
    body += b'\x00\x00\x00\x00'

    # XPQ calldata: 00 || Owner(33 bytes) || amount(u128 LE, <= u64::MAX).
    body += b'\x17'
    body += b'\x15' + integer(1) + integer(33) + b'\x35\x34'
    body += b'\x15' + integer(34) + integer(16) + b'\x35\x29'
    body += b'\x40'  # coin.transfer
    body += integer(0) + b'\x03'

    asset_offset = len(body)
    body[jump_to_asset:jump_to_asset + 4] = struct.pack('<I', asset_offset)
    body += transfer_asset()

    header = b'XPVM' + struct.pack('<BHHI', 4, 8, 1, 0)
    return header + body


pathlib.Path(args.output).write_bytes(build())
print(f'Wrote owner-controlled XPVM v4 vault to {args.output}')
