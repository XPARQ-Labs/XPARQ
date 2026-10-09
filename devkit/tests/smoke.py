#!/usr/bin/env python3
"""Real XPVM lifecycle, restart and authorization regressions in fresh devnet storage."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'devkit/devnet'))
import run as devnet


def rejected(args, expected):
    result = subprocess.run([str(a) for a in args], cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert result.returncode != 0, 'invalid call succeeded'
    assert expected in result.stderr, result.stderr


with tempfile.TemporaryDirectory(prefix='xparq-devkit-smoke-') as temporary:
    state = Path(temporary)
    devnet.require_bins()
    counter, vault = devnet.demo(state)
    with devnet.node(state, 0, 0) as (rpc, owner, child):
        assert devnet.get(rpc, '/program/account/' + counter)['state_value'] == 1
        assert devnet.get(rpc, '/program/account/' + vault)['coin_balance'] == 75_000_000
        args = [devnet.BIN / 'wallet', 'program-call', '--program-id', vault, '--rpc', rpc]
        rejected(args + ['--wallet', devnet.wallet_file(state), '--data', '01'], 'InvalidOperand')
        other = state / 'other-wallet.json'
        devnet.command([devnet.BIN / 'wallet', 'new', '--wallet', other], quiet=True)
        output = devnet.command([devnet.BIN / 'wallet', 'program-id', '--wallet', other], quiet=True)
        recipient = re.search(r'\b[0-9a-f]{64}\b', output).group()
        devnet.command([devnet.BIN / 'wallet', 'sign-spend', '--wallet', devnet.wallet_file(state),
                        '--rpc', rpc, '--to', recipient, '--amount', '1'])
        devnet.wait_for(rpc, '/program/balance/' + recipient, lambda v: v['available'] >= 100_000_000, child=child)
        rejected(args + ['--wallet', other, '--data', (1).to_bytes(16, 'little').hex()], 'Reverted')
        assert devnet.get(rpc, '/program/account/' + vault)['coin_balance'] == 75_000_000
        assert devnet.get(rpc, '/program/account/' + counter)['state_value'] == 1
        print('PASS: restart preserved state; malformed calldata and another wallet cannot withdraw.')
