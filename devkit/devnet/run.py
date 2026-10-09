#!/usr/bin/env python3
"""Local XPVM development workflows using the existing node and wallet CLIs."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
DEVKIT = ROOT / 'devkit'
BIN = DEVKIT / 'target' / 'debug'


def command(args, *, quiet=False):
    result = subprocess.run([str(a) for a in args], cwd=ROOT, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if result.returncode:
        # Wallet creation output contains recovery material; never print it.
        raise RuntimeError(result.stderr.strip() or f'{Path(args[0]).name} exited {result.returncode}')
    if not quiet:
        print(result.stdout, end='')
    return result.stdout


def build():
    env = dict(os.environ, CARGO_TARGET_DIR=str(DEVKIT / 'target'))
    subprocess.run(['cargo', 'build', '-p', 'node', '-p', 'wallet', '-p', 'xparq-devkit',
                    '--no-default-features', '--features', 'devnet', '--locked', '--offline',
                    '--config', 'profile.dev.package.argon2.opt-level=3',
                    '--config', 'profile.dev.package.blake2.opt-level=3'],
                   cwd=ROOT, env=env, check=True)


def require_bins():
    for name in ('node', 'wallet', 'xparq-devkit'):
        if not (BIN / name).is_file():
            raise RuntimeError('Build first: python3 devkit/devnet/run.py build')


def get(rpc, route):
    with urllib.request.urlopen('http://' + rpc + route, timeout=10) as response:
        return json.load(response)


def wait_for(rpc, route, predicate, *, child=None):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if child is not None and child.poll() is not None:
            raise RuntimeError('devnet node stopped; inspect node.log')
        try:
            value = get(rpc, route)
            if predicate(value):
                return value
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.2)
    raise RuntimeError(f'timed out waiting for {route}; inspect node.log')


def wallet_file(state):
    return state / 'wallet.json'


def wallet_id(state):
    # Use the wallet CLI so file consistency and account derivation are checked.
    output = command([BIN / 'wallet', 'program-id', '--wallet', wallet_file(state)], quiet=True)
    ids = re.findall(r'\b[0-9a-f]{64}\b', output)
    if len(ids) != 1:
        raise RuntimeError('wallet returned no unambiguous ProgramId')
    return ids[0]


def prepare(state):
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not wallet_file(state).exists():
        command([BIN / 'wallet', 'new', '--wallet', wallet_file(state), '--account', 'mldsa44'], quiet=True)
    return wallet_id(state)


def address(port):
    return f'127.0.0.1:{port}'


def ensure_free(port):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', port))
        return sock.getsockname()[1]


@contextlib.contextmanager
def node(state, rpc_port, p2p_port):
    owner = prepare(state)
    rpc = address(ensure_free(rpc_port))
    p2p = address(ensure_free(p2p_port))
    if rpc == p2p:
        raise RuntimeError('RPC and P2P ports must differ')
    # A lock prevents two launchers from mining against the same database.
    import fcntl
    with (state / 'devnet.lock').open('a') as lock, (state / 'node.log').open('a') as log:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError('this devnet directory is already in use') from error
        child = subprocess.Popen([str(BIN / 'node'), 'run', '--data', str(state / 'chain'),
                                  '--rpc', rpc, '--p2p', p2p, '--miner', owner],
                                 cwd=ROOT, stdout=log, stderr=log)
        try:
            wait_for(rpc, '/status', lambda _: True, child=child)
            print(f'Devnet RPC: http://{rpc}\nWallet ProgramId: {owner}\nState: {state}', flush=True)
            yield rpc, owner, child
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()


def deploy(state, rpc, code, nonce):
    output = command([BIN / 'wallet', 'program-deploy', '--code', code, '--nonce', nonce,
                      '--wallet', wallet_file(state), '--rpc', rpc])
    match = re.search(r'Program ID: ([0-9a-f]{64})', output)
    if not match:
        raise RuntimeError('deploy returned no ProgramId')
    program = match[1]
    wait_for(rpc, '/program/account/' + program, lambda v: v.get('policy') == 'deployed')
    return program


def call(state, rpc, program, data='', deposit=None):
    args = [BIN / 'wallet', 'program-call', '--program-id', program, '--wallet', wallet_file(state), '--rpc', rpc]
    if data:
        args += ['--data', data]
    if deposit is not None:
        args += ['--deposit', deposit]
    output = command(args)
    match = re.search(r'(?:Transaction Hash|Hash): ([0-9a-f]{64})', output)
    if not match:
        raise RuntimeError('call returned no transaction hash')
    wait_for(rpc, '/explorer/transaction/' + match[1], lambda v: v.get('status') == 'confirmed')


def assemble(source, output):
    command([BIN / 'xparq-devkit', 'assemble', source, '-o', output])


def demo(state):
    # Demo owns its temporary node process, but retains artifacts for inspection.
    with node(state, 0, 0) as (rpc, owner, child):
        wait_for(rpc, '/program/balance/' + owner, lambda v: int(v.get('available', 0)) > 1_000_000, child=child)
        counter = state / 'counter.xpvm'
        assemble(DEVKIT / 'examples' / 'counter.xpa', counter)
        # Retain confirmed deployment IDs; time-based nonces avoid demo reuse.
        manifest = state / 'programs.json'
        known = json.loads(manifest.read_text()) if manifest.exists() else []
        nonce = time.time_ns()
        program = deploy(state, rpc, counter, str(nonce))
        known.append(program)
        manifest.write_text(json.dumps(known, indent=2) + '\n')
        call(state, rpc, program)
        result = wait_for(rpc, '/program/account/' + program, lambda v: v.get('state_value') == 1, child=child)
        print(json.dumps(result, indent=2))
        vault_code = state / 'vault.xpvm'
        assemble(DEVKIT / 'examples' / 'vault.xpa', vault_code)
        vault = deploy(state, rpc, vault_code, str(nonce + 1))
        known.append(vault)
        manifest.write_text(json.dumps(known, indent=2) + '\n')
        call(state, rpc, vault, deposit='1')
        wait_for(rpc, '/program/account/' + vault, lambda v: v.get('coin_balance') == 100_000_000, child=child)
        call(state, rpc, vault, data=(25_000_000).to_bytes(16, 'little').hex())
        result = wait_for(rpc, '/program/account/' + vault, lambda v: v.get('coin_balance') == 75_000_000, child=child)
        print(json.dumps(result, indent=2))
        print('PASS: counter state persisted; vault received 1 XPQ and returned 0.25 XPQ.')
    return program, vault


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, default=DEVKIT / '.local')
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('build')
    up = sub.add_parser('up')
    up.add_argument('--rpc-port', type=int, default=26666)
    up.add_argument('--p2p-port', type=int, default=26001)
    sub.add_parser('demo')
    for name in ('deploy', 'call', 'inspect'):
        cmd = sub.add_parser(name)
        cmd.add_argument('--rpc', default='127.0.0.1:26666')
        if name == 'deploy':
            cmd.add_argument('--code', type=Path, required=True)
            cmd.add_argument('--nonce', type=int, required=True)
        else:
            cmd.add_argument('--program-id', required=True)
        if name == 'call':
            cmd.add_argument('--data', default='')
            cmd.add_argument('--deposit')
    args = parser.parse_args()
    if args.action == 'build':
        build()
        return
    require_bins()
    state = args.state.expanduser().resolve()
    if args.action == 'up':
        with node(state, args.rpc_port, args.p2p_port) as (_, _, child):
            child.wait()
    elif args.action == 'demo':
        demo(state)
    elif args.action == 'deploy':
        print('Confirmed ProgramId:', deploy(state, args.rpc, args.code.resolve(), str(args.nonce)))
    elif args.action == 'call':
        call(state, args.rpc, args.program_id, args.data, args.deposit)
    else:
        if not re.fullmatch('[0-9a-fA-F]{64}', args.program_id):
            raise RuntimeError('expected 64-hex ProgramId')
        print(json.dumps(get(args.rpc, '/program/account/' + args.program_id), indent=2))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    except (OSError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError) as error:
        print(f'devkit: {error}', file=sys.stderr)
        sys.exit(1)
