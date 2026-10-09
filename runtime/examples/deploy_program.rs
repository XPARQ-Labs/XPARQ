//! Build a signed DeployProgram payload for `node submit-deploy`.
//! Usage: cargo run -p node --example deploy_program -- <rpc-host:port> <seed-file> <coin-share> <input-zeno> <nonce> <code-file> <output-file>
use std::{
    env, fs,
    io::{Read, Write},
    net::TcpStream,
};

use kernel::{
    crypto::{AccountSignatureScheme, SigningSeed, canonical_bytes, program_id_from_public_key},
    monetary::coin::{CoinOutput, CoinShare, Zeno},
    operation::{AuthorizedDeployProgram, BlockOperation},
    program::{AccountAuthorization, CoinCharges, CoinTransition, DeployProgram},
};

fn quote(rpc: &str, deploy: &AuthorizedDeployProgram) -> Result<serde_json::Value, String> {
    let body = canonical_bytes(deploy).map_err(|e| e.to_string())?;
    let mut stream = TcpStream::connect(rpc).map_err(|e| e.to_string())?;
    write!(stream, "POST /program/deploy/quote HTTP/1.1\r\nHost: {rpc}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())
        .map_err(|e| e.to_string())?;
    stream.write_all(&body).map_err(|e| e.to_string())?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| e.to_string())?;
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("invalid HTTP response")?;
    let header = std::str::from_utf8(&response[..split]).map_err(|e| e.to_string())?;
    if !header.starts_with("HTTP/1.1 200 ") && !header.starts_with("HTTP/1.0 200 ") {
        return Err(format!(
            "quote failed: {}",
            String::from_utf8_lossy(&response)
        ));
    }
    serde_json::from_slice(&response[split + 4..]).map_err(|e| e.to_string())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 8 {
        return Err("usage: deploy_program <rpc-host:port> <seed-file> <coin-share> <input-zeno> <nonce> <code-file> <output-file>".into());
    }
    // The file contains 64 hex characters for an ML-DSA-44 signing seed.
    let seed_hex = fs::read_to_string(&args[2]).map_err(|e| e.to_string())?;
    let seed_bytes: [u8; 32] = hex::decode(seed_hex.trim())
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "seed must contain exactly 32 bytes")?;
    let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new(seed_bytes));
    let owner =
        program_id_from_public_key(&seed.public_key()).map_err(|error| error.to_string())?;
    let input: CoinShare = args[3]
        .parse()
        .map_err(|e| format!("invalid coin share: {e}"))?;
    let input_amount: u64 = args[4]
        .parse()
        .map_err(|e| format!("invalid input amount: {e}"))?;
    let nonce: u64 = args[5].parse().map_err(|e| format!("invalid nonce: {e}"))?;
    let code = fs::read(&args[6]).map_err(|e| e.to_string())?;
    let program = DeployProgram {
        owner,
        nonce,
        code: code.into(),
    };
    program
        .validate_structure()
        .map_err(|e| format!("invalid XPVM code: {e:?}"))?;
    let chain = kernel::genesis::chain_context().map_err(|e| e.to_string())?;

    // The quote includes the serialized signature size. Its bytes are replaced
    // after the final payment is known; the burn stays the same size.
    let placeholder = seed.sign(&[0; kernel::crypto::HASH_SIZE]);
    let build = |burn: u64, fee: u64| -> Result<AuthorizedDeployProgram, String> {
        let change = input_amount
            .checked_sub(burn)
            .and_then(|n| n.checked_sub(fee))
            .ok_or("input cannot cover protocol burn and miner fee")?;
        let outputs = if change == 0 {
            vec![]
        } else {
            vec![CoinOutput::new(owner, Zeno::from_zeno(change))]
        };
        let payment = CoinTransition::coin_with_charges(
            owner,
            vec![input],
            outputs,
            CoinCharges::new(Zeno::from_zeno(fee)),
        )
        .map_err(|e| e.to_string())?;
        Ok(AuthorizedDeployProgram {
            deploy: program.clone(),
            payment,
            authorization: AccountAuthorization {
                salt: [0; 32],
                public_key: seed.public_key(),
                signature: placeholder.clone(),
            },
        })
    };

    // A deliberately generous fee also covers the minimum relay fee per byte.
    // The caller can raise it if this network's operation is unusually large.
    let fee = 100_000u64;
    let first = quote(&args[1], &build(0, fee)?)?;
    let burn = first["required_protocol_burn"]
        .as_u64()
        .ok_or("quote has no burn")?;
    let mut deploy = build(burn, fee)?;
    let second = quote(&args[1], &deploy)?;
    if second["required_protocol_burn"].as_u64() != Some(burn)
        || second["height"] != first["height"]
        || second["tip_hash"] != first["tip_hash"]
    {
        return Err("quote changed while building deploy; retry with the current chain tip".into());
    }
    let commitment = deploy.commitment(chain).map_err(|e| e.to_string())?;
    if second["authorization_commitment"].as_str()
        != Some(hex::encode(commitment.as_bytes()).as_str())
    {
        return Err("local and RPC authorization commitments differ".into());
    }
    deploy.authorization.signature = seed.sign(commitment.as_bytes());
    let operation = BlockOperation::DeployProgram(Box::new(deploy.clone()));
    let bytes = canonical_bytes(&deploy).map_err(|e| e.to_string())?;
    fs::write(&args[7], bytes).map_err(|e| e.to_string())?;
    println!(
        "owner={} program_id={} operation_id={} burn={} miner_fee={} output={}",
        kernel::crypto::program_id_to_string(&owner),
        second["program_id"].as_str().unwrap_or("?"),
        hex::encode(operation.id().map_err(|e| e.to_string())?.into_bytes()),
        burn,
        fee,
        args[7]
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("deploy_program: {error}");
        std::process::exit(1);
    }
}
