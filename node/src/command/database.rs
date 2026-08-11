use crate::runtime::node::Node;
use std::fs;
use std::path::Path;
use xparq::consensus::Consensus;

pub fn run(args: &[String], default_database: &str) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("check") => {
            let path = args.get(1).map(String::as_str).unwrap_or(default_database);
            let node = open_node(path)?;
            node.storage
                .validate_chain_integrity()
                .map_err(|error| format!("database integrity check failed: {error}"))?;
            println!("database integrity ok: {path}");
            Ok(())
        }
        Some("backup") => {
            let source = args.get(1).map(String::as_str).unwrap_or(default_database);
            let destination = args
                .get(2)
                .ok_or_else(|| "usage: node node db backup <database> <backup>".to_string())?;
            backup(source, destination)
        }
        Some("restore") => {
            let backup = args
                .get(1)
                .ok_or_else(|| "usage: node node db restore <backup> <database>".to_string())?;
            let destination = args
                .get(2)
                .ok_or_else(|| "usage: node node db restore <backup> <database>".to_string())?;
            restore(backup, destination)
        }
        _ => Err("usage: node node db <check|backup|restore> [paths]".to_string()),
    }
}

pub fn backup(source: &str, destination: &str) -> Result<(), String> {
    let node = open_node(source)?;
    node.flush_to_storage()
        .map_err(|error| format!("failed to flush database before backup: {error}"))?;
    node.storage
        .validate_chain_integrity()
        .map_err(|error| format!("refusing to back up invalid database: {error}"))?;
    drop(node);

    let destination = Path::new(destination);
    if destination.exists() {
        return Err("backup destination already exists".to_string());
    }
    fs::create_dir_all(destination)
        .map_err(|error| format!("failed to create backup directory: {error}"))?;
    fs::copy(
        Path::new(source).join("data.mdb"),
        destination.join("data.mdb"),
    )
    .map_err(|error| format!("failed to copy database backup: {error}"))?;
    println!("database backup created: {}", destination.display());
    Ok(())
}

pub fn restore(backup: &str, destination: &str) -> Result<(), String> {
    let backup_node = open_node(backup)?;
    backup_node
        .storage
        .validate_chain_integrity()
        .map_err(|error| format!("refusing to restore invalid backup: {error}"))?;
    drop(backup_node);

    let destination = Path::new(destination);
    if destination.exists() {
        return Err("restore destination already exists".to_string());
    }
    fs::create_dir_all(destination)
        .map_err(|error| format!("failed to create restore directory: {error}"))?;
    fs::copy(
        Path::new(backup).join("data.mdb"),
        destination.join("data.mdb"),
    )
    .map_err(|error| format!("failed to restore database: {error}"))?;
    let restored = open_node(destination.to_string_lossy().as_ref())?;
    restored
        .storage
        .validate_chain_integrity()
        .map_err(|error| format!("restored database failed integrity check: {error}"))?;
    println!("database restored: {}", destination.display());
    Ok(())
}

fn open_node(path: &str) -> Result<Node, String> {
    Node::init_or_load(path, Consensus::with_default_config())
        .map_err(|error| format!("failed to open node storage: {error}"))
}
