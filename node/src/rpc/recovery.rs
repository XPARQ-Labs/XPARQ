#[derive(Serialize)]
struct RollbackIssueResponse {
    id: String,
    disconnected_block_height: u64,
    disconnected_block_hash: String,
    transaction_index: u32,
    transaction_hash: String,
    family: String,
    affected_accounts: Vec<String>,
    signed_transaction: String,
    rollback_proof_bundle: Option<String>,
    rollback_proof_encoding: &'static str,
    status: String,
    reconfirmed_height: Option<u64>,
    reconfirmed_block_hash: Option<String>,
    detected_at: u64,
    retry_attempts: u32,
    last_error: Option<String>,
}

#[derive(Serialize)]
struct RollbackIssueListResponse {
    total: usize,
    issues: Vec<RollbackIssueResponse>,
}

async fn rpc_account_rollback_issues(
    State(state): State<RpcState>,
    AxumPath(address): AxumPath<String>,
) -> axum::response::Response {
    let address = match address_from_string(&address) {
        Ok(address) => address,
        Err(error) => return rpc_error(StatusCode::BAD_REQUEST, error.to_string()),
    };
    match state.node.lock() {
        Ok(node) => match node.rollback_issues_for_account(&address) {
            Ok(issues) => rollback_issue_list_response(issues),
            Err(error) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
        },
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

async fn rpc_rollback_issue(
    State(state): State<RpcState>,
    AxumPath(id): AxumPath<String>,
) -> axum::response::Response {
    let id = match parse_rollback_issue_id(&id) {
        Ok(id) => id,
        Err(error) => return rpc_error(StatusCode::BAD_REQUEST, error),
    };
    match state.node.lock() {
        Ok(node) => match node.rollback_issue(&id) {
            Ok(Some(issue)) => match node
                .rollback_proof_bundle(&issue)
                .map_err(|error| error.to_string())
                .and_then(|bundle| rollback_issue_response(issue, Some(bundle)))
            {
                Ok(response) => Json(response).into_response(),
                Err(error) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error),
            },
            Ok(None) => rpc_error(StatusCode::NOT_FOUND, "rollback_issue_not_found"),
            Err(error) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
        },
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

async fn rpc_retry_rollback_issue(
    State(state): State<RpcState>,
    AxumPath(id): AxumPath<String>,
) -> axum::response::Response {
    let id = match parse_rollback_issue_id(&id) {
        Ok(id) => id,
        Err(error) => return rpc_error(StatusCode::BAD_REQUEST, error),
    };
    match state.node.lock() {
        Ok(mut node) => match node.retry_rollback_issue(&id) {
            Ok(Some(issue)) => match node
                .rollback_proof_bundle(&issue)
                .map_err(|error| error.to_string())
                .and_then(|bundle| rollback_issue_response(issue, Some(bundle)))
            {
                Ok(response) => Json(response).into_response(),
                Err(error) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error),
            },
            Ok(None) => rpc_error(StatusCode::NOT_FOUND, "rollback_issue_not_found"),
            Err(error) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
        },
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

fn rollback_issue_list_response(issues: Vec<RollbackIssue>) -> axum::response::Response {
    let responses: Result<Vec<_>, _> = issues
        .into_iter()
        .map(|issue| rollback_issue_response(issue, None))
        .collect();
    match responses {
        Ok(issues) => Json(RollbackIssueListResponse {
            total: issues.len(),
            issues,
        })
        .into_response(),
        Err(error) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

fn rollback_issue_response(
    issue: RollbackIssue,
    proof_bundle: Option<xparq::qcash::recovery::RollbackProofBundle>,
) -> Result<RollbackIssueResponse, String> {
    let (status, reconfirmed_height, reconfirmed_block_hash) = match issue.status {
        RollbackRecoveryStatus::Detected => ("detected", None, None),
        RollbackRecoveryStatus::Requeued => ("requeued", None, None),
        RollbackRecoveryStatus::Conflict => ("conflict", None, None),
        RollbackRecoveryStatus::Reconfirmed {
            block_height,
            block_hash,
        } => (
            "reconfirmed",
            Some(block_height.0),
            Some(hex::encode(block_hash.0)),
        ),
    };
    let signed_transaction = issue
        .transaction
        .to_bytes()
        .map(hex::encode)
        .map_err(|error| format!("failed to encode recovery transaction: {error}"))?;
    let rollback_proof_bundle = proof_bundle
        .as_ref()
        .map(xparq::codec::canonical_bytes)
        .transpose()
        .map_err(|error| format!("failed to encode rollback proof bundle: {error}"))?
        .map(hex::encode);
    Ok(RollbackIssueResponse {
        id: hex::encode(issue.id.0),
        disconnected_block_height: issue.disconnected_block_height.0,
        disconnected_block_hash: hex::encode(issue.disconnected_block_hash.0),
        transaction_index: issue.transaction_index,
        transaction_hash: hex::encode(issue.transaction_hash.0),
        family: format!("{:?}", issue.family).to_ascii_lowercase(),
        affected_accounts: issue
            .affected_accounts
            .iter()
            .map(address_to_string)
            .collect(),
        signed_transaction,
        rollback_proof_bundle,
        rollback_proof_encoding: "xparq-canonical-borsh-hex-v1",
        status: status.to_string(),
        reconfirmed_height,
        reconfirmed_block_hash,
        detected_at: issue.detected_at,
        retry_attempts: issue.retry_attempts,
        last_error: issue.last_error,
    })
}

fn parse_rollback_issue_id(value: &str) -> Result<RollbackIssueId, String> {
    let bytes = hex::decode(value).map_err(|_| "invalid_rollback_issue_id".to_string())?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "invalid_rollback_issue_id".to_string())?;
    Ok(RollbackIssueId(bytes))
}
