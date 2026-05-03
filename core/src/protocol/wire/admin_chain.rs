//! Admin-chain export / import wire types
//! (`GET /v1/admin-chain/:cluster_id` and `POST /v1/admin-chain/:cluster_id`).

use serde::{Deserialize, Serialize};

use crate::crypto::admin_chain::AdminChainEntry;
use crate::types::ClusterId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainExport {
    pub cluster_id: ClusterId,
    pub entries: Vec<AdminChainEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAppendRequest {
    pub entries: Vec<AdminChainEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainHeadResponse {
    pub head: AdminChainEntry,
}
