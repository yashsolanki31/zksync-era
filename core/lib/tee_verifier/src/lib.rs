//! Types for the tee_verifier

// Can't be put in `zksync_types`, because it would add a circular dependency.

use multivm::interface::{L1BatchEnv, SystemEnv};
use serde::{Deserialize, Serialize};
use zksync_basic_types::{L1BatchNumber, H256};
use zksync_object_store::{serialize_using_bincode, Bucket, StoredObject};
use zksync_prover_interface::inputs::PrepareBasicCircuitsJob;
use zksync_types::block::MiniblockExecutionData;

/// Storage data used as input for the TEE verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeVerifierInput {
    pub prepare_basic_circuits_job: PrepareBasicCircuitsJob,
    pub new_root_hash: H256,
    pub miniblocks_execution_data: Vec<MiniblockExecutionData>,
    pub fictive_miniblock_data: MiniblockExecutionData,
    pub l1_batch_env: L1BatchEnv,
    pub system_env: SystemEnv,
    pub used_contracts: Vec<(H256, Vec<u8>)>,
}

impl StoredObject for TeeVerifierInput {
    const BUCKET: Bucket = Bucket::TeeVerifierInput;
    type Key<'a> = L1BatchNumber;

    fn encode_key(key: Self::Key<'_>) -> String {
        format!("tee_verifier_input_for_l1_batch_{key}.bin")
    }

    serialize_using_bincode!();
}
