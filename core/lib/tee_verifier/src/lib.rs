//! Types for the tee_verifier

// Can't be put in `zksync_types`, because it would add a circular dependency.

use std::{cell::RefCell, rc::Rc};

use anyhow::{bail, Context};
use multivm::{
    interface::{FinishedL1Batch, L1BatchEnv, L2BlockEnv, SystemEnv, TxExecutionMode, VmInterface},
    vm_latest::HistoryEnabled,
    zk_evm_latest::ethereum_types::U256,
    VmInstance,
};
use serde::{Deserialize, Serialize};
use tracing::{error, trace};
use vm_utils::execute_tx;
use zksync_basic_types::{protocol_version::ProtocolVersionId, Address, L2BlockNumber, L2ChainId};
use zksync_contracts::{BaseSystemContracts, SystemContractCode};
use zksync_crypto::hasher::blake2::Blake2Hasher;
use zksync_merkle_tree::{
    BlockOutputWithProofs, TreeInstruction, TreeLogEntry, TreeLogEntryWithProof,
};
use zksync_object_store::{Bucket, StoredObject, _reexports::BoxedError};
use zksync_prover_interface::inputs::{PrepareBasicCircuitsJob, StorageLogMetadata};
use zksync_state::{InMemoryStorage, StorageView, WriteStorage};
use zksync_types::{
    block::L2BlockExecutionData,
    ethabi::ethereum_types::BigEndianHash,
    fee_model::{BatchFeeInput, L1PeggedBatchFeeModelInput, PubdataIndependentBatchFeeModelInput},
    zk_evm_types::LogQuery,
    AccountTreeId, L1BatchNumber, StorageKey, Transaction, H256,
};
use zksync_utils::{bytecode::hash_bytecode, u256_to_h256};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MyL2BlockExecutionData {
    number: L2BlockNumber,
    timestamp: u64,
    prev_block_hash: H256,
    virtual_blocks: u32,
    txs: Vec<Transaction>,
}

impl From<MyL2BlockExecutionData> for L2BlockExecutionData {
    fn from(value: MyL2BlockExecutionData) -> Self {
        L2BlockExecutionData {
            number: value.number,
            timestamp: value.timestamp,
            prev_block_hash: value.prev_block_hash,
            virtual_blocks: value.virtual_blocks,
            txs: value.txs,
        }
    }
}

impl From<L2BlockExecutionData> for MyL2BlockExecutionData {
    fn from(value: L2BlockExecutionData) -> Self {
        MyL2BlockExecutionData {
            number: value.number,
            timestamp: value.timestamp,
            prev_block_hash: value.prev_block_hash,
            virtual_blocks: value.virtual_blocks,
            txs: value.txs,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct MyL1PeggedBatchFeeModelInput {
    /// Fair L2 gas price to provide
    fair_l2_gas_price: u64,
    /// The L1 gas price to provide to the VM.
    l1_gas_price: u64,
}
impl From<MyL1PeggedBatchFeeModelInput> for L1PeggedBatchFeeModelInput {
    fn from(value: MyL1PeggedBatchFeeModelInput) -> Self {
        L1PeggedBatchFeeModelInput {
            fair_l2_gas_price: value.fair_l2_gas_price,
            l1_gas_price: value.l1_gas_price,
        }
    }
}

impl From<L1PeggedBatchFeeModelInput> for MyL1PeggedBatchFeeModelInput {
    fn from(value: L1PeggedBatchFeeModelInput) -> Self {
        MyL1PeggedBatchFeeModelInput {
            fair_l2_gas_price: value.fair_l2_gas_price,
            l1_gas_price: value.l1_gas_price,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct MyPubdataIndependentBatchFeeModelInput {
    /// Fair L2 gas price to provide
    fair_l2_gas_price: u64,
    /// Fair pubdata price to provide.
    fair_pubdata_price: u64,
    /// The L1 gas price to provide to the VM. Even if some of the VM versions may not use this value, it is still maintained for backward compatibility.
    l1_gas_price: u64,
}

impl From<MyPubdataIndependentBatchFeeModelInput> for PubdataIndependentBatchFeeModelInput {
    fn from(value: MyPubdataIndependentBatchFeeModelInput) -> Self {
        PubdataIndependentBatchFeeModelInput {
            fair_l2_gas_price: value.fair_l2_gas_price,
            fair_pubdata_price: value.fair_pubdata_price,
            l1_gas_price: value.l1_gas_price,
        }
    }
}

impl From<PubdataIndependentBatchFeeModelInput> for MyPubdataIndependentBatchFeeModelInput {
    fn from(value: PubdataIndependentBatchFeeModelInput) -> Self {
        MyPubdataIndependentBatchFeeModelInput {
            fair_l2_gas_price: value.fair_l2_gas_price,
            fair_pubdata_price: value.fair_pubdata_price,
            l1_gas_price: value.l1_gas_price,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum MyBatchFeeInput {
    L1Pegged(MyL1PeggedBatchFeeModelInput),
    PubdataIndependent(MyPubdataIndependentBatchFeeModelInput),
}

impl From<MyBatchFeeInput> for BatchFeeInput {
    fn from(value: MyBatchFeeInput) -> Self {
        match value {
            MyBatchFeeInput::L1Pegged(input) => BatchFeeInput::L1Pegged(input.into()),
            MyBatchFeeInput::PubdataIndependent(input) => {
                BatchFeeInput::PubdataIndependent(input.into())
            }
        }
    }
}

impl From<BatchFeeInput> for MyBatchFeeInput {
    fn from(value: BatchFeeInput) -> Self {
        match value {
            BatchFeeInput::L1Pegged(input) => MyBatchFeeInput::L1Pegged(input.into()),
            BatchFeeInput::PubdataIndependent(input) => {
                MyBatchFeeInput::PubdataIndependent(input.into())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
struct MyL2BlockEnv {
    number: u32,
    timestamp: u64,
    prev_block_hash: H256,
    max_virtual_blocks_to_create: u32,
}

impl From<MyL2BlockEnv> for L2BlockEnv {
    fn from(value: MyL2BlockEnv) -> Self {
        L2BlockEnv {
            number: value.number,
            timestamp: value.timestamp,
            prev_block_hash: value.prev_block_hash,
            max_virtual_blocks_to_create: value.max_virtual_blocks_to_create,
        }
    }
}

impl From<L2BlockEnv> for MyL2BlockEnv {
    fn from(value: L2BlockEnv) -> Self {
        MyL2BlockEnv {
            number: value.number,
            timestamp: value.timestamp,
            prev_block_hash: value.prev_block_hash,
            max_virtual_blocks_to_create: value.max_virtual_blocks_to_create,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MyL1BatchEnv {
    // If previous batch hash is None, then this is the first batch
    previous_batch_hash: Option<H256>,
    number: L1BatchNumber,
    timestamp: u64,

    /// The fee input into the batch. It contains information such as L1 gas price, L2 fair gas price, etc.
    fee_input: MyBatchFeeInput,
    fee_account: Address,
    enforced_base_fee: Option<u64>,
    first_l2_block: MyL2BlockEnv,
}

impl From<MyL1BatchEnv> for L1BatchEnv {
    fn from(value: MyL1BatchEnv) -> Self {
        let MyL1BatchEnv {
            previous_batch_hash,
            number,
            timestamp,
            fee_input,
            fee_account,
            enforced_base_fee,
            first_l2_block,
        } = value;

        L1BatchEnv {
            previous_batch_hash,
            number,
            timestamp,
            fee_input: fee_input.into(),
            fee_account,
            enforced_base_fee,
            first_l2_block: first_l2_block.into(),
        }
    }
}

impl From<L1BatchEnv> for MyL1BatchEnv {
    fn from(value: L1BatchEnv) -> Self {
        let L1BatchEnv {
            previous_batch_hash,
            number,
            timestamp,
            fee_input,
            fee_account,
            enforced_base_fee,
            first_l2_block,
        } = value;

        MyL1BatchEnv {
            previous_batch_hash,
            number,
            timestamp,
            fee_input: fee_input.into(),
            fee_account,
            enforced_base_fee,
            first_l2_block: first_l2_block.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MySystemContractCode {
    code: Vec<U256>,
    hash: H256,
}

impl From<MySystemContractCode> for SystemContractCode {
    fn from(value: MySystemContractCode) -> Self {
        let MySystemContractCode { code, hash } = value;
        SystemContractCode { code, hash }
    }
}

impl From<SystemContractCode> for MySystemContractCode {
    fn from(value: SystemContractCode) -> Self {
        let SystemContractCode { code, hash } = value;
        MySystemContractCode { code, hash }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MyBaseSystemContracts {
    bootloader: MySystemContractCode,
    default_aa: MySystemContractCode,
}

impl From<MyBaseSystemContracts> for BaseSystemContracts {
    fn from(value: MyBaseSystemContracts) -> Self {
        let MyBaseSystemContracts {
            bootloader,
            default_aa,
        } = value;

        BaseSystemContracts {
            bootloader: bootloader.into(),
            default_aa: default_aa.into(),
        }
    }
}

impl From<BaseSystemContracts> for MyBaseSystemContracts {
    fn from(value: BaseSystemContracts) -> Self {
        let BaseSystemContracts {
            bootloader,
            default_aa,
        } = value;

        MyBaseSystemContracts {
            bootloader: bootloader.into(),
            default_aa: default_aa.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MySystemEnv {
    // Always false for VM
    zk_porter_available: bool,
    version: ProtocolVersionId,
    base_system_smart_contracts: MyBaseSystemContracts,
    bootloader_gas_limit: u32,
    execution_mode: MyTxExecutionMode,
    default_validation_computational_gas_limit: u32,
    chain_id: L2ChainId,
}

impl From<MySystemEnv> for SystemEnv {
    fn from(value: MySystemEnv) -> Self {
        let MySystemEnv {
            zk_porter_available,
            version,
            base_system_smart_contracts,
            bootloader_gas_limit,
            execution_mode,
            default_validation_computational_gas_limit,
            chain_id,
        } = value;

        SystemEnv {
            default_validation_computational_gas_limit,
            chain_id,
            zk_porter_available,
            version,
            execution_mode: execution_mode.into(),
            base_system_smart_contracts: base_system_smart_contracts.into(),
            bootloader_gas_limit,
        }
    }
}

impl From<SystemEnv> for MySystemEnv {
    fn from(value: SystemEnv) -> Self {
        let SystemEnv {
            zk_porter_available,
            version,
            base_system_smart_contracts,
            bootloader_gas_limit,
            execution_mode,
            default_validation_computational_gas_limit,
            chain_id,
        } = value;

        MySystemEnv {
            default_validation_computational_gas_limit,
            chain_id,
            zk_porter_available,
            version,
            execution_mode: execution_mode.into(),
            base_system_smart_contracts: base_system_smart_contracts.into(),
            bootloader_gas_limit,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum MyTxExecutionMode {
    VerifyExecute,
    EstimateFee,
    EthCall,
}

impl From<MyTxExecutionMode> for TxExecutionMode {
    fn from(value: MyTxExecutionMode) -> Self {
        match value {
            MyTxExecutionMode::VerifyExecute => TxExecutionMode::VerifyExecute,
            MyTxExecutionMode::EstimateFee => TxExecutionMode::EstimateFee,
            MyTxExecutionMode::EthCall => TxExecutionMode::EthCall,
        }
    }
}

impl From<TxExecutionMode> for MyTxExecutionMode {
    fn from(value: TxExecutionMode) -> Self {
        match value {
            TxExecutionMode::VerifyExecute => MyTxExecutionMode::VerifyExecute,
            TxExecutionMode::EstimateFee => MyTxExecutionMode::EstimateFee,
            TxExecutionMode::EthCall => MyTxExecutionMode::EthCall,
        }
    }
}

/// Storage data used as input for the TEE verifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V1TeeVerifierInput {
    prepare_basic_circuits_job: PrepareBasicCircuitsJob,
    new_root_hash: H256,
    miniblocks_execution_data: Vec<MyL2BlockExecutionData>,
    l1_batch_env: MyL1BatchEnv,
    system_env: MySystemEnv,
    used_contracts: Vec<(H256, Vec<u8>)>,
}

/// Storage data used as input for the TEE verifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub enum TeeVerifierInput {
    V0,
    V1(V1TeeVerifierInput),
}

impl TeeVerifierInput {
    pub fn new(
        prepare_basic_circuits_job: PrepareBasicCircuitsJob,
        new_root_hash: H256,
        miniblocks_execution_data: Vec<L2BlockExecutionData>,
        l1_batch_env: L1BatchEnv,
        system_env: SystemEnv,
        used_contracts: Vec<(H256, Vec<u8>)>,
    ) -> Self {
        TeeVerifierInput::V1(V1TeeVerifierInput {
            prepare_basic_circuits_job,
            new_root_hash,
            miniblocks_execution_data: miniblocks_execution_data
                .into_iter()
                .map(|v| v.into())
                .collect(),
            l1_batch_env: l1_batch_env.into(),
            system_env: system_env.into(),
            used_contracts,
        })
    }

    pub fn run_tee_verifier(self) -> anyhow::Result<()> {
        let TeeVerifierInput::V1(V1TeeVerifierInput {
            prepare_basic_circuits_job,
            new_root_hash,
            miniblocks_execution_data,
            l1_batch_env,
            system_env,
            used_contracts,
        }) = self
        else {
            error!("TeeVerifierInput variant not supported");
            bail!("TeeVerifierInput variant not supported");
        };

        let old_root_hash = l1_batch_env.previous_batch_hash.unwrap();
        let l1_batch_number = l1_batch_env.number;
        let l2_chain_id = system_env.chain_id;
        let enumeration_index = prepare_basic_circuits_job.next_enumeration_index();

        let mut raw_storage = InMemoryStorage::with_custom_system_contracts_and_chain_id(
            l2_chain_id,
            hash_bytecode,
            Vec::with_capacity(0),
        );

        for (hash, bytes) in used_contracts.into_iter() {
            trace!("raw_storage.store_factory_dep({hash}, bytes)");
            raw_storage.store_factory_dep(hash, bytes)
        }

        let block_output_with_proofs =
            Self::get_bowp_and_set_initial_values(prepare_basic_circuits_job, &mut raw_storage);

        let storage_view = Rc::new(RefCell::new(StorageView::new(&raw_storage)));

        let vm = VmInstance::new(l1_batch_env.into(), system_env.into(), storage_view);

        let miniblocks_execution_data = miniblocks_execution_data
            .into_iter()
            .map(|v| v.into())
            .collect();

        let vm_out = Self::execute_vm(miniblocks_execution_data, vm)?;

        let instructions: Vec<TreeInstruction> =
            Self::generate_tree_instructions(enumeration_index, &block_output_with_proofs, vm_out)?;

        // `verify_proofs` will panic!() if something does not add up.
        block_output_with_proofs
            .verify_proofs(&Blake2Hasher, old_root_hash, &instructions)
            .context("🛑 🛑 Failed to verify_proofs {l1_batch_number} correctly - oh no!")?;

        if block_output_with_proofs.root_hash() != Some(new_root_hash) {
            error!(
                "🛑 🛑 Failed to verify {l1_batch_number} correctly - oh no! {:#?} != {:#?}",
                block_output_with_proofs.root_hash(),
                new_root_hash
            );
            bail!(
                "Failed to verify {l1_batch_number} correctly - oh no! {:#?} != {:#?}",
                block_output_with_proofs.root_hash(),
                new_root_hash
            );
        }

        Ok(())
    }

    fn get_bowp_and_set_initial_values(
        prepare_basic_circuits_job: PrepareBasicCircuitsJob,
        raw_storage: &mut InMemoryStorage,
    ) -> BlockOutputWithProofs {
        let logs = prepare_basic_circuits_job
            .into_merkle_paths()
            .map(
                |StorageLogMetadata {
                     root_hash,
                     merkle_paths,
                     is_write,
                     first_write,
                     leaf_enumeration_index,
                     value_read,
                     leaf_hashed_key: leaf_storage_key,
                     ..
                 }| {
                    let root_hash = root_hash.into();
                    let merkle_path = merkle_paths.into_iter().map(|x| x.into()).collect();
                    let base: TreeLogEntry = match (is_write, first_write, leaf_enumeration_index) {
                        (false, _, 0) => TreeLogEntry::ReadMissingKey,
                        (false, _, _) => {
                            // This is a special U256 here, which needs `to_little_endian`
                            let mut hashed_key = [0_u8; 32];
                            leaf_storage_key.to_little_endian(&mut hashed_key);
                            raw_storage.set_value_hashed_enum(
                                hashed_key.into(),
                                leaf_enumeration_index,
                                value_read.into(),
                            );
                            TreeLogEntry::Read {
                                leaf_index: leaf_enumeration_index,
                                value: value_read.into(),
                            }
                        }
                        (true, true, _) => TreeLogEntry::Inserted,
                        (true, false, _) => {
                            // This is a special U256 here, which needs `to_little_endian`
                            let mut hashed_key = [0_u8; 32];
                            leaf_storage_key.to_little_endian(&mut hashed_key);
                            raw_storage.set_value_hashed_enum(
                                hashed_key.into(),
                                leaf_enumeration_index,
                                value_read.into(),
                            );
                            TreeLogEntry::Updated {
                                leaf_index: leaf_enumeration_index,
                                previous_value: value_read.into(),
                            }
                        }
                    };
                    TreeLogEntryWithProof {
                        base,
                        merkle_path,
                        root_hash,
                    }
                },
            )
            .collect();

        BlockOutputWithProofs {
            logs,
            leaf_count: 0,
        }
    }

    fn execute_vm<S: WriteStorage>(
        miniblocks_execution_data: Vec<L2BlockExecutionData>,
        mut vm: VmInstance<S, HistoryEnabled>,
    ) -> anyhow::Result<FinishedL1Batch> {
        let next_miniblocks_data = miniblocks_execution_data.iter().skip(1);

        let miniblocks_data = miniblocks_execution_data.iter().zip(next_miniblocks_data);

        for (miniblock_data, next_miniblock_data) in miniblocks_data {
            trace!(
                "Started execution of miniblock: {:?}, executing {:?} transactions",
                miniblock_data.number,
                miniblock_data.txs.len(),
            );
            for tx in &miniblock_data.txs {
                trace!("Started execution of tx: {tx:?}");
                execute_tx(tx, &mut vm)
                    .context("failed to execute transaction in TeeVerifierInputProducer")?;
                trace!("Finished execution of tx: {tx:?}");
            }
            vm.start_new_l2_block(L2BlockEnv::from_l2_block_data(next_miniblock_data));

            trace!(
                "Finished execution of miniblock: {:?}",
                miniblock_data.number
            );
        }

        Ok(vm.finish_batch())
    }

    fn map_log_tree(
        log_query: &LogQuery,
        tree_log_entry: &TreeLogEntry,
        idx: &mut u64,
    ) -> anyhow::Result<TreeInstruction> {
        let key = StorageKey::new(
            AccountTreeId::new(log_query.address),
            u256_to_h256(log_query.key),
        )
        .hashed_key_u256();
        Ok(match (log_query.rw_flag, *tree_log_entry) {
            (true, TreeLogEntry::Updated { leaf_index, .. }) => {
                TreeInstruction::write(key, leaf_index, H256(log_query.written_value.into()))
            }
            (true, TreeLogEntry::Inserted) => {
                let leaf_index = *idx;
                *idx += 1;
                TreeInstruction::write(key, leaf_index, H256(log_query.written_value.into()))
            }
            (false, TreeLogEntry::Read { value, .. }) => {
                if log_query.read_value != value.into_uint() {
                    error!(
                        "🛑 🛑 Failed to map LogQuery to TreeInstruction: {:#?} != {:#?}",
                        log_query.read_value, value
                    );
                    bail!(
                        "Failed to map LogQuery to TreeInstruction: {:#?} != {:#?}",
                        log_query.read_value,
                        value
                    );
                }
                TreeInstruction::Read(key)
            }
            (false, TreeLogEntry::ReadMissingKey { .. }) => TreeInstruction::Read(key),
            _ => {
                error!("🛑 🛑 Failed to map LogQuery to TreeInstruction");
                bail!("Failed to map LogQuery to TreeInstruction");
            }
        })
    }

    fn generate_tree_instructions(
        mut idx: u64,
        bowp: &BlockOutputWithProofs,
        vm_out: FinishedL1Batch,
    ) -> anyhow::Result<Vec<TreeInstruction>> {
        vm_out
            .final_execution_state
            .deduplicated_storage_log_queries
            .into_iter()
            .zip(bowp.logs.iter())
            .map(|(log_query, tree_log_entry)| {
                Self::map_log_tree(&log_query, &tree_log_entry.base, &mut idx)
            })
            .collect::<Result<Vec<_>, _>>()
    }
}

impl StoredObject for TeeVerifierInput {
    const BUCKET: Bucket = Bucket::TeeVerifierInput;
    type Key<'a> = L1BatchNumber;

    fn encode_key(key: Self::Key<'_>) -> String {
        format!("tee_verifier_input_for_l1_batch_{key}.bin")
    }

    fn serialize(&self) -> Result<Vec<u8>, BoxedError> {
        let mut buf = Vec::new();
        ciborium::into_writer(&self, &mut buf)?;
        Ok(buf)
    }

    fn deserialize(bytes: Vec<u8>) -> Result<Self, BoxedError> {
        /*
               let val: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
               val.deserialized().map_err(From::from)
        */
        ciborium::from_reader(bytes.as_slice()).map_err(From::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v1_serialization() {
        let tvi = TeeVerifierInput::new(
            PrepareBasicCircuitsJob::new(0),
            H256([1; 32]),
            vec![],
            L1BatchEnv {
                previous_batch_hash: Some(H256([1; 32])),
                number: Default::default(),
                timestamp: 0,
                fee_input: Default::default(),
                fee_account: Default::default(),
                enforced_base_fee: None,
                first_l2_block: L2BlockEnv {
                    number: 0,
                    timestamp: 0,
                    prev_block_hash: H256([1; 32]),
                    max_virtual_blocks_to_create: 0,
                },
            },
            SystemEnv {
                zk_porter_available: false,
                version: Default::default(),
                base_system_smart_contracts: BaseSystemContracts {
                    bootloader: SystemContractCode {
                        code: vec![U256([1; 4])],
                        hash: H256([1; 32]),
                    },
                    default_aa: SystemContractCode {
                        code: vec![U256([1; 4])],
                        hash: H256([1; 32]),
                    },
                },
                bootloader_gas_limit: 0,
                execution_mode: TxExecutionMode::VerifyExecute,
                default_validation_computational_gas_limit: 0,
                chain_id: Default::default(),
            },
            vec![(H256([1; 32]), vec![0, 1, 2, 3, 4])],
        );

        let serialized = <TeeVerifierInput as StoredObject>::serialize(&tvi)
            .expect("Failed to serialize TeeVerifierInput.");
        let deserialized: TeeVerifierInput =
            <TeeVerifierInput as StoredObject>::deserialize(serialized)
                .expect("Failed to deserialize TeeVerifierInput.");

        assert_eq!(tvi, deserialized);
    }
}
