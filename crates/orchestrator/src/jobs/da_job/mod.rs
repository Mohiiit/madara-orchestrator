use crate::config::Config;
use crate::jobs::types::{JobItem, JobStatus, JobType, JobVerificationStatus};
use crate::jobs::Job;
use async_trait::async_trait;
use color_eyre::eyre::eyre;
use color_eyre::Result;
use starknet::core::types::{BlockId, FieldElement, MaybePendingStateUpdate, StateUpdate, StorageEntry};
use starknet::providers::Provider;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use tracing::log;
use uuid::Uuid;
pub struct DaJob;

#[async_trait]
impl Job for DaJob {
    async fn create_job(&self, _config: &Config, internal_id: String) -> Result<JobItem> {
        Ok(JobItem {
            id: Uuid::new_v4(),
            internal_id,
            job_type: JobType::DataSubmission,
            status: JobStatus::Created,
            external_id: String::new().into(),
            metadata: HashMap::new(),
            version: 0,
        })
    }

    async fn process_job(&self, config: &Config, job: &JobItem) -> Result<String> {
        let block_no = job.internal_id.parse::<u64>()?;
        let state_update = config.starknet_client().get_state_update(BlockId::Number(block_no)).await?;

        let state_update = match state_update {
            MaybePendingStateUpdate::PendingUpdate(_) => {
                log::error!("Cannot process block {} for job id {} as it's still in pending state", block_no, job.id);
                return Err(eyre!(
                    "Cannot process block {} for job id {} as it's still in pending state",
                    block_no,
                    job.id
                ));
            }
            MaybePendingStateUpdate::Update(state_update) => state_update,
        };

        let blob_data = state_update_to_blob_data(block_no, state_update);
        let max_bytes_per_blob = config.da_client().max_bytes_per_blob().await;
        let max_blob_per_txn = config.da_client().max_blob_per_txn().await;
        let blob_array = field_elements_to_blobs(max_bytes_per_blob, blob_data);
        let current_blob_length: u64 = blob_array.len().try_into().unwrap();
        if current_blob_length > max_blob_per_txn {
            return Err(eyre!(
                "Cannot process block {} for job id {} as number of blobs allowd are {} but it contains {} blobs",
                block_no,
                job.id,
                max_blob_per_txn,
                current_blob_length
            ));
        }
        let external_id = config.da_client().publish_state_diff(blob_array).await?;

        Ok(external_id)
    }

    async fn verify_job(&self, config: &Config, job: &JobItem) -> Result<JobVerificationStatus> {
        Ok(config.da_client().verify_inclusion(job.external_id.unwrap_string()?).await?.into())
    }

    fn max_process_attempts(&self) -> u64 {
        1
    }

    fn max_verification_attempts(&self) -> u64 {
        3
    }

    fn verification_polling_delay_seconds(&self) -> u64 {
        60
    }
}

fn field_elements_to_blobs(blob_size: u64, blob_data: Vec<FieldElement>) -> Vec<Vec<u8>> {
    // Validate blob size
    if blob_size < 32 {
        panic!("Blob size must be at least 32 bytes to accommodate a single FieldElement");
    }

    let mut blobs: Vec<Vec<u8>> = Vec::new();

    // Convert all FieldElements to bytes first
    let mut bytes: Vec<u8> = blob_data.iter().flat_map(|element| element.to_bytes_be().to_vec()).collect();

    // Process bytes in chunks of blob_size
    while bytes.len() >= blob_size as usize {
        let chunk = bytes.drain(..blob_size as usize).collect();
        blobs.push(chunk);
    }

    // Handle any remaining bytes (not a complete blob)
    if !bytes.is_empty() {
        let remaining_bytes = bytes.len();
        let mut last_blob = bytes;
        last_blob.resize(blob_size as usize, 0); // Pad with zeros
        blobs.push(last_blob);
        println!("Warning: Remaining {} bytes not forming a complete blob were padded", remaining_bytes);
    }

    return blobs;
}

fn state_update_to_blob_data(block_no: u64, state_update: StateUpdate) -> Vec<FieldElement> {
    let state_diff = state_update.state_diff;
    let mut blob_data: Vec<FieldElement> = vec![
        // TODO: confirm first three fields
        FieldElement::from(state_diff.storage_diffs.len()),
        FieldElement::ONE,
        FieldElement::ONE,
        FieldElement::from(block_no),
        state_update.block_hash,
    ];

    let storage_diffs: HashMap<FieldElement, &Vec<StorageEntry>> =
        state_diff.storage_diffs.iter().map(|item| (item.address, &item.storage_entries)).collect();
    let declared_classes: HashMap<FieldElement, FieldElement> =
        state_diff.declared_classes.iter().map(|item| (item.class_hash, item.compiled_class_hash)).collect();
    let deployed_contracts: HashMap<FieldElement, FieldElement> =
        state_diff.deployed_contracts.iter().map(|item| (item.address, item.class_hash)).collect();
    let replaced_classes: HashMap<FieldElement, FieldElement> =
        state_diff.replaced_classes.iter().map(|item| (item.contract_address, item.class_hash)).collect();
    let mut nonces: HashMap<FieldElement, FieldElement> =
        state_diff.nonces.iter().map(|item| (item.contract_address, item.nonce)).collect();

    // Loop over storage diffs
    for (addr, writes) in storage_diffs {
        blob_data.push(addr);

        let class_flag = deployed_contracts.get(&addr).or_else(|| replaced_classes.get(&addr));

        let nonce = nonces.remove(&addr);
        blob_data.push(da_word(class_flag.is_some(), nonce, writes.len() as u64));

        if let Some(class_hash) = class_flag {
            blob_data.push(*class_hash);
        }

        for entry in writes {
            blob_data.push(entry.key);
            blob_data.push(entry.value);
        }
    }

    // Handle nonces
    for (addr, nonce) in nonces {
        blob_data.push(addr);

        let class_flag = deployed_contracts.get(&addr).or_else(|| replaced_classes.get(&addr));

        blob_data.push(da_word(class_flag.is_some(), Some(nonce), 0_u64));
        if let Some(class_hash) = class_flag {
            blob_data.push(*class_hash);
        }
    }

    // Handle deployed contracts
    for (addr, class_hash) in deployed_contracts {
        blob_data.push(addr);

        blob_data.push(da_word(true, None, 0_u64));
        blob_data.push(class_hash);
    }

    // Handle declared classes
    blob_data.push(FieldElement::from(declared_classes.len()));

    for (class_hash, compiled_class_hash) in &declared_classes {
        blob_data.push(*class_hash);
        blob_data.push(*compiled_class_hash);
    }

    blob_data
}

/// DA word encoding:
/// |---padding---|---class flag---|---new nonce---|---num changes---|
///     127 bits        1 bit           64 bits          64 bits
fn da_word(class_flag: bool, nonce_change: Option<FieldElement>, num_changes: u64) -> FieldElement {
    const CLASS_FLAG_TRUE: &str = "0x100000000000000000000000000000001"; // 2 ^ 128 + 1
    const NONCE_BASE: &str = "0xFFFFFFFFFFFFFFFF"; // 2 ^ 64 - 1

    let mut word = FieldElement::ZERO;

    if class_flag {
        word += FieldElement::from_hex_be(CLASS_FLAG_TRUE).unwrap();
    }
    if let Some(new_nonce) = nonce_change {
        word += new_nonce + FieldElement::from_hex_be(NONCE_BASE).unwrap();
    }

    word += FieldElement::from(num_changes);

    word
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(false, 1, 1, "18446744073709551617")]
    #[case(false, 1, 0, "18446744073709551616")]
    #[case(false, 0, 6, "6")]
    #[case(true, 1, 0, "340282366920938463481821351505477763073")]
    fn da_word_works(
        #[case] class_flag: bool,
        #[case] new_nonce: u64,
        #[case] num_changes: u64,
        #[case] expected: String,
    ) {
        let new_nonce = if new_nonce > 0 { Some(FieldElement::from(new_nonce)) } else { None };
        let da_word = da_word(class_flag, new_nonce, num_changes);
        let expected = FieldElement::from_dec_str(expected.as_str()).unwrap();
        assert_eq!(da_word, expected);
    }

    #[rstest]
    #[case(131072, 4096, 1)]
    #[case(131072, 2, 1)]
    #[case(131072, 5000, 2)]
    #[case(131072, 4096*2, 2)]
    fn test_field_elements_to_blobs_works(
        #[case] blob_size: u64,
        #[case] num_elements: u64,
        #[case] expected_blobs: u8,
    ) {
        let mut elements = Vec::new();
        for _ in 0..num_elements {
            elements.push(FieldElement::from_bytes_be(&[1; 32]).expect("Issues in changing"));
        }

        let blobs = field_elements_to_blobs(blob_size, elements);

        assert_eq!(blobs.len(), expected_blobs as usize);
        for i in 0..blobs.len() {
            assert_eq!(blobs[i].len(), blob_size as usize);

            // files can be created to see each element is right or not
            // let filename = format!("{}_elements_{}.txt", num_elements, i + 1);
            // let mut file = File::create(filename).expect("Failed to create file");

            // for element in &blobs[i] {
            //     // Convert vec<u8> to a single line string representation
            //     // (modify this line based on your desired format)
            //     let element_string = format!("{:?}\n", element);
            //     file.write_all(element_string.as_bytes()).expect("Failed to write to file");
            // }
        }
    }
}
