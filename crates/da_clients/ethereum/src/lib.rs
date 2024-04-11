#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]
use alloy::consensus::{
    BlobTransactionSidecar, SignableTransaction, TxEip4844, TxEip4844Variant, TxEip4844WithSidecar, TxEnvelope,
};
use alloy::eips::{eip2718::Encodable2718, eip2930::AccessList, eip4844::BYTES_PER_BLOB};
use alloy::network::{Ethereum, TxSigner};
use alloy::primitives::{bytes, FixedBytes, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::client::RpcClient;
use alloy::signers::wallet::LocalWallet;
use alloy::transports::http::Http;
use async_trait::async_trait;
use color_eyre::Result;
// use reqwest::async_impl::client::Client;
use reqwest::Client;
use starknet::core::types::FieldElement;
use std::str::FromStr;
use url::Url;

use c_kzg::{Blob, KzgCommitment, KzgProof, KzgSettings};
use config::EthereumDaConfig;
use da_client_interface::{DaClient, DaVerificationStatus};
use dotenv::dotenv;
use std::{env, path::Path};
pub mod config;
pub struct EthereumDaClient {
    #[allow(dead_code)]
    provider: RootProvider<Ethereum, Http<Client>>,
}

#[async_trait]
impl DaClient for EthereumDaClient {
    async fn publish_state_diff(&self, _state_diff: Vec<Vec<u8>>) -> Result<String> {
        dotenv().ok();
        let provider = &self.provider;
        // check that the _State_diff has length <= self.max_blob, and throw the error otherwise. (Can be handled on the prior function as well)
        let trusted_setup = KzgSettings::load_trusted_setup_file(Path::new("./trusted_setup.txt"))?;
        let wallet: LocalWallet = env::var("PK").expect("PK must be set").parse()?;
        let addr = wallet.address();

        let (sidecar_blobs, sidecar_commitments, sidecar_proofs) =
            prepare_sidecar(&_state_diff, &trusted_setup).await?;
        let sidecar = BlobTransactionSidecar::new(sidecar_blobs, sidecar_commitments, sidecar_proofs);

        let tx = TxEip4844 {
            chain_id: 17000, // Holesky 17000 sepolia 11155111
            nonce: 1,
            gas_limit: 30_000_000,
            max_fee_per_gas: 10000000100, //estimation.max_fee_per_gas.to_string().parse()?,
            max_priority_fee_per_gas: 200000010,
            to: addr,
            value: U256::from(0),
            access_list: AccessList(vec![]),
            blob_versioned_hashes: sidecar.versioned_hashes().collect(),
            max_fee_per_blob_gas: 7300000_535,
            input: bytes!(),
        };
        let txsidecar = TxEip4844WithSidecar { tx: tx.clone(), sidecar: sidecar.clone() };
        let mut variant2 = TxEip4844Variant::from(txsidecar);

        // Sign and submit
        // let mut variant = TxEip4844Variant::from((tx, sidecar));
        let signature = wallet.sign_transaction(&mut variant2).await?;
        let tx_signed = variant2.into_signed(signature);
        let tx_envelope: TxEnvelope = tx_signed.into();
        let encoded = tx_envelope.encoded_2718();

        let pending_tx = provider.send_raw_transaction(&encoded).await?;
        println!("{:?} ", pending_tx);
        println!("Pending transaction...{:?}", pending_tx.tx_hash());

        // // Wait for the transaction to be included.
        // let receipt = pending_tx.get_receipt().await?;
        // println!(
        //     "Transaction included in block: {:?} and tx is {:?}",
        //     receipt.block_number.expect("Failed to get block number").to_string(),
        //     receipt.transaction_hash.expect("Failed to get block number").to_string()
        // );

        Ok(pending_tx.tx_hash().to_string())
    }

    async fn verify_inclusion(&self, _external_id: &str) -> Result<DaVerificationStatus> {
        todo!()
    }

    async fn max_blob_per_txn(&self) -> u64 {
        6
    }

    async fn max_bytes_per_blob(&self) -> u64 {
        131072
    }
}

impl From<EthereumDaConfig> for EthereumDaClient {
    fn from(config: EthereumDaConfig) -> Self {
        // let provider = RpcClient::builder().reqwest_http();
        let client =
            RpcClient::new_http(Url::from_str(config.rpc_url.as_str()).expect("Failed to parse ETHEREUM_RPC_URL"));
        let provider = ProviderBuilder::<_, Ethereum>::new().on_client(client);
        EthereumDaClient { provider }
    }
}

async fn prepare_sidecar(
    state_diff: &[Vec<u8>],
    trusted_setup: &KzgSettings,
) -> Result<(Vec<FixedBytes<131072>>, Vec<FixedBytes<48>>, Vec<FixedBytes<48>>)> {
    let mut sidecar_blobs = vec![];
    let mut sidecar_commitments = vec![];
    let mut sidecar_proofs = vec![];

    for blob_data in state_diff {
        // Ensure blob data size matches expected value
        // if blob_data.len() != BYTES_PER_BLOB as usize {
        //     return Err(color_eyre::Report::new(format!(
        //         "Invalid blob size: expected {}, got {}",
        //         BYTES_PER_BLOB,
        //         blob_data.len()
        //     )));
        // }

        let mut fixed_size_blob: [u8; BYTES_PER_BLOB as usize] = [0; BYTES_PER_BLOB as usize];
        fixed_size_blob.copy_from_slice(blob_data.as_slice());

        let blob = Blob::new(fixed_size_blob);

        let commitment = KzgCommitment::blob_to_kzg_commitment(&blob, trusted_setup)?;
        let proof = KzgProof::compute_blob_kzg_proof(&blob, &commitment.to_bytes(), trusted_setup)?;

        sidecar_blobs.push(FixedBytes::new(fixed_size_blob));
        sidecar_commitments.push(FixedBytes::new(commitment.to_bytes().into_inner()));
        sidecar_proofs.push(FixedBytes::new(proof.to_bytes().into_inner()));
    }

    Ok((sidecar_blobs, sidecar_commitments, sidecar_proofs))
}
