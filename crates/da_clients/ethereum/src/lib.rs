#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]
use alloy::consensus::{
    BlobTransactionSidecar, SignableTransaction, TxEip4844, TxEip4844Variant, TxEip4844WithSidecar, TxEnvelope,
};
use alloy::network::Ethereum;
use alloy::primitives::FixedBytes;
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::client::RpcClient;
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
use std::{env, path::Path};
pub mod config;
pub struct EthereumDaClient {
    #[allow(dead_code)]
    provider: RpcClient<Http<Client>>,
}

#[async_trait]
impl DaClient for EthereumDaClient {
    async fn publish_state_diff(&self, _state_diff: Vec<Vec<u8>>) -> Result<String> {
        let provider = &self.provider;
        // check that the _State_diff has length <= self.max_blob, and throw the error otherwise. (Can be handled on the prior function as well)
        let trusted_setup = KzgSettings::load_trusted_setup_file(Path::new("./trusted_setup.txt"))?;

        let mut sidecar_blobs = vec![];
        let mut sidecar_commitments = vec![];
        let mut sidecar_proofs = vec![];

        for blob_data in _state_diff {
            let mut fixed_size_blob: [u8; 131072] = [0; 131072];
            fixed_size_blob.copy_from_slice(blob_data.as_slice());
            let blob = Blob::new(fixed_size_blob);

            let commitment = KzgCommitment::blob_to_kzg_commitment(&blob, &trusted_setup)?;
            let proof = KzgProof::compute_blob_kzg_proof(&blob, &commitment.to_bytes(), &trusted_setup)?;

            sidecar_blobs.push(FixedBytes::new(fixed_size_blob));
            sidecar_commitments.push(FixedBytes::new(commitment.to_bytes().into_inner()));
            sidecar_proofs.push(FixedBytes::new(proof.to_bytes().into_inner()));
        }
        let sidecar = BlobTransactionSidecar::new(sidecar_blobs, sidecar_commitments, sidecar_proofs);

        unimplemented!()
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
        EthereumDaClient { provider: client }
    }
}
