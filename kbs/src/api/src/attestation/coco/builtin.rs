// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::attestation::Attest;
use anyhow::*;
use async_trait::async_trait;
use attestation_service::{config::Config as AsConfig, AttestationService, Data, HashAlgorithm};
use base64::{engine::general_purpose::STANDARD, Engine};
use kbs_types::{Attestation, Challenge, Tee};
use rand::{thread_rng, Rng};
use serde_json::json;
use tokio::sync::RwLock;
use log::{debug, info, error}; // Added logging imports

pub struct BuiltInCoCoAs {
    inner: RwLock<AttestationService>,
}

#[async_trait]
impl Attest for BuiltInCoCoAs {
    async fn set_policy(&self, policy_id: &str, policy: &str) -> Result<()> {
        // Log policy details before setting
        debug!("Setting policy: policy_id = {}, policy = {}", policy_id, policy);

        self.inner
            .write()
            .await
            .set_policy(policy_id.to_string(), policy.to_string())
            .await
            .map_err(|e| {
                error!("Failed to set policy: {:?}", e);
                e
            })?;

        info!("Policy set successfully for policy_id = {}", policy_id);
        Ok(())
    }

    async fn verify(&self, tee: Tee, nonce: &str, attestation: &str) -> Result<String> {
        debug!("Verifying attestation: tee = {:?}, nonce = {}", tee, nonce);

        let attestation: Attestation = serde_json::from_str(attestation)
            .map_err(|e| {
                error!("Failed to deserialize attestation: {:?}", e);
                e
            })?;

        let runtime_data_plaintext = json!({"tee-pubkey": attestation.tee_pubkey, "nonce": nonce});

        debug!("Generated runtime data plaintext: {}", runtime_data_plaintext);

        // Log before calling evaluate
        info!("Sending evaluate request with attestation data and runtime data");

        let result = self
            .inner
            .read()
            .await
            .evaluate(
                attestation.tee_evidence.into_bytes(),
                tee,
                Some(Data::Structured(runtime_data_plaintext)),
                HashAlgorithm::Sha384,
                None,
                HashAlgorithm::Sha384,
                vec!["default".into()],
            )
            .await
            .map_err(|e| {
                error!("Attestation evaluation failed: {:?}", e);
                e
            })?;

        info!("Attestation verified successfully, result: {}", result);
        Ok(result)
    }

    async fn generate_challenge(&self, tee: Tee, tee_parameters: String) -> Result<Challenge> {
        info!("Generating challenge for TEE: {:?}", tee);

        let nonce = match tee {
            Tee::Se => {
                info!("Generating supplemental challenge for SE");
                self.inner
                    .read()
                    .await
                    .generate_supplemental_challenge(tee, tee_parameters)
                    .await
                    .map_err(|e| {
                        error!("Failed to generate supplemental challenge: {:?}", e);
                        e
                    })?
            }
            _ => {
                let mut nonce: Vec<u8> = vec![0; 32];

                thread_rng()
                    .try_fill(&mut nonce[..])
                    .map_err(|e| {
                        error!("Failed to generate random nonce: {:?}", e);
                        e
                    })?;

                info!("Generated random nonce for challenge");

                STANDARD.encode(&nonce)
            }
        };

        debug!("Generated challenge nonce: {}", nonce);

        let challenge = Challenge {
            nonce,
            extra_params: String::new(),
        };

        Ok(challenge)
    }
}

impl BuiltInCoCoAs {
    pub async fn new(config: AsConfig) -> Result<Self> {
        info!("Initializing BuiltInCoCoAs with config");

        let inner = RwLock::new(AttestationService::new(config).await?);

        debug!("AttestationService initialized successfully");

        Ok(Self { inner })
    }
}

