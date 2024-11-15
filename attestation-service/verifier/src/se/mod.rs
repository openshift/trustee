// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{Context, Result};
use async_trait::async_trait;
use ibmse::SeVerifierImpl;
use log::{debug, warn}; // Keep only the used imports
use tokio::sync::OnceCell;

use crate::{InitDataHash, ReportData, TeeEvidenceParsedClaim, Verifier};

pub mod ibmse;

static VERIFIER: OnceCell<SeVerifierImpl> = OnceCell::const_new();

#[derive(Debug, Default)]
pub struct SeVerifier;

#[async_trait]
impl Verifier for SeVerifier {
    async fn evaluate(
        &self,
        evidence: &[u8],
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<TeeEvidenceParsedClaim> {
        debug!("Initializing SE Verifier...");
        
        let se_verifier = VERIFIER
            .get_or_try_init(|| async { SeVerifierImpl::new() })
            .await
            .context("Failed to initialize SE Verifier")?;

        // Log warnings about unsupported verifications
        if let InitDataHash::Value(_) = expected_init_data_hash {
            warn!("IBM SE verifier does not support verifying init data hash, ignoring the input `init_data_hash`.");
        }
        if let ReportData::Value(_) = expected_report_data {
            warn!("IBM SE verifier does not support verifying report data hash, ignoring the input `report_data`.");
        }
        
        debug!("Evaluating evidence...");
        
        // Directly call the evaluate function if it returns a Result
        let result = se_verifier.evaluate(evidence)
            .context("Failed to evaluate evidence with SE Verifier")?;

        debug!("Evaluation successful: {:?}", result);
        Ok(result)
    }

    async fn generate_supplemental_challenge(&self, tee_parameters: String) -> Result<String> {
        debug!("Generating supplemental challenge...");
        
        let se_verifier = VERIFIER
            .get_or_try_init(|| async { SeVerifierImpl::new() })
            .await
            .context("Failed to initialize SE Verifier for generating supplemental challenge")?;
        
        let challenge = se_verifier
            .generate_supplemental_challenge(tee_parameters)
            .await
            .context("Failed to generate supplemental challenge")?;
        
        debug!("Supplemental challenge generated: {:?}", challenge);
        Ok(challenge)
    }
}

