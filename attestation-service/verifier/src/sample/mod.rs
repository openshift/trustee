use log::{debug, trace}; // Import necessary log macros
extern crate serde;
use serde::{Deserialize, Serialize};
use super::*;
use async_trait::async_trait;
use base64::Engine;
use serde_json::json;
use anyhow::{bail, Context, Result}; // Ensure necessary imports for error handling

#[derive(Serialize, Deserialize, Debug)]
struct SampleTeeEvidence {
    svn: String,

    #[serde(default = "String::default")]
    report_data: String,

    #[serde(default = "String::default")]
    init_data: String,
}

#[derive(Debug, Default)]
pub struct Sample {}

#[async_trait]
impl Verifier for Sample {
    async fn evaluate(
        &self,
        evidence: &[u8],
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<TeeEvidenceParsedClaim> {
        debug!("Starting evaluation of TEE evidence.");

        let tee_evidence = serde_json::from_slice::<SampleTeeEvidence>(evidence)
            .with_context(|| "Deserialize Quote failed.")?;

        debug!("TEE evidence deserialized successfully: {:?}", tee_evidence);

        verify_tee_evidence(expected_report_data, expected_init_data_hash, &tee_evidence)
            .await
            .with_context(|| "Evidence's identity verification error.")?;

        debug!("TEE evidence verified successfully.");

        let parsed_claim = parse_tee_evidence(&tee_evidence)?;
        debug!("Parsed TEE evidence claims: {:?}", parsed_claim);

        Ok(parsed_claim)
    }
}

async fn verify_tee_evidence(
    expected_report_data: &ReportData<'_>,
    expected_init_data_hash: &InitDataHash<'_>,
    evidence: &SampleTeeEvidence,
) -> Result<()> {
    debug!("Verifying TEE evidence...");

    // Verify the TEE Hardware signature. (Null for sample TEE)

    // Emulate the report data.
    if let ReportData::Value(expected_report_data) = expected_report_data {
        debug!("Checking the binding of REPORT_DATA.");
        let ev_report_data = base64::engine::general_purpose::STANDARD
            .decode(&evidence.report_data)
            .with_context(|| "Base64 decode report data for sample evidence failed.")?;

        debug!("Decoded report data: {:?}", ev_report_data);
        
        if *expected_report_data != ev_report_data {
            bail!("REPORT_DATA is different from that in Sample Quote");
        }
        debug!("REPORT_DATA matches expected value.");
    } else {
        debug!("Expected report data is not a Value type, skipping verification.");
    }

    // Emulate the init data hash.
    if let InitDataHash::Value(expected_init_data_hash) = expected_init_data_hash {
        debug!("Checking the binding of INIT_DATA_HASH.");
        let ev_init_data_hash = base64::engine::general_purpose::STANDARD
            .decode(&evidence.init_data)
            .with_context(|| "Base64 decode init data hash for sample evidence failed.")?;

        debug!("Decoded init data hash: {:?}", ev_init_data_hash);

        if *expected_init_data_hash != ev_init_data_hash {
            bail!("INIT DATA HASH is different from that in Sample Quote");
        }
        debug!("INIT DATA HASH matches expected value.");
    } else {
        debug!("Expected init data hash is not a Value type, skipping verification.");
    }

    Ok(())
}

// Dump the TCB status from the quote.
// Example: CPU SVN, RTMR, etc.
fn parse_tee_evidence(quote: &SampleTeeEvidence) -> Result<TeeEvidenceParsedClaim> {
    debug!("Parsing TEE evidence for claims.");

    let claims_map = json!({
        "svn": quote.svn,
        "report_data": quote.report_data,
        "init_data": quote.init_data,
    });

    debug!("Parsed claims: {:?}", claims_map);

    Ok(claims_map as TeeEvidenceParsedClaim)
}

