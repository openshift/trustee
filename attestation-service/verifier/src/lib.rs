use std::cmp::Ordering;
use anyhow::*;
use async_trait::async_trait;
use kbs_types::Tee;
use log::debug;

pub mod sample;

#[cfg(feature = "az-snp-vtpm-verifier")]
pub mod az_snp_vtpm;

#[cfg(feature = "az-tdx-vtpm-verifier")]
pub mod az_tdx_vtpm;

#[cfg(feature = "snp-verifier")]
pub mod snp;

#[cfg(feature = "tdx-verifier")]
pub mod tdx;

#[cfg(feature = "sgx-verifier")]
pub mod sgx;

#[cfg(feature = "csv-verifier")]
pub mod csv;

#[cfg(feature = "cca-verifier")]
pub mod cca;

#[cfg(feature = "se-verifier")]
pub mod se;

pub fn to_verifier(tee: &Tee) -> Result<Box<dyn Verifier + Send + Sync>> {
    debug!("Attempting to map TEE {:?} to a verifier implementation", tee);
    match tee {
        Tee::Sev => {
            debug!("SEV support is currently not implemented");
            todo!()
        }
        Tee::AzSnpVtpm => {
            debug!("Attempting to initialize AZ SNP vTPM verifier");
            cfg_if::cfg_if! {
                if #[cfg(feature = "az-snp-vtpm-verifier")] {
                    let verifier = az_snp_vtpm::AzSnpVtpm::new()?;
                    debug!("AZ SNP vTPM verifier initialized successfully");
                    Ok(Box::new(verifier) as Box<dyn Verifier + Send + Sync>)
                } else {
                    debug!("AZ SNP vTPM verifier feature is not enabled");
                    bail!("feature `az-snp-vtpm-verifier` is not enabled for `verifier` crate.")
                }
            }
        }
        Tee::AzTdxVtpm => {
            debug!("Attempting to initialize AZ TDX vTPM verifier");
            cfg_if::cfg_if! {
                if #[cfg(feature = "az-tdx-vtpm-verifier")] {
                    debug!("AZ TDX vTPM verifier initialized successfully");
                    Ok(Box::<az_tdx_vtpm::AzTdxVtpm>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    debug!("AZ TDX vTPM verifier feature is not enabled");
                    bail!("feature `az-tdx-vtpm-verifier` is not enabled for `verifier` crate.");
                }
            }
        }
        Tee::Tdx => {
            debug!("Attempting to initialize TDX verifier");
            cfg_if::cfg_if! {
                if #[cfg(feature = "tdx-verifier")] {
                    debug!("TDX verifier initialized successfully");
                    Ok(Box::<tdx::Tdx>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    debug!("TDX verifier feature is not enabled");
                    bail!("feature `tdx-verifier` is not enabled for `verifier` crate.")
                }
            }
        }
        Tee::Snp => {
            debug!("Attempting to initialize SNP verifier");
            cfg_if::cfg_if! {
                if #[cfg(feature = "snp-verifier")] {
                    let verifier = snp::Snp::new()?;
                    debug!("SNP verifier initialized successfully");
                    Ok(Box::new(verifier) as Box<dyn Verifier + Send + Sync>)
                } else {
                    debug!("SNP verifier feature is not enabled");
                    bail!("feature `snp-verifier` is not enabled for `verifier` crate.")
                }
            }
        }
        Tee::Sample => {
            debug!("Using Sample verifier");
            Ok(Box::<sample::Sample>::default() as Box<dyn Verifier + Send + Sync>)
        }
        Tee::Sgx => {
            debug!("Attempting to initialize SGX verifier");
            cfg_if::cfg_if! {
                if #[cfg(feature = "sgx-verifier")] {
                    debug!("SGX verifier initialized successfully");
                    Ok(Box::<sgx::SgxVerifier>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    debug!("SGX verifier feature is not enabled");
                    bail!("feature `sgx-verifier` is not enabled for `verifier` crate.")
                }
            }
        }
        Tee::Csv => {
            debug!("Attempting to initialize CSV verifier");
            cfg_if::cfg_if! {
                if #[cfg(feature = "csv-verifier")] {
                    debug!("CSV verifier initialized successfully");
                    Ok(Box::<csv::CsvVerifier>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    debug!("CSV verifier feature is not enabled");
                    bail!("feature `csv-verifier` is not enabled for `verifier` crate.")
                }
            }
        }
        Tee::Cca => {
            debug!("Attempting to initialize CCA verifier");
            cfg_if::cfg_if! {
                if #[cfg(feature = "cca-verifier")] {
                    debug!("CCA verifier initialized successfully");
                    Ok(Box::<cca::CCA>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    debug!("CCA verifier feature is not enabled");
                    bail!("feature `cca-verifier` is not enabled for `verifier` crate.")
                }
            }
        }
        Tee::Se => {
            debug!("Attempting to initialize SE verifier");
            cfg_if::cfg_if! {
                if #[cfg(feature = "se-verifier")] {
                    debug!("SE verifier initialized successfully");
                    Ok(Box::<se::SeVerifier>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    debug!("SE verifier feature is not enabled");
                    bail!("feature `se-verifier` is not enabled for `verifier` crate.")
                }
            }
        }
    }
}

pub type TeeEvidenceParsedClaim = serde_json::Value;

pub enum ReportData<'a> {
    Value(&'a [u8]),
    NotProvided,
}

pub enum InitDataHash<'a> {
    Value(&'a [u8]),
    NotProvided,
}

#[async_trait]
pub trait Verifier {
    /// Verify the hardware signature.
    async fn evaluate(
        &self,
        evidence: &[u8],
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<TeeEvidenceParsedClaim>;

    /// Generate the supplemental challenge
    async fn generate_supplemental_challenge(&self, _tee_parameters: String) -> Result<String> {
        debug!("Generating supplemental challenge");
        Ok(String::new())
    }
}

/// Padding or truncate the given data slice to the given `len` bytes.
fn regularize_data(data: &[u8], len: usize, data_name: &str, arch: &str) -> Vec<u8> {
    let data_len = data.len();
    match data_len.cmp(&len) {
        Ordering::Less => {
            debug!(
                "The input {data_name} of {arch} is shorter than {len} bytes, padding with '\\0'."
            );
            let mut data = data.to_vec();
            data.resize(len, b'\0');
            data
        }
        Ordering::Equal => {
            debug!("The input {data_name} of {arch} is exactly {len} bytes.");
            data.to_vec()
        }
        Ordering::Greater => {
            debug!(
                "The input {data_name} of {arch} is longer than {len} bytes, truncating to {len} bytes."
            );
            data[..len].to_vec()
        }
    }
}

