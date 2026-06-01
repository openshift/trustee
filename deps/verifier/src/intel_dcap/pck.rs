// Copyright (c) 2026 Intel Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

//! Parsing of Intel SGX extensions from PCK (Provisioning Certification Key)
//! certificates. The extensions are DER-encoded under OID 1.2.840.113741.1.13.1
//! and are present in both TDX and SGX PCK certificate chains.
//! See "Intel® SGX PCK Certificate and Certificate Revocation List Profile Specification".

use anyhow::{Context, Result};
use asn1_rs::{oid, DerSequence, Enumerated, FromDer, Oid};
use x509_parser::prelude::*;

const DCAP_SGX_EXTENSIONS: Oid<'static> = oid!(1.2.840 .113741 .1 .13 .1);

#[derive(Debug, PartialEq, DerSequence)]
struct OidAndString<'a> {
    id: Oid<'a>,
    s: &'a [u8],
}

#[derive(Debug, PartialEq, DerSequence)]
struct OidAndInt<'a> {
    id: Oid<'a>,
    val: u8,
}

#[derive(Debug, PartialEq, DerSequence)]
struct OidAndInt16<'a> {
    id: Oid<'a>,
    val: u16,
}

#[derive(Debug, PartialEq, DerSequence)]
struct OidAndEnum<'a> {
    id: Oid<'a>,
    e: Enumerated,
}

#[derive(Debug, PartialEq, DerSequence)]
struct OidAndBool<'a> {
    id: Oid<'a>,
    b: bool,
}

#[derive(Debug, PartialEq, DerSequence)]
struct PlatformConfig<'a> {
    dynamic_platform: OidAndBool<'a>,
    cached_keys: OidAndBool<'a>,
    smt_enabled: OidAndBool<'a>,
}

#[derive(Debug, PartialEq, DerSequence)]
struct ConfigSequence<'a> {
    id: Oid<'a>,
    configs: PlatformConfig<'a>,
}

#[derive(Debug, PartialEq, DerSequence)]
struct Tcbs<'a> {
    comp1: OidAndInt<'a>,
    comp2: OidAndInt<'a>,
    comp3: OidAndInt<'a>,
    comp4: OidAndInt<'a>,
    comp5: OidAndInt<'a>,
    comp6: OidAndInt<'a>,
    comp7: OidAndInt<'a>,
    comp8: OidAndInt<'a>,
    comp9: OidAndInt<'a>,
    comp10: OidAndInt<'a>,
    comp11: OidAndInt<'a>,
    comp12: OidAndInt<'a>,
    comp13: OidAndInt<'a>,
    comp14: OidAndInt<'a>,
    comp15: OidAndInt<'a>,
    comp16: OidAndInt<'a>,
    pcesvn: OidAndInt16<'a>,
    cpusvn: OidAndString<'a>,
}

#[derive(Debug, PartialEq, DerSequence)]
struct TcbSequence<'a> {
    id: Oid<'a>,
    tcbs: Tcbs<'a>,
}

#[derive(Debug, PartialEq, DerSequence)]
struct SgxExtension<'a> {
    ppid: OidAndString<'a>,
    tcb: TcbSequence<'a>,
    pceid: OidAndString<'a>,
    fmspc: OidAndString<'a>,
    sgxtype: OidAndEnum<'a>,
    platform_instance: OidAndString<'a>,
    configuration: ConfigSequence<'a>,
}

/// Parse all PEM-encoded certificates from a PCK certificate chain.
/// The Intel cert chain ordering is leaf (index 0), intermediate CA, root CA.
pub(crate) fn parse_pck_pem_certs(pem_certs: &[u8]) -> Result<Vec<Pem>> {
    Pem::iter_from_buffer(pem_certs)
        .collect::<Result<Vec<Pem>, _>>()
        .context("failed to parse PCK PEM certificate chain")
}

/// Extract the `platform_instance_id` from an already-parsed PCK leaf certificate.
/// Returns `Ok(None)` if the SGX extensions OID is absent (Processor CA-signed certs).
/// The `platform_instance` field is only present in Platform CA-signed PCK certs.
pub(crate) fn platform_instance_id_from_pck_leaf_cert(
    cert: &X509Certificate,
) -> Result<Option<[u8; 16]>> {
    let ext = cert
        .tbs_certificate
        .get_extension_unique(&DCAP_SGX_EXTENSIONS)
        .context("failed to look up SGX extensions OID")?;

    let ext_value = match ext {
        Some(e) => e.value,
        None => return Ok(None),
    };

    let (_, parsed) =
        SgxExtension::from_der(ext_value).context("failed to parse SGX extension DER")?;

    let bytes: [u8; 16] = parsed
        .platform_instance
        .s
        .try_into()
        .context("platform_instance is not 16 bytes")?;

    // The GUID is stored little-endian in the OCTET STRING; convert to big-endian.
    Ok(Some(u128::from_le_bytes(bytes).to_be_bytes()))
}

#[cfg(test)]
mod tests {
    use super::{parse_pck_pem_certs, platform_instance_id_from_pck_leaf_cert};
    use crate::tdx::quote::{parse_tdx_quote, parse_tdx_quote_certification};

    #[test]
    fn parse_platform_instance_id() {
        let quote_bin = std::fs::read("./test_data/tdx_quote_4.dat").expect("read quote failed");
        let quote = parse_tdx_quote(&quote_bin).expect("parse quote");
        let pck_certs_pem = parse_tdx_quote_certification(&quote_bin, &quote)
            .expect("parse cert chain")
            .qe_certification_data
            .certificates;

        let certs = parse_pck_pem_certs(&pck_certs_pem).expect("parse PEM certs");
        let leaf = certs[0].parse_x509().expect("parse leaf cert");

        let piid = platform_instance_id_from_pck_leaf_cert(&leaf)
            .expect("extract platform_instance_id")
            .expect("platform_instance_id not present");

        assert_eq!(hex::encode(piid), "82548d228d94d5e204a95b354dc61a02");
    }
}
