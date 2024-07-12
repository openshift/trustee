use crate::algs;
use crate::errors::{CoseError, CoseResultWithRet};
use crate::keys;
use cbor::{decoder::DecodeError, types::Type};

pub(crate) const MAX_BYTES: usize = 0x500000;
pub(crate) const CBOR_NUMBER_TYPES: [Type; 8] = [
    Type::UInt16,
    Type::UInt32,
    Type::UInt64,
    Type::UInt8,
    Type::Int16,
    Type::Int32,
    Type::Int64,
    Type::Int8,
];

pub(crate) fn get_alg_id(alg: String) -> CoseResultWithRet<i32> {
    for i in 0..algs::SIGNING_ALGS.len() {
        if algs::SIGNING_ALGS_NAMES[i] == alg {
            return Ok(algs::SIGNING_ALGS[i]);
        }
    }
    for i in 0..algs::ENCRYPT_ALGS.len() {
        if algs::ENCRYPT_ALGS_NAMES[i] == alg {
            return Ok(algs::ENCRYPT_ALGS[i]);
        }
    }
    for i in 0..algs::MAC_ALGS.len() {
        if algs::MAC_ALGS_NAMES[i] == alg {
            return Ok(algs::MAC_ALGS[i]);
        }
    }
    for i in 0..algs::KEY_DISTRIBUTION_ALGS.len() {
        if algs::KEY_DISTRIBUTION_NAMES[i] == alg {
            return Ok(algs::KEY_DISTRIBUTION_ALGS[i]);
        }
    }
    for i in 0..algs::HASH_ALGS.len() {
        if algs::HASH_ALGS_NAMES[i] == alg {
            return Ok(algs::HASH_ALGS[i]);
        }
    }
    Err(CoseError::InvalidAlg())
}
pub(crate) fn ph_bstr(bytes: Result<Vec<u8>, DecodeError>) -> CoseResultWithRet<Vec<u8>> {
    match bytes {
        Ok(value) => Ok(value),
        Err(ref err) => match err {
            DecodeError::UnexpectedType { datatype, info } => {
                if *datatype == Type::Object && *info == 0 {
                    Ok(Vec::new())
                } else {
                    Err(CoseError::InvalidCoseStructure())
                }
            }
            _ => Err(CoseError::InvalidCoseStructure()),
        },
    }
}

pub(crate) fn get_kty_id(kty: String) -> CoseResultWithRet<i32> {
    for i in 0..keys::KTY_ALL.len() {
        if keys::KTY_NAMES[i] == kty {
            return Ok(keys::KTY_ALL[i]);
        }
    }
    Err(CoseError::InvalidKTY())
}
pub(crate) fn get_crv_id(crv: String) -> CoseResultWithRet<i32> {
    for i in 0..keys::CURVES_ALL.len() {
        if keys::CURVES_NAMES[i] == crv {
            return Ok(keys::CURVES_ALL[i]);
        }
    }
    Err(CoseError::InvalidCRV())
}
pub(crate) fn get_key_op_id(key_op: String) -> CoseResultWithRet<i32> {
    for i in 0..keys::KEY_OPS_ALL.len() {
        if keys::KEY_OPS_NAMES[i] == key_op {
            return Ok(keys::KEY_OPS_ALL[i]);
        }
    }
    Err(CoseError::InvalidKeyOp())
}
