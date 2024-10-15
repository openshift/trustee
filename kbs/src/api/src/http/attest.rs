// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::{raise_error, session::SessionStatus};

use super::*;

use anyhow::anyhow;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use kbs_types::Challenge;
use log::{debug, error, info};
use serde_json::json;

/// POST /auth
pub(crate) async fn auth(
    request: web::Json<Request>,
    map: web::Data<SessionMap>,
    timeout: web::Data<i64>,
    attestation_service: web::Data<Arc<AttestationService>>,
) -> Result<HttpResponse> {
    info!("Auth API called.");
    debug!("Auth Request: {:?}", &request);

    let challenge = attestation_service
        .generate_challenge(request.tee, request.extra_params.clone())
        .await
        .map_err(|e| {
            error!("Failed to generate challenge: {:?}", e);
            Error::FailedAuthentication(format!("generate challenge: {e:?}"))
        })?;

    debug!("Generated challenge: {:?}", challenge);

    let session = SessionStatus::auth(request.0, **timeout, challenge)
        .map_err(|e| {
            error!("Failed to authenticate session: {:?}", e);
            Error::FailedAuthentication(format!("Session: {e}"))
        })?;

    debug!("Session created: ID={}, timeout={:?}", session.id(), session.timeout());

    let response = HttpResponse::Ok()
        .cookie(session.cookie())
        .json(session.challenge());

    debug!("Sending response with session challenge: {:?}", session.challenge());

    map.insert(session);

    info!("Session inserted into the session map.");

    Ok(response)
}

/// POST /attest
pub(crate) async fn attest(
    attestation: web::Json<Attestation>,
    request: HttpRequest,
    map: web::Data<SessionMap>,
    attestation_service: web::Data<Arc<AttestationService>>,
) -> Result<HttpResponse> {
    info!("Attest API called.");
    debug!("Attestation request: {:?}", attestation);

    let cookie = request.cookie(KBS_SESSION_ID).ok_or_else(|| {
        error!("Missing session cookie.");
        Error::MissingCookie
    })?;
    debug!("Found session cookie: {:?}", cookie);

    let (tee, nonce) = {
        let session = map
            .sessions
            .get_async(cookie.value())
            .await
            .ok_or_else(|| {
                error!("Invalid session cookie: {}", cookie.value());
                Error::InvalidCookie
            })?;
        let session = session.get();

        debug!("Session ID: {}", session.id());

        if session.is_expired() {
            error!("Session has expired: ID={}", session.id());
            raise_error!(Error::ExpiredCookie);
        }

        if let SessionStatus::Attested { token, .. } = session {
            debug!(
                "Session {} is already attested. Returning the old token.",
                session.id()
            );
            let body = serde_json::to_string(&json!({
                "token": token,
            }))
            .map_err(|e| {
                error!("Failed to serialize token: {:?}", e);
                Error::TokenIssueFailed(format!("Serialize token failed {e}"))
            })?;

            return Ok(HttpResponse::Ok()
                .cookie(session.cookie())
                .content_type("application/json")
                .body(body));
        }

        let attestation_str = serde_json::to_string_pretty(&attestation.0)
            .map_err(|e| {
                error!("Failed to serialize attestation: {:?}", e);
                Error::AttestationFailed("Failed to serialize Attestation".into())
            })?;
        debug!("Serialized attestation: {attestation_str}");

        (session.request().tee, session.challenge().nonce.to_string())
    };

    let attestation_str = serde_json::to_string(&attestation)
        .map_err(|e| {
            error!("Failed to serialize attestation: {:?}", e);
            Error::AttestationFailed(format!("serialize attestation failed : {e:?}"))
        })?;
    debug!("Serialized attestation for verification: {}", attestation_str);

    let token = attestation_service
        .verify(tee, &nonce, &attestation_str)
        .await
        .map_err(|e| {
            error!("Attestation verification failed: {:?}", e);
            Error::AttestationFailed(format!("{e:?}"))
        })?;
    debug!("Attestation verification successful. Token generated: {}", token);

    let claims_b64 = token
        .split('.')
        .nth(1)
        .ok_or_else(|| {
            error!("Illegal token format: {}", token);
            Error::TokenIssueFailed("Illegal token format".to_string())
        })?;
    let claims = String::from_utf8(
        URL_SAFE_NO_PAD
            .decode(claims_b64)
            .map_err(|e| {
                error!("Illegal token base64 claims: {:?}", e);
                Error::TokenIssueFailed(format!("Illegal token base64 claims: {e}"))
            })?,
    )
    .map_err(|e| {
        error!("Failed to convert base64 claims to string: {:?}", e);
        Error::TokenIssueFailed(format!("Illegal token base64 claims: {e}"))
    })?;
    debug!("Decoded token claims: {}", claims);

    let mut session = map
        .sessions
        .get_async(cookie.value())
        .await
        .ok_or_else(|| {
            error!("Invalid session cookie during update: {}", cookie.value());
            Error::InvalidCookie
        })?;
    let session = session.get_mut();

    let body = serde_json::to_string(&json!({
        "token": token,
    }))
    .map_err(|e| {
        error!("Failed to serialize token for response: {:?}", e);
        Error::TokenIssueFailed(format!("Serialize token failed {e}"))
    })?;

    debug!("Session attested successfully. Token: {}", token);
    session.attest(claims, token);

    Ok(HttpResponse::Ok()
        .cookie(session.cookie())
        .content_type("application/json")
        .body(body))
}

