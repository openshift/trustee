// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::cookie::{
    time::{Duration, OffsetDateTime},
    Cookie,
};
use anyhow::{bail, Result};
use kbs_types::{Challenge, Request};
use log::{debug, warn};
use semver::Version;
use uuid::Uuid;

pub(crate) static KBS_SESSION_ID: &str = "kbs-session-id";

/// Finite State Machine model for RCAR handshake
pub(crate) enum SessionStatus {
    Authed {
        request: Request,
        challenge: Challenge,
        id: String,
        timeout: OffsetDateTime,
    },

    Attested {
        attestation_claims: String,
        token: String,
        id: String,
        timeout: OffsetDateTime,
    },
}

macro_rules! impl_member {
    ($attr: ident, $typ: ident) => {
        pub fn $attr(&self) -> &$typ {
            match self {
                SessionStatus::Authed { $attr, .. } => $attr,
                SessionStatus::Attested { $attr, .. } => $attr,
            }
        }
    };
    ($attr: ident, $typ: ident, $branch: ident) => {
        pub fn $attr(&self) -> &$typ {
            match self {
                SessionStatus::$branch { $attr, .. } => $attr,
                _ => panic!("unexpected status"),
            }
        }
    };
}

impl SessionStatus {
    pub fn auth(request: Request, timeout: i64, challenge: Challenge) -> Result<Self> {
        debug!("Starting authentication with request: {:?}", request);

        let version = Version::parse(&request.version).map_err(anyhow::Error::from)?;
        debug!("Parsed version: {}", version);

        if !crate::VERSION_REQ.matches(&version) {
            bail!("Invalid Request version {}", request.version);
        }
        debug!("Request version is valid.");

        let id = Uuid::new_v4().as_simple().to_string();
        debug!("Generated session ID: {}", id);

        let timeout = OffsetDateTime::now_utc() + Duration::minutes(timeout);
        debug!("Session timeout set to: {:?}", timeout);

        Ok(Self::Authed {
            request,
            challenge,
            id,
            timeout,
        })
    }

    pub fn cookie<'a>(&self) -> Cookie<'a> {
        debug!("Generating cookie for session.");
        match self {
            SessionStatus::Authed { id, timeout, .. } => {
                debug!("Authed session cookie: id={}, timeout={:?}", id, timeout);
                Cookie::build(KBS_SESSION_ID, id.clone())
                    .expires(*timeout)
                    .finish()
            }
            SessionStatus::Attested { id, timeout, .. } => {
                debug!("Attested session cookie: id={}, timeout={:?}", id, timeout);
                Cookie::build(KBS_SESSION_ID, id.clone())
                    .expires(*timeout)
                    .finish()
            }
        }
    }

    impl_member!(request, Request, Authed);
    impl_member!(challenge, Challenge, Authed);
    impl_member!(id, str);
    impl_member!(timeout, OffsetDateTime);

    pub fn is_expired(&self) -> bool {
        let expired = *self.timeout() < OffsetDateTime::now_utc();
        debug!("Session expired check: expired={}", expired);
        expired
    }

    pub fn attest(&mut self, attestation_claims: String, token: String) {
        match self {
            SessionStatus::Authed { id, timeout, .. } => {
                debug!("Attesting session: id={}, claims={}, token={}", id, attestation_claims, token);
                *self = SessionStatus::Attested {
                    attestation_claims,
                    token,
                    id: id.clone(),
                    timeout: *timeout,
                };
            }
            SessionStatus::Attested { .. } => {
                warn!("Session already attested.");
            }
        }
    }
}

pub(crate) struct SessionMap {
    pub sessions: scc::HashMap<String, SessionStatus>,
}

impl SessionMap {
    pub fn new() -> Self {
        debug!("Creating new SessionMap.");
        SessionMap {
            sessions: scc::HashMap::new(),
        }
    }

    pub fn insert(&self, session: SessionStatus) {
        debug!("Inserting session into map: id={}", session.id());
        let _ = self.sessions.insert(session.id().to_string(), session);
    }
}

