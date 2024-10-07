use std::{net::SocketAddr, path::Path, sync::Arc};

use actix_web::{web, App, HttpServer};
use anyhow::{Result, Context};
use attestation_service::{config::Config, config::ConfigError, AttestationService, ServiceError};
use clap::{arg, command, Parser};
use log::{info, debug, error};
use openssl::{
    pkey::PKey,
    ssl::{SslAcceptor, SslMethod},
};
use strum::{AsRefStr, EnumString};
use thiserror::Error;
use tokio::sync::RwLock;

use crate::restful::{attestation, get_challenge, get_policies, set_policy};

mod restful;

/// RESTful-AS command-line arguments.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to a CoCo-AS config file.
    #[arg(short, long)]
    pub config_file: Option<String>,

    /// Socket addresses (IP:port) to listen on, e.g. 127.0.0.1:8080.
    #[arg(short, long)]
    pub socket: SocketAddr,

    /// Path to the public key cert for HTTPS. Both public key cert and
    /// private key are provided then HTTPS will be enabled.
    #[arg(short, long)]
    pub https_pubkey_cert: Option<String>,

    /// Path to the private key for HTTPS. Both public key cert and
    /// private key are provided then HTTPS will be enabled.
    #[arg(short, long)]
    pub https_prikey: Option<String>,
}

#[derive(EnumString, AsRefStr)]
#[strum(serialize_all = "lowercase")]
enum WebApi {
    #[strum(serialize = "/attestation")]
    Attestation,

    #[strum(serialize = "/policy")]
    Policy,

    #[strum(serialize = "/challenge")]
    Challenge,
}

#[derive(Error, Debug)]
pub enum RestfulError {
    #[error("Creating service failed: {0}")]
    Service(#[from] ServiceError),
    #[error("Failed to read AS config file: {0}")]
    Config(#[from] ConfigError),
    #[error("Openssl errorstack: {0}")]
    Openssl(#[from] openssl::error::ErrorStack),
    #[error("failed to read HTTPS private key: {0}")]
    ReadHttpsKey(#[source] std::io::Error),
    #[error("failed to get HTTPS private key from pem: {0}")]
    ReadHttpsKeyFromPem(#[source] openssl::error::ErrorStack),
    #[error("set private key failed: {0}")]
    SetPrivateKey(#[source] openssl::error::ErrorStack),
    #[error("set HTTPS public key cert: {0}")]
    SetHttpsCert(#[source] openssl::error::ErrorStack),
    #[error("io error: {0}")]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

#[actix_web::main]
async fn main() -> Result<(), RestfulError> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    debug!("Initializing application...");

    let cli = Cli::parse();
    debug!("Parsed CLI arguments: {:?}", cli);

    let config = match cli.config_file {
        Some(path) => {
            info!("Using config file: {}", path);
            debug!("Attempting to load configuration from path: {}", path);
            Config::try_from(Path::new(&path)).context("Failed to load config from file")?
        }
        None => {
            info!("No config file path provided, using default configuration.");
            Config::default()
        }
    };

    debug!("Loaded configuration: {:?}", config);

    debug!("Initializing AttestationService...");
    let attestation_service = AttestationService::new(config).await?;
    debug!("Initialized AttestationService: {:?}", attestation_service);

    let attestation_service = web::Data::new(Arc::new(RwLock::new(attestation_service)));
    debug!("Wrapped AttestationService in Arc and RwLock.");

    let server = HttpServer::new(move || {
        debug!("Creating new App instance...");
        App::new()
            .service(web::resource(WebApi::Attestation.as_ref()).route(web::post().to(attestation)))
            .service(
                web::resource(WebApi::Policy.as_ref())
                    .route(web::post().to(set_policy))
                    .route(web::get().to(get_policies)),
            )
            .service(web::resource(WebApi::Challenge.as_ref()).route(web::post().to(get_challenge)))
            .app_data(web::Data::clone(&attestation_service))
    });

    debug!("Checking for HTTPS configuration...");
    let server = match (cli.https_prikey.clone(), cli.https_pubkey_cert.clone()) {
        (Some(prikey), Some(pubkey_cert)) => {
            debug!("Configuring HTTPS with public key cert: {} and private key: {}", pubkey_cert, prikey);
            let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls())?;
            debug!("Initialized SslAcceptor for HTTPS.");

            let prikey = tokio::fs::read(&prikey)
                .await
                .map_err(RestfulError::ReadHttpsKey)?;
            debug!("Successfully read HTTPS private key from: {}", prikey);

            let prikey =
                PKey::private_key_from_pem(&prikey).map_err(RestfulError::ReadHttpsKeyFromPem)?;
            debug!("Parsed private key from PEM format.");

            builder
                .set_private_key(&prikey)
                .map_err(RestfulError::SetPrivateKey)?;
            debug!("Set private key for HTTPS.");

            builder
                .set_certificate_chain_file(pubkey_cert)
                .map_err(RestfulError::SetHttpsCert)?;
            debug!("Set certificate chain file for HTTPS.");

            info!("Starting HTTPS server at https://{}", cli.socket);
            server.bind_openssl(cli.socket, builder)?.run()
        }
        _ => {
            info!("Starting HTTP server at http://{}", cli.socket);
            server
                .bind((cli.socket.ip().to_string(), cli.socket.port()))?
                .run()
        }
    };

    debug!("Awaiting server to run...");
    server.await.map_err(|e| {
        error!("Server error: {:?}", e);
        RestfulError::Anyhow(e.into())
    })?;

    debug!("Server has stopped.");
    Ok(())
}

