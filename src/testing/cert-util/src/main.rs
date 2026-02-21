// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use clap::{Args, Parser, Subcommand};
use der::{Decode, DecodePem, Encode, EncodePem};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier,
};
use x509_cert::ext::Extension;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a TBS (To-Be-Signed) certificate from a CSR.
    Tbs(TbsArgs),
    /// Assemble a final certificate from TBS and a signature.
    Assemble(AssembleArgs),
}

#[derive(Args)]
struct TbsArgs {
    /// Path to the CSR.
    #[arg(long)]
    csr: PathBuf,
    /// Path to the CA certificate (issuer). If omitted, generates a self-signed TBS.
    #[arg(long)]
    ca_cert: Option<PathBuf>,
    /// Path to output the TBS DER file.
    #[arg(short, long)]
    output: PathBuf,
    /// Number of days the certificate is valid for. Use -1 for no expiry.
    #[arg(long, default_value = "7300")]
    days: i64,
}

#[derive(Args)]
struct AssembleArgs {
    /// Path to the TBS DER file.
    #[arg(long)]
    tbs: PathBuf,
    /// Path to the signature file (raw bytes).
    #[arg(long)]
    signature: PathBuf,
    /// Path to output the final PEM certificate.
    #[arg(short, long)]
    output: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Tbs(args) => generate_tbs(args),
        Commands::Assemble(args) => assemble_cert(args),
    }
}

fn generate_tbs(args: TbsArgs) -> Result<()> {
    let csr_pem = fs::read(&args.csr)?;
    let csr = x509_cert::request::CertReq::from_pem(&csr_pem)
        .map_err(|e| anyhow!("Failed to parse CSR: {}", e))?;

    let (issuer, aki_bytes) = if let Some(ca_cert_path) = &args.ca_cert {
        let ca_cert_pem = fs::read(ca_cert_path)?;
        let ca_cert = Certificate::from_pem(&ca_cert_pem)
            .map_err(|e| anyhow!("Failed to parse CA Certificate: {}", e))?;

        let issuer = ca_cert.tbs_certificate.subject.clone();

        let ca_pub_key_bytes = ca_cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or(anyhow!("Invalid CA public key bytes"))?;

        let mut hasher_ca = Sha256::new();
        hasher_ca.update(ca_pub_key_bytes);
        let aki = hasher_ca.finalize()[0..20].to_vec();
        (issuer, Some(aki))
    } else {
        // Self-signed root CA
        (csr.info.subject.clone(), None)
    };

    let subject = csr.info.subject.clone();
    let subject_public_key_info = csr.info.public_key.clone();

    let sub_pub_key_bytes = subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(anyhow!("Invalid subject public key bytes"))?
        .to_vec();

    // Validity
    let now = SystemTime::now();
    let not_before = Time::try_from(now).map_err(|e| anyhow!("Time error: {}", e))?;

    let not_after = if args.days == -1 {
        let no_expiry = der::asn1::GeneralizedTime::from_date_time(
            der::DateTime::new(9999, 12, 31, 23, 59, 59)
                .map_err(|e| anyhow!("DateTime error: {}", e))?,
        );
        Time::GeneralTime(no_expiry)
    } else {
        let days_u64 = u64::try_from(args.days)
            .map_err(|_| anyhow!("Invalid number of days: {}", args.days))?;
        let not_after_time = now + Duration::from_secs(days_u64 * 24 * 60 * 60);
        Time::try_from(not_after_time).map_err(|e| anyhow!("Time error: {}", e))?
    };

    let validity = Validity {
        not_before,
        not_after,
    };

    // Serial Number
    let mut serial_bytes = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut serial_bytes);
    serial_bytes[0] &= 0x7f; // Ensure positive
    let serial_number = SerialNumber::new(&serial_bytes)
        .map_err(|e| anyhow!("Invalid serial number: {}", e))?;

    // Extensions
    let mut extensions = Vec::new();

    // Basic Constraints
    let basic_constraints = BasicConstraints {
        ca: true,
        path_len_constraint: None,
    };
    extensions.push(Extension {
        extn_id: const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS,
        critical: true,
        extn_value: der::asn1::OctetString::new(basic_constraints.to_der()?)?,
    });

    // Key Usage
    let key_usage = KeyUsage(
        x509_cert::ext::pkix::KeyUsages::KeyCertSign | x509_cert::ext::pkix::KeyUsages::CRLSign,
    );
    extensions.push(Extension {
        extn_id: const_oid::db::rfc5280::ID_CE_KEY_USAGE,
        critical: true,
        extn_value: der::asn1::OctetString::new(key_usage.to_der()?)?,
    });

    // Subject Key Identifier
    let mut hasher_sub = Sha256::new();
    hasher_sub.update(&sub_pub_key_bytes);
    let ski = SubjectKeyIdentifier(der::asn1::OctetString::new(hasher_sub.finalize()[0..20].to_vec())?);
    extensions.push(Extension {
        extn_id: const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER,
        critical: false,
        extn_value: der::asn1::OctetString::new(ski.to_der()?)?,
    });

    // Authority Key Identifier
    if let Some(aki_bytes) = aki_bytes {
        let aki = AuthorityKeyIdentifier {
            key_identifier: Some(der::asn1::OctetString::new(aki_bytes)?),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        };
        extensions.push(Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER,
            critical: false,
            extn_value: der::asn1::OctetString::new(aki.to_der()?)?,
        });
    }

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number,
        signature: csr.algorithm.clone(),
        issuer,
        validity,
        subject,
        subject_public_key_info,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };

    fs::write(&args.output, tbs.to_der()?)?;
    Ok(())
}

fn assemble_cert(args: AssembleArgs) -> Result<()> {
    let tbs_der = fs::read(&args.tbs)?;
    let tbs = TbsCertificate::from_der(&tbs_der)?;
    
    let signature_bytes = fs::read(&args.signature)?;

    let cert = Certificate {
        tbs_certificate: tbs.clone(),
        signature_algorithm: tbs.signature.clone(),
        signature: der::asn1::BitString::from_bytes(&signature_bytes)?,
    };

    fs::write(&args.output, cert.to_pem(der::pem::LineEnding::LF)?)?;
    Ok(())
}
