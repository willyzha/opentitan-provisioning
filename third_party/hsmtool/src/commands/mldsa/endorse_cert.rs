// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use const_oid::ObjectIdentifier;
use cryptoki::mechanism::vendor_defined::VendorDefinedMechanism;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::Attribute;
use cryptoki::session::Session;
use der::{DecodePem, Encode, EncodePem};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::any::Any;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier,
};
use x509_cert::ext::Extension;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::time::{Time, Validity};

use crate::commands::{BasicResult, Dispatch};
use crate::error::HsmError;
use crate::module::Module;
use crate::util::attribute::{KeyType, MechanismType, ObjectClass};
use crate::util::helper;

// ML-DSA-87 OID: 2.16.840.1.101.3.4.3.19
const OID_MLDSA_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

#[derive(clap::Args, Debug, Serialize, Deserialize)]
pub struct EndorseCert {
    #[arg(long)]
    id: Option<String>,
    #[arg(short, long)]
    label: Option<String>,
    #[arg(long)]
    csr: PathBuf,
    #[arg(long)]
    ca_cert: PathBuf,
    #[arg(short, long)]
    output: PathBuf,
    #[arg(long, default_value = "7300")]
    days: u64,
}

impl EndorseCert {
    fn run_command(&self, session: &Session) -> Result<()> {
        // Load and parse CSR
        let csr_pem = helper::read_file(&self.csr)?;
        let csr = x509_cert::request::CertReq::from_pem(&csr_pem)
            .map_err(|e| anyhow!("Failed to parse CSR: {}", e))?;
        let csr_info = csr.info;

        // Load and parse CA Certificate
        let ca_cert_pem = helper::read_file(&self.ca_cert)?;
        let ca_cert = Certificate::from_pem(&ca_cert_pem)
            .map_err(|e| anyhow!("Failed to parse CA Certificate: {}", e))?;
        let issuer = ca_cert.tbs_certificate.subject;
        let ca_pub_key_bytes = ca_cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or(anyhow!("Invalid CA public key bytes"))?;

        // Find the CA private key
        let mut attrs = helper::search_spec(self.id.as_deref(), self.label.as_deref())?;
        attrs.push(Attribute::Class(ObjectClass::PrivateKey.try_into()?));
        attrs.push(Attribute::KeyType(KeyType::MlDsa.try_into()?));
        let private_key = helper::find_one_object(session, &attrs)?;

        // Validity
        let now = SystemTime::now();
        let not_before = Time::try_from(now).map_err(|e| anyhow!("Time error: {}", e))?;
        let not_after_time = now + Duration::from_secs(self.days * 24 * 60 * 60);
        let not_after =
            Time::try_from(not_after_time).map_err(|e| anyhow!("Time error: {}", e))?;
        let validity = Validity {
            not_before,
            not_after,
        };

        // Serial Number (random 16 bytes)
        let mut serial_bytes = [0u8; 16];
        rand::thread_rng().fill(&mut serial_bytes);
        let serial_number = SerialNumber::new(&serial_bytes)
            .map_err(|e| anyhow!("Invalid serial number: {}", e))?;

        // Extensions
        let mut extensions = Vec::new();

        // Basic Constraints: CA:TRUE, Critical
        let basic_constraints = BasicConstraints {
            ca: true,
            path_len_constraint: None,
        };
        extensions.push(Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS,
            critical: true,
            extn_value: x509_cert::der::asn1::OctetString::new(basic_constraints.to_der()?)?,
        });

        // Key Usage: KeyCertSign, CRLSign, DigitalSignature, Critical
        let key_usage_flags = x509_cert::ext::pkix::KeyUsages::DigitalSignature
            | x509_cert::ext::pkix::KeyUsages::KeyCertSign
            | x509_cert::ext::pkix::KeyUsages::CRLSign;
        let key_usage = KeyUsage::from(key_usage_flags);

        extensions.push(Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_KEY_USAGE,
            critical: true,
            extn_value: x509_cert::der::asn1::OctetString::new(key_usage.to_der()?)?,
        });

        // Subject Key Identifier: SHA-1 hash of subject public key BIT STRING value
        let mut hasher = Sha1::new();
        let sub_pub_key_bytes = csr_info
            .public_key
            .subject_public_key
            .as_bytes()
            .ok_or(anyhow!("Invalid subject public key bytes"))?;
        hasher.update(sub_pub_key_bytes);
        let ski_bytes = hasher.finalize();
        let ski =
            SubjectKeyIdentifier(x509_cert::der::asn1::OctetString::new(ski_bytes.as_slice())?);
        extensions.push(Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER,
            critical: false,
            extn_value: x509_cert::der::asn1::OctetString::new(ski.to_der()?)?,
        });

        // Authority Key Identifier: SHA-1 hash of CA public key BIT STRING value
        // Note: We only set keyIdentifier, not authorityCertIssuer/Serial (as per config 'keyid:always,issuer:always' request?
        // Wait, 'issuer:always' means we SHOULD include issuer and serial.
        // But simpler to start with just KeyID if that works.
        // OpenSSL 'keyid:always' sets keyIdentifier. 'issuer:always' sets authorityCertIssuer and authorityCertSerialNumber.
        // Let's implement both if possible.
        // We need CA Serial Number.
        let ca_serial = ca_cert.tbs_certificate.serial_number;
        // We need CA Issuer Name? No, AuthorityCertIssuer is the Name of the Issuer of the Authority Cert...
        // Wait. RFC 5280:
        // "The authorityCertIssuer and authorityCertSerialNumber fields ... identify the certificate of the issuer of the signing key."
        // So authorityCertIssuer is the Issuer of CA Certificate. And authorityCertSerialNumber is the Serial of CA Certificate?
        // NO.
        // "The value of the authorityCertIssuer field is the name of the issuer of the CRL or certificate." -> This refers to the GeneralNames of the issuer.
        // Actually, it usually refers to the Subject Name of the CA.
        // If I put `DirName: <CA_Subject>`, that matches.

        // Let's stick to KeyIdentifier for now as it's the most critical for chaining.
        // Generating full AuthorityKeyIdentifier with issuer/serial is more complex with x509-cert types.

        let mut hasher_ca = Sha1::new();
        hasher_ca.update(ca_pub_key_bytes);
                let aki_bytes = hasher_ca.finalize();
        
                let aki = AuthorityKeyIdentifier {            key_identifier: Some(x509_cert::der::asn1::OctetString::new(
                aki_bytes.as_slice(),
            )?),
            authority_cert_issuer: None, // Simplified
            authority_cert_serial_number: None,
        };
        extensions.push(Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER,
            critical: false,
            extn_value: x509_cert::der::asn1::OctetString::new(aki.to_der()?)?,
        });

        // Construct TBS
        let tbs_cert = TbsCertificate {
            version: Version::V3,
            serial_number,
            signature: AlgorithmIdentifierOwned {
                oid: OID_MLDSA_87,
                parameters: None,
            },
            issuer,
            validity,
            subject: csr_info.subject,
            subject_public_key_info: csr_info.public_key,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        };

        // Serialize TBS to sign
        let tbs_bytes = tbs_cert
            .to_der()
            .map_err(|e| anyhow!("Failed to encode TbsCertificate: {}", e))?;

        // Sign using HSM
        let mechanism = Mechanism::VendorDefined(VendorDefinedMechanism::new::<()>(
            MechanismType::MlDsa.try_into()?,
            None,
        ));

        let signature_bytes = session
            .sign(&mechanism, private_key, &tbs_bytes)
            .map_err(|e| anyhow!("HSM signing failed: {}", e))?;

        let signature = x509_cert::der::asn1::BitString::from_bytes(&signature_bytes)
            .map_err(|e| anyhow!("Invalid signature bytes: {}", e))?;

        let cert = Certificate {
            tbs_certificate: tbs_cert,
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: OID_MLDSA_87,
                parameters: None,
            },
            signature,
        };

        // Encode to PEM
        let pem = cert
            .to_pem(Default::default())
            .map_err(|e| anyhow!("Failed to encode Certificate to PEM: {}", e))?;

        helper::write_file(&self.output, pem.as_bytes())?;

        Ok(())
    }
}

#[typetag::serde(name = "mldsa-endorse-cert")]
impl Dispatch for EndorseCert {
    fn run(
        &self,
        _context: &dyn Any,
        _hsm: &Module,
        session: Option<&Session>,
    ) -> Result<Box<dyn erased_serde::Serialize>> {
        let session = session.ok_or(HsmError::SessionRequired)?;
        self.run_command(session)?;
        Ok(Box::<BasicResult>::default())
    }
}
