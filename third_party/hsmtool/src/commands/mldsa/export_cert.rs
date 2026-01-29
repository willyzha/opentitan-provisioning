// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use const_oid::ObjectIdentifier;
use cryptoki::mechanism::vendor_defined::VendorDefinedMechanism;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::Attribute;
use cryptoki::session::Session;
use der::{Encode, EncodePem}; // removed Decode, as we might not need it if we don't parse back
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
use x509_cert::ext::Extension;

use crate::commands::{BasicResult, Dispatch};
use crate::error::HsmError;
use crate::module::Module;
use crate::util::attribute::{AttributeMap, AttributeType, KeyType, MechanismType, ObjectClass};
use crate::util::helper;

// ML-DSA-87 OID: 2.16.840.1.101.3.4.3.19
const OID_MLDSA_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

#[derive(clap::Args, Debug, Serialize, Deserialize)]
pub struct ExportCert {
    #[arg(long)]
    id: Option<String>,
    #[arg(short, long)]
    label: Option<String>,
    #[arg(long)]
    subject: String,
    #[arg(short, long)]
    output: PathBuf,
    #[arg(long, default_value = "7300")]
    days: u64,
}

impl ExportCert {
    fn run_command(&self, session: &Session) -> Result<()> {
        // Find the private key
        let mut attrs = helper::search_spec(self.id.as_deref(), self.label.as_deref())?;
        attrs.push(Attribute::Class(ObjectClass::PrivateKey.try_into()?));
        attrs.push(Attribute::KeyType(KeyType::MlDsa.try_into()?));
        let private_key = helper::find_one_object(session, &attrs)?;

        // Determine public key label
        let pub_label_string = if let Some(l) = self.label.as_deref() {
            if l.ends_with(".priv") {
                Some(l.replace(".priv", ".pub"))
            } else {
                Some(l.to_string())
            }
        } else {
            None
        };
        let pub_label = pub_label_string.as_deref();

        // Find the public key (needed for Cert)
        let mut pub_attrs = helper::search_spec(self.id.as_deref(), pub_label)?;
        pub_attrs.push(Attribute::Class(ObjectClass::PublicKey.try_into()?));
        pub_attrs.push(Attribute::KeyType(KeyType::MlDsa.try_into()?));
        let public_key = helper::find_one_object(session, &pub_attrs)?;

        // Get public key value
        let map = AttributeMap::from_object(session, public_key)?;
        let val = map
            .get(&AttributeType::Value)
            .ok_or(anyhow!("Public key does not contain a value"))?;
        let pub_key_bytes: Vec<u8> = val.try_into()?;

        // Construct Subject Name
        let subject = Name::from_str(&self.subject).map_err(|e| anyhow!("Invalid subject: {}", e))?;

        // Create AlgorithmIdentifier
        let algorithm = AlgorithmIdentifierOwned {
            oid: OID_MLDSA_87,
            parameters: None,
        };
        let subject_public_key_info = SubjectPublicKeyInfoOwned {
            algorithm: algorithm.clone(),
            subject_public_key: x509_cert::der::asn1::BitString::from_bytes(&pub_key_bytes)
                .map_err(|e| anyhow!("Invalid public key bytes: {}", e))?,
        };

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

        // Key Usage: KeyCertSign, CRLSign, Critical
        // KeyUsage is BitString.
        // KeyCertSign is bit 5 (0x04 in byte 0?), CRLSign is bit 6 (0x02?)
        // x509-cert provides KeyUsages flags.
        // KeyUsage is a BitString wrapper.
        // Let's manually construct the byte. 
        // KeyCertSign = 1 << 5 (32? No, bit 0 is MSB in ASN.1 bitstring usually?)
        // x509_cert::ext::pkix::KeyUsages::KeyCertSign is defined as `KeyUsages::KEY_CERT_SIGN`.
        let key_usage_flags = x509_cert::ext::pkix::KeyUsages::DigitalSignature | x509_cert::ext::pkix::KeyUsages::KeyCertSign | x509_cert::ext::pkix::KeyUsages::CRLSign;
        // KeyUsage::new() does not exist?
        // KeyUsage is a tuple struct wrapping BitString.
        // x509-cert 0.2.5 KeyUsage implements From<KeyUsages>.
        let key_usage = KeyUsage::from(key_usage_flags);
        
        extensions.push(Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_KEY_USAGE,
            critical: true,
            extn_value: x509_cert::der::asn1::OctetString::new(key_usage.to_der()?)?,
        });

        // Subject Key Identifier: SHA-1 hash of public key BIT STRING value
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(&pub_key_bytes);
        let ski_bytes = hasher.finalize();
        let ski = SubjectKeyIdentifier(x509_cert::der::asn1::OctetString::new(ski_bytes.as_slice())?);
        extensions.push(Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER,
            critical: false,
            extn_value: x509_cert::der::asn1::OctetString::new(ski.to_der()?)?,
        });

        let tbs_cert = TbsCertificate {
            version: Version::V3,
            serial_number,
            signature: algorithm.clone(),
            issuer: subject.clone(),
            validity,
            subject,
            subject_public_key_info,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        };

        // Serialize TBS to sign
        let tbs_bytes = tbs_cert
            .to_der()
            .map_err(|e| anyhow!("Failed to encode TbsCertificate: {}", e))?;

        // Sign using HSM
        // Using VendorDefinedMechanism for MLDSA signature generation
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
            signature_algorithm: algorithm,
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

#[typetag::serde(name = "mldsa-export-cert")]
impl Dispatch for ExportCert {
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
