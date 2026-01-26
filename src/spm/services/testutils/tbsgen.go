// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package tbsgen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/lowRISC/opentitan-provisioning/src/pk11"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/se"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/skumgr"
)

// computeSKI calculates the Subject Key Identifier for a public key.
func computeSKI(pubKey crypto.PublicKey) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	hash := sha1.Sum(spki)
	return hash[:], nil
}

// patchTBSAlg patches the TBS certificate bytes to replace the ECDSA-SHA256 OID
// with MLDSA-65 OID.
func patchTBSAlg(tbs []byte) ([]byte, error) {
	// ECDSA-SHA256 OID: 1.2.840.10045.4.3.2 -> 06 08 2A 86 48 CE 3D 04 03 02
	// MLDSA-65 OID: 2.16.840.1.101.3.4.3.18 -> 06 0B 60 86 48 01 65 03 04 03 12
	ecdsaOID := []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02}
	mldsaOID := []byte{0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12}

	// Find ECDSA OID
	idx := -1
	for i := 0; i < len(tbs)-len(ecdsaOID); i++ {
		match := true
		for j := 0; j < len(ecdsaOID); j++ {
			if tbs[i+j] != ecdsaOID[j] {
				match = false
				break
			}
		}
		if match {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, fmt.Errorf("ECDSA OID not found in TBS")
	}

	// Reconstruct TBS
	// We expect the OID to be wrapped in a SEQUENCE (AlgorithmIdentifier).
	// ECDSA: 30 0A <OID> (12 bytes)
	// MLDSA: 30 0D <OID> (15 bytes)
	// The sequence header is at idx - 2.
	if tbs[idx-2] != 0x30 || tbs[idx-1] != 0x0A {
		return nil, fmt.Errorf("unexpected AlgorithmIdentifier structure")
	}

	// Create new bytes
	newTBS := make([]byte, 0, len(tbs)+3)
	newTBS = append(newTBS, tbs[:idx-2]...) // Before AlgId
	newTBS = append(newTBS, 0x30, 0x0D)     // New AlgId Header
	newTBS = append(newTBS, mldsaOID...)    // New OID
	newTBS = append(newTBS, tbs[idx+len(ecdsaOID):]...) // Rest

	// Now we must fix the outer SEQUENCE length (TBSCertificate).
	// Assuming it's the first thing.
	if newTBS[0] != 0x30 {
		return nil, fmt.Errorf("TBS is not a SEQUENCE")
	}
	
	// Parse length
	// Standard ASN.1 length encoding handling is complex, but usually for TBS it's > 127 bytes.
	// So 0x30 0x82 0xXX 0xXX.
	// We need to increment the length by 3.
	
	// This simple patching is fragile if length boundaries change (e.g. 255 -> 256).
	// But for test certs it works most of the time.
	// Let's implement generic length patch or re-encode using asn1.RawValue?
	// Re-encoding is safer.
	// But we don't have the struct definition.
	
	// Hack: parse the length, increment, and re-write.
	lengthBytes := 0
	if newTBS[1] < 0x80 {
		// Short form
		newLen := int(newTBS[1]) + 3
		if newLen >= 0x80 {
			// Needs expansion to long form. Complex.
			return nil, fmt.Errorf("length expansion needed, not implemented")
		}
		newTBS[1] = byte(newLen)
	} else {
		// Long form
		numOctets := int(newTBS[1] & 0x7F)
		lengthBytes = numOctets
		if numOctets == 1 {
			length := int(newTBS[2]) + 3
			if length > 255 {
				return nil, fmt.Errorf("length expansion needed (1->2 bytes), not implemented")
			}
			newTBS[2] = byte(length)
		} else if numOctets == 2 {
			length := int(newTBS[2])<<8 | int(newTBS[3])
			length += 3
			newTBS[2] = byte(length >> 8)
			newTBS[3] = byte(length)
		} else {
			return nil, fmt.Errorf("unsupported length octets: %d", numOctets)
		}
	}

	return newTBS, nil
}

// buildTestTbsCert creates a To-Be-Signed (TBS) certificate for testing purposes.
// It takes an intermediate CA certificate. It generates a new key pair for the
// subject, creates a certificate, and returns the TBS part of it.
// The private key of the new certificate is also returned.
func buildTestTbsCert(session *pk11.Session, label string, intermediateCACert *x509.Certificate, alg string) ([]byte, *ecdsa.PrivateKey, error) {
	// Get the private key object.
	keyID, err := se.GetKeyIDByLabel(session, pk11.ClassPrivateKey, label)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get key ID by label %q: %v", label, err)
	}

	key, err := session.FindPrivateKey(keyID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find key object %q: %v", keyID, err)
	}

	privKey, err := key.Signer()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get signer: %v", err)
	}

	// Generate a new public key outside the HSM.
	dutKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate public key: %v", err)
	}
	pubKey := dutKey.PublicKey

	ski, err := computeSKI(&pubKey)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{label + " Test Certificate"},
			CommonName:   label,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(7 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		Issuer:                intermediateCACert.Subject,
		AuthorityKeyId:        intermediateCACert.SubjectKeyId,
		SubjectKeyId:          ski,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, intermediateCACert, &pubKey, privKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	tbs := cert.RawTBSCertificate
	if alg == "mldsa" {
		tbs, err = patchTBSAlg(tbs)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to patch TBS for MLDSA: %w", err)
		}
	}

	return tbs, dutKey, nil
}

// BuildTestTBSCerts generates a set of TBS certificates for a given SKU.
// It returns a map of TBS certificates and a map of the corresponding private keys.
func BuildTestTBSCerts(mgr *skumgr.Manager, skuName string, certLabels []string, alg string) (map[string][]byte, map[string]*ecdsa.PrivateKey, error) {
	sku, err := mgr.LoadSku(skuName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load SKU %q: %w", skuName, err)
	}

	tbsCerts := make(map[string][]byte)
	privKeys := make(map[string]*ecdsa.PrivateKey)
	for _, kl := range certLabels {
		var label string
		if kl == "UDS" {
			label = "SigningKey/Dice/v0"
		} else {
			label = "SigningKey/Ext/v0"
		}
		issuerCert, ok := sku.Certs[label]
		if !ok {
			return nil, nil, fmt.Errorf("issuer certificate %q not found for SKU %q", label, skuName)
		}
		privKeyLabel, err := sku.Config.GetUnsafeAttribute(label)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get private key label for %q: %v", label, err)
		}
		hsm := sku.SeHandle.(*se.HSM)
		if err := hsm.ExecuteCmd(func(session *pk11.Session) error {
			tbs, priv, err := buildTestTbsCert(session, privKeyLabel, issuerCert, alg)
			if err != nil {
				return err
			}
			tbsCerts[kl] = tbs
			privKeys[kl] = priv
			return nil
		}); err != nil {
			return nil, nil, fmt.Errorf("failed to generate TBS certificate: %w", err)
		}
	}

	return tbsCerts, privKeys, nil
}
