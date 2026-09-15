// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"hash"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/testing/protocmp"

	rrpb "github.com/lowRISC/opentitan-provisioning/src/proto/registry_record_go_pb"
	pbp "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/proto/proxy_buffer_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/services/httpregistry"
)

func createSignedRecord(t *testing.T, curve elliptic.Curve, deviceID string, data []byte) *rrpb.RegistryRecord {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	var hasher hash.Hash
	switch curve {
	case elliptic.P256():
		hasher = crypto.SHA256.New()
	case elliptic.P384():
		hasher = crypto.SHA384.New()
	case elliptic.P521():
		hasher = crypto.SHA512.New()
	default:
		t.Fatalf("unsupported curve in test helper: %v", curve)
	}
	hasher.Write(data)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, hasher.Sum(nil))
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}

	return &rrpb.RegistryRecord{
		DeviceId:      deviceID,
		Sku:           "sival",
		Version:       0,
		Data:          data,
		AuthPubkey:    pubBytes,
		AuthSignature: sig,
	}
}

func TestVerifyRecordSignature(t *testing.T) {
	validP256 := createSignedRecord(t, elliptic.P256(), "device-p256", []byte("test-device-data-p256"))
	validP384 := createSignedRecord(t, elliptic.P384(), "device-p384", []byte("test-device-data-p384"))
	unsupportedP521 := createSignedRecord(t, elliptic.P521(), "device-p521", []byte("test-device-data-p521"))

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	rsaPubBytes, err := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA public key: %v", err)
	}

	tamperedData := createSignedRecord(t, elliptic.P256(), "device-tampered", []byte("original-data"))
	tamperedData.Data = []byte("modified-data")

	wrongKeyRecord := createSignedRecord(t, elliptic.P256(), "device-wrong-key", []byte("some-data"))
	otherKeyRecord := createSignedRecord(t, elliptic.P256(), "device-other-key", []byte("other-data"))
	wrongKeyRecord.AuthPubkey = otherKeyRecord.AuthPubkey

	tcs := []struct {
		name      string
		record    *rrpb.RegistryRecord
		wantError bool
	}{
		{
			name:      "ValidP256",
			record:    validP256,
			wantError: false,
		},
		{
			name:      "ValidP384",
			record:    validP384,
			wantError: false,
		},
		{
			name:      "NilRecord",
			record:    nil,
			wantError: true,
		},
		{
			name: "EmptyData",
			record: &rrpb.RegistryRecord{
				DeviceId:      "dev1",
				AuthPubkey:    validP256.AuthPubkey,
				AuthSignature: validP256.AuthSignature,
			},
			wantError: true,
		},
		{
			name: "EmptyAuthPubkey",
			record: &rrpb.RegistryRecord{
				DeviceId:      "dev1",
				Data:          validP256.Data,
				AuthSignature: validP256.AuthSignature,
			},
			wantError: true,
		},
		{
			name: "EmptyAuthSignature",
			record: &rrpb.RegistryRecord{
				DeviceId:   "dev1",
				Data:       validP256.Data,
				AuthPubkey: validP256.AuthPubkey,
			},
			wantError: true,
		},
		{
			name: "MalformedAuthPubkey",
			record: &rrpb.RegistryRecord{
				DeviceId:      "dev1",
				Data:          validP256.Data,
				AuthPubkey:    []byte("not-der-encoded-pubkey"),
				AuthSignature: validP256.AuthSignature,
			},
			wantError: true,
		},
		{
			name: "NonECDSAPubkey",
			record: &rrpb.RegistryRecord{
				DeviceId:      "dev1",
				Data:          validP256.Data,
				AuthPubkey:    rsaPubBytes,
				AuthSignature: validP256.AuthSignature,
			},
			wantError: true,
		},
		{
			name:      "UnsupportedCurveP521",
			record:    unsupportedP521,
			wantError: true,
		},
		{
			name:      "TamperedData",
			record:    tamperedData,
			wantError: true,
		},
		{
			name:      "WrongPublicKey",
			record:    wrongKeyRecord,
			wantError: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyRecordSignature(tc.record)
			if (err != nil) != tc.wantError {
				t.Errorf("verifyRecordSignature() error = %v, wantError = %v", err, tc.wantError)
			}
		})
	}
}

func TestFakeRegistryHTTPHandlers(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/registerDevice", registerDevice)
	mux.HandleFunc("/batchRegisterDevice", batchRegisterDevice)
	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := httpregistry.New(&httpregistry.RegistryConfig{
		RegisterDeviceURL:      server.URL + "/registerDevice",
		BatchRegisterDeviceURL: server.URL + "/batchRegisterDevice",
	})
	if err != nil {
		t.Fatalf("failed to create httpregistry client: %v", err)
	}

	validRecord := createSignedRecord(t, elliptic.P256(), "device-ok", []byte("valid-payload"))
	invalidRecord := createSignedRecord(t, elliptic.P256(), "device-bad", []byte("original-payload"))
	invalidRecord.Data = []byte("tampered-payload")

	t.Run("RegisterDevice_Success", func(t *testing.T) {
		resp, err := client.RegisterDevice(context.Background(), &pbp.DeviceRegistrationRequest{
			Record: validRecord,
		})
		if err != nil {
			t.Fatalf("RegisterDevice() unexpected error: %v", err)
		}
		want := &pbp.DeviceRegistrationResponse{
			DeviceId:  "device-ok",
			Status:    pbp.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_SUCCESS,
			RpcStatus: uint32(codes.OK),
		}
		if diff := cmp.Diff(want, resp, protocmp.Transform()); diff != "" {
			t.Errorf("RegisterDevice() diff (-want +got):\n%s", diff)
		}
	})

	t.Run("RegisterDevice_InvalidSignature", func(t *testing.T) {
		resp, err := client.RegisterDevice(context.Background(), &pbp.DeviceRegistrationRequest{
			Record: invalidRecord,
		})
		if err != nil {
			t.Fatalf("RegisterDevice() unexpected error: %v", err)
		}
		want := &pbp.DeviceRegistrationResponse{
			DeviceId:  "device-bad",
			Status:    pbp.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_BAD_REQUEST,
			RpcStatus: uint32(codes.InvalidArgument),
		}
		if diff := cmp.Diff(want, resp, protocmp.Transform()); diff != "" {
			t.Errorf("RegisterDevice() diff (-want +got):\n%s", diff)
		}
	})

	t.Run("BatchRegisterDevice_Mixed", func(t *testing.T) {
		resp, err := client.BatchRegisterDevice(context.Background(), &pbp.BatchDeviceRegistrationRequest{
			Requests: []*pbp.DeviceRegistrationRequest{
				{Record: validRecord},
				{Record: invalidRecord},
			},
		})
		if err != nil {
			t.Fatalf("BatchRegisterDevice() unexpected error: %v", err)
		}
		want := &pbp.BatchDeviceRegistrationResponse{
			Responses: []*pbp.DeviceRegistrationResponse{
				{
					DeviceId:  "device-ok",
					Status:    pbp.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_SUCCESS,
					RpcStatus: uint32(codes.OK),
				},
				{
					DeviceId:  "device-bad",
					Status:    pbp.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_BAD_REQUEST,
					RpcStatus: uint32(codes.InvalidArgument),
				},
			},
		}
		if diff := cmp.Diff(want, resp, protocmp.Transform()); diff != "" {
			t.Errorf("BatchRegisterDevice() diff (-want +got):\n%s", diff)
		}
	})
}
