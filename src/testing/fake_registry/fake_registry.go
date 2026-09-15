// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package main is fake HTTP registry server. See README.md for more details.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"

	rrpb "github.com/lowRISC/opentitan-provisioning/src/proto/registry_record_go_pb"
	pbp "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/proto/proxy_buffer_go_pb"

	"google.golang.org/grpc/codes"
)

var (
	port                   = flag.Int("port", 9999, "Port to listen, defaults to 9999")
	registerDeviceURL      = flag.String("register_device_url", "/registerDevice", "URL to listen to RegisterDevice requests. Defaults to '/registerDevice'")
	batchRegisterDeviceURL = flag.String("batchRegister_device_url", "/batchRegisterDevice", "URL to listen to BatchRegisterDevice requests. Defaults to '/batchRegisterDevice'")
)

type callError struct {
	Code    codes.Code `json:"code"`
	Status  string     `json:"status,omitempty"`
	Message string     `json:"message,omitempty"`
}

type registerResponse struct {
	DeviceID string     `json:"deviceId"`
	Error    *callError `json:"error,omitempty"`
}

type batchRegisterResponse struct {
	Responses []*registerResponse `json:"responses"`
}

func handleError(w http.ResponseWriter, errorMessage string) {
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(errorMessage))
}

func verifyRecordSignature(record *rrpb.RegistryRecord) error {
	if record == nil {
		return errors.New("missing registry record")
	}
	if len(record.GetData()) == 0 {
		return errors.New("missing device data")
	}
	if len(record.GetAuthPubkey()) == 0 {
		return errors.New("missing auth_pubkey")
	}
	if len(record.GetAuthSignature()) == 0 {
		return errors.New("missing auth_signature")
	}

	rawPubKey, err := x509.ParsePKIXPublicKey(record.GetAuthPubkey())
	if err != nil {
		return fmt.Errorf("failed to parse auth_pubkey: %w", err)
	}
	pubKey, ok := rawPubKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("auth_pubkey is not an ECDSA public key: %T", rawPubKey)
	}

	var hasher hash.Hash
	switch pubKey.Curve {
	case elliptic.P256():
		hasher = crypto.SHA256.New()
	case elliptic.P384():
		hasher = crypto.SHA384.New()
	default:
		return fmt.Errorf("unsupported elliptic curve: %s", pubKey.Curve.Params().Name)
	}
	hasher.Write(record.GetData())
	if !ecdsa.VerifyASN1(pubKey, hasher.Sum(nil), record.GetAuthSignature()) {
		return errors.New("signature verification failed")
	}
	return nil
}

func registerDevice(w http.ResponseWriter, r *http.Request) {
	reqBytes, err := io.ReadAll(r.Body)
	if err != nil {
		handleError(w, "failed to read request body")
		return
	}
	req := &pbp.DeviceRegistrationRequest{}
	if err := json.Unmarshal(reqBytes, req); err != nil {
		handleError(w, "failed to unmarshal request body")
		return
	}
	resp := &registerResponse{
		DeviceID: req.GetRecord().GetDeviceId(),
	}
	statusCode := http.StatusOK
	if err := verifyRecordSignature(req.GetRecord()); err != nil {
		resp.Error = &callError{
			Code:    codes.InvalidArgument,
			Status:  "INVALID_ARGUMENT",
			Message: err.Error(),
		}
		statusCode = http.StatusBadRequest
	}
	respBytes, err := json.Marshal(resp)
	if err != nil {
		handleError(w, "failed to marshal response body")
		return
	}
	w.WriteHeader(statusCode)
	if _, err := w.Write(respBytes); err != nil {
		log.Printf("failed to write response body: %v", err)
		return
	}
}

func batchRegisterDevice(w http.ResponseWriter, r *http.Request) {
	reqBytes, err := io.ReadAll(r.Body)
	if err != nil {
		handleError(w, "failed to read request body")
		return
	}
	req := &pbp.BatchDeviceRegistrationRequest{}
	if err := json.Unmarshal(reqBytes, req); err != nil {
		handleError(w, "failed to unmarshal request body")
		return
	}
	resp := &batchRegisterResponse{Responses: make([]*registerResponse, 0, len(req.GetRequests()))}
	for _, registerReq := range req.GetRequests() {
		regResp := &registerResponse{
			DeviceID: registerReq.GetRecord().GetDeviceId(),
		}
		if err := verifyRecordSignature(registerReq.GetRecord()); err != nil {
			regResp.Error = &callError{
				Code:    codes.InvalidArgument,
				Status:  "INVALID_ARGUMENT",
				Message: err.Error(),
			}
		}
		resp.Responses = append(resp.Responses, regResp)
	}
	respBytes, err := json.Marshal(resp)
	if err != nil {
		handleError(w, "failed to marshal response body")
		return
	}
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(respBytes); err != nil {
		log.Printf("failed to write response body: %v", err)
		return
	}
}

func main() {
	flag.Parse()
	http.HandleFunc(*registerDeviceURL, registerDevice)
	http.HandleFunc(*batchRegisterDeviceURL, batchRegisterDevice)
	log.Printf("Listening on port %d...", *port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
}
