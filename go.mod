// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
module github.com/lowRISC/opentitan-provisioning

go 1.19

replace github.com/lowRISC/opentitan-provisioning => ./

// This file is used to manage dependencies for the OpenTitan Provisioning
// project. It is used by the Go toolchain to fetch dependencies and their
// transitive dependencies.
//
// To update the dependencies, run `bazel run //:update-go-repos`.
//
// This project does not support the `go mod tidy` command.
require (

	// OpenTitan Provisioning core dependencies.
	github.com/golang/protobuf v1.5.2
	github.com/google/go-cmp v0.5.6
	github.com/google/tink/go v1.6.1
	github.com/jinzhu/inflection v1.0.0
	github.com/jinzhu/now v1.1.5

	// Required by gorm.
	github.com/mattn/go-sqlite3 v1.14.22
	github.com/miekg/pkcs11 v1.0.3
	golang.org/x/crypto v0.23.0
	golang.org/x/sync v0.3.0
	golang.org/x/sys v0.20.0
	// Required by Bazel golang infrastructure.
	golang.org/x/tools v0.10.0
	google.golang.org/api v0.32.0

	// Required by google.golang.org/grpc
	google.golang.org/genproto v0.0.0-20210602131652-f16073e35f0c
	google.golang.org/grpc v1.41.0
	gorm.io/driver/sqlite v1.5.7

	// Proxy buffer backends.
	gorm.io/gorm v1.25.12
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/glebarez/go-sqlite v1.21.2 // indirect
	github.com/glebarez/sqlite v1.11.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/text v0.15.0 // indirect
	modernc.org/libc v1.22.5 // indirect
	modernc.org/mathutil v1.5.0 // indirect
	modernc.org/memory v1.5.0 // indirect
	modernc.org/sqlite v1.23.1 // indirect
)
