#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# Builds the Wine base image used to simulate a Windows ATE machine.
#
# The tests build this automatically when it is missing, so this script is only
# needed to refresh the image (e.g. to pick up a newer Wine) or to publish it.
#
# TODO: publish to us-docker.pkg.dev and pull it by digest from
# `third_party/docker/extensions.bzl`, as is done for the SoftHSM2 image, so
# that CI does not rebuild it from Debian packages.

set -e

if ! command -v podman &> /dev/null
then
    echo "podman could not be found."
    echo "Please install via 'sudo apt install podman'"
    exit 1
fi

podman build -t us-docker.pkg.dev/opentitan/opentitan-public/ot-prov-ate-client \
  -f util/containers/ate_client/Dockerfile util/containers/ate_client
