#!/bin/bash
# Copyright (c) Aptos
# SPDX-License-Identifier: Apache-2.0

# This script docker bake to build all the rust-based docker images
# You need to execute this from the repository root as working directory
# E.g. docker/docker-bake-rust-all.sh 

set -e

GIT_REV=$(git rev-parse --short=8 HEAD) BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" docker buildx bake --progress=plain --push --file docker/docker-bake-rust-all.hcl all
