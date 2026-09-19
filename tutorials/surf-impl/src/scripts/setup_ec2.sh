#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update

mkdir 2pc/key-derivation

mkdir build/

# Core build tools
sudo apt-get install -y \
  build-essential \
  cmake \
  ninja-build \
  git \
  perl

# Go (required by BoringSSL for code generation)
sudo apt-get install -y golang-go

# OpenSSL dev headers (required by emp-tool and main project)
sudo apt-get install -y libssl-dev

# Benchmark-only dependencies (only needed with -DBENCHMARKING=ON)
sudo apt-get install -y \
  libgumbo-dev \
  libnghttp2-dev

# Initialize Google Benchmark submodule
git -C "$(dirname "$0")" submodule update --init benchmark

# Configure and build (with benchmarking enabled)
cd build
cmake ../ -DBENCHMARKING=ON
make

# Generate Bristol Format circuits
./DeriveCircuits

# Install generated Bristol Format circuits
cp *.txt ../2pc/key-derivation/
