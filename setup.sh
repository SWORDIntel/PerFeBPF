#!/bin/bash

# Exit on any error
set -e

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

# 1. Install dependencies
echo "Installing dependencies..."
apt-get update
apt-get install -y clang libbpf-dev golang-go

# 2. Generate Go BPF wrapper
echo "Generating Go BPF wrapper..."
/home/john/go/bin/bpf2go bpf -output-stem bpf_out -type bpfEvent -go-package main bpf_monitor.c -- -D__TARGET_ARCH_x86 -I/usr/include

# 4. Build Go application
echo "Building Go application..."
go build -o oom_protector main.go

# 5. Install application
echo "Installing application..."
mkdir -p /etc/oom_protector
cp config.yaml /etc/oom_protector/config.yaml
cp oom_protector /usr/local/bin/
cp oom_protector.service /etc/systemd/system/

# 6. Setup and start service
echo "Setting up and starting service..."
systemctl daemon-reload
systemctl enable oom_protector.service
systemctl start oom_protector.service

echo "Setup complete. The oom_protector service is now running."
