#!/usr/bin/env bash
# Build the committed HEAD for Linux and upgrade a server with deploy/upgrade.sh
# (rehearsal on a data snapshot, backup, automatic rollback).
#   scripts/deploy-remote.sh user@host [amd64|arm64]
# The host can also come from COMMON_RELAY_DEPLOY_HOST (e.g. in an untracked .local/deploy.env).
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .local/deploy.env ]] && . .local/deploy.env
host=${1:-${COMMON_RELAY_DEPLOY_HOST:-}}; arch=${2:-amd64}
[[ -n $host ]] || { echo "usage: $0 user@host [amd64|arm64]" >&2; exit 2; }
[[ -z $(git status --porcelain) ]] || { echo "working tree is dirty: commit first so the server runs a known revision" >&2; exit 1; }
rev=$(git rev-parse --short HEAD)
out=build/deploy-$rev; mkdir -p "$out"
CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags "-s -w" -o "$out/common-relay" ./cmd/common-relay
sha=$(shasum -a 256 "$out/common-relay" | cut -d' ' -f1)
echo "revision $rev  sha256 $sha"
stage=/tmp/common-relay-stage-$rev
ssh -o BatchMode=yes "$host" "rm -rf $stage && mkdir -m 700 $stage"
scp -q "$out/common-relay" deploy/upgrade.sh "$host:$stage/"
ssh -o BatchMode=yes "$host" "sudo STAGE=$stage EXPECTED_SHA256=$sha bash $stage/upgrade.sh; rc=\$?; rm -rf $stage; exit \$rc"
