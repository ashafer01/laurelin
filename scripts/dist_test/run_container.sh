#!/bin/bash
# This builds a quick container for doing manual validation that distribution
# packages are being built as expected.

cd "$(git rev-parse --show-toplevel)"

tag="laurelin-dist-test-$$"
name="container-$tag"

set -e

./scripts/build.sh --force

docker build -f ./scripts/dist_test/Dockerfile -t "$tag" .
docker run --name "$name" -it "$tag"

docker rm "$name"
docker rmi "$tag"
