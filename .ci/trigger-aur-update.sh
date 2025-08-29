#!/bin/bash
set -e

VERSION=$1

if [ -z "$VERSION" ]; then
    echo "Error: Version not provided"
    exit 1
fi

echo "Triggering AUR repository update for version ${VERSION}"

# Trigger workflow in the AUR repo using GitHub API
curl -X POST \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer ${AUR_REPO_TOKEN}" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/theesfed/libgpg-stream-aur/dispatches \
  -d "{\"event_type\":\"update-version\",\"client_payload\":{\"version\":\"${VERSION}\"}}"

echo "AUR update triggered successfully"
