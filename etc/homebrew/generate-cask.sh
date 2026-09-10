#!/usr/bin/env bash

set -euo pipefail

# Expect the release version, GoReleaser's checksum manifest, and the cask destination.
if (( $# != 3 )); then
  printf 'usage: %s VERSION CHECKSUMS_FILE OUTPUT_FILE\n' "$0" >&2
  exit 2
fi

version="$1"
checksums_file="$2"
output_file="$3"

# These names match the macOS archives uploaded to the GitHub Release.
amd64_archive="super-trouper-${version}-darwin-amd64.tar.xz"
arm64_archive="super-trouper-${version}-darwin-arm64.tar.xz"
amd64_checksum=""
arm64_checksum=""

# Select the two archive hashes from the published checksum manifest.
while read -r checksum filename; do
  # Some checksum formats prefix binary-mode filenames with an asterisk.
  filename="${filename#\*}"
  case "${filename}" in
    "${amd64_archive}") amd64_checksum="${checksum}" ;;
    "${arm64_archive}") arm64_checksum="${checksum}" ;;
  esac
done < "${checksums_file}"

# Do not publish a cask that lacks either architecture's checksum.
test -n "${amd64_checksum}"
test -n "${arm64_checksum}"

# Write the cask into the tap's Casks directory.
mkdir -p "$(dirname "${output_file}")"
cat > "${output_file}" <<EOF
cask "super-trouper" do
  version "${version}"

  on_arm do
    sha256 "${arm64_checksum}"
    url "https://github.com/crissyfield/super-trouper/releases/download/v#{version}/super-trouper-#{version}-darwin-arm64.tar.xz"
  end

  on_intel do
    sha256 "${amd64_checksum}"
    url "https://github.com/crissyfield/super-trouper/releases/download/v#{version}/super-trouper-#{version}-darwin-amd64.tar.xz"
  end

  name "super-trouper"
  desc "Frida reverse-engineering MCP server"
  homepage "https://github.com/crissyfield/super-trouper"

  depends_on macos: :ventura
  binary "super-trouper"

  # Remove the download quarantine until release binaries are signed and notarized.
  postflight_steps do
    run "xattr", args: ["-dr", "com.apple.quarantine", "{{staged_path}}/super-trouper"]
  end
end
EOF
