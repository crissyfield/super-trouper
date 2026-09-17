#!/usr/bin/env bash

set -euo pipefail

# Parse and validate arguments
if (( $# < 2 )) || (( $# > 3 )); then
  printf 'usage: %s VERSION ASSETS_DIRECTORY [--dry-run]\n' "$0" >&2
  exit 2
fi

version="$1"
assets_dir="$2"
dry_run=false

if (( $# == 3 )); then
  if [[ "$3" != "--dry-run" ]]; then
    printf 'usage: %s VERSION ASSETS_DIRECTORY [--dry-run]\n' "$0" >&2
    exit 2
  fi
  dry_run=true
fi

# Set up directories
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

staging_dir="$(mktemp -d)"
trap 'rm -rf "${staging_dir}"' EXIT

# Use proper SHA-256 checksum tool
checksum_tool="sha256sum"

if ! command -v "${checksum_tool}" >/dev/null 2>&1; then
  checksum_tool="shasum -a 256"
fi

# Platform packages to publish: "{npm suffix}|{archive suffix}|{OS}|{CPU}|{libc variant}"
platforms=(
  "darwin-x64|darwin-amd64|darwin|x64|"
  "darwin-arm64|darwin-arm64|darwin|arm64|"
  "linux-x64-gnu|linux-amd64|linux|x64|glibc"
  "linux-x64-musl|linux-amd64-musl|linux|x64|musl"
  "linux-arm64-gnu|linux-arm64|linux|arm64|glibc"
  "linux-arm64-musl|linux-arm64|linux|arm64|musl"
  "linux-ia32|linux-x86|linux|ia32|glibc"
)

# Read checksum manifest
declare -A checksums=()

while read -r checksum filename; do
  filename="${filename#\*}"
  checksums["${filename}"]="${checksum}"
done < "${assets_dir}/checksums.txt"

# Iterate platforms
for platform in "${platforms[@]}"; do
  # Parse platform components
  IFS='|' read -r npm_suffix archive_suffix os cpu libc <<< "${platform}"

  # Validate archive
  archive_name="super-trouper-${version}-${archive_suffix}.tar.xz"
  archive="${assets_dir}/${archive_name}"
  test -f "${archive}"

  # Reject if checksum is missing
  test -n "${checksums[${archive_name}]:-}"
  
  actual_checksum="$(${checksum_tool} "${archive}" | awk '{ print $1 }')"
  if [[ "${actual_checksum}" != "${checksums[${archive_name}]}" ]]; then
    printf 'checksum mismatch for %s\n' "${archive_name}" >&2
    exit 1
  fi

  # Extract binary and assemble package
  package_dir="${staging_dir}/${npm_suffix}"
  mkdir -p "${package_dir}/bin"

  tar --extract --file "${archive}" --xz --directory "${package_dir}/bin" super-trouper
  chmod 755 "${package_dir}/bin/super-trouper"

  cp "${script_dir}/../../README.md" "${package_dir}/README.md"
  cp "${script_dir}/../../LICENSE" "${package_dir}/LICENSE"

  # Declare libc variant
  libc_field=""

  if [[ -n "${libc}" ]]; then
    libc_field=$'\n  "libc": ["'"${libc}"'"],'
  fi

  # Create package.json
  cat > "${package_dir}/package.json" <<EOF
{
  "name": "@crissyfield/super-trouper-${npm_suffix}",
  "version": "${version}",
  "description": "MCP server for the Frida reverse engineering toolkit.",
  "license": "MIT",
  "author": "Crissy Field GmbH",
  "mcpName": "io.github.crissyfield/super-trouper",
  "homepage": "https://github.com/crissyfield/super-trouper",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/crissyfield/super-trouper.git"
  },
  "engines": {
    "node": ">=20"
  },
  "os": ["${os}"],
  "cpu": ["${cpu}"],${libc_field}
  "files": ["bin/"]
}
EOF

  # Validate
  node \
    --input-type=module \
	-e '
	  import { readFileSync } from "node:fs";
	  JSON.parse(readFileSync(process.argv[1], "utf8"));
	' \
	"${package_dir}/package.json"
done

# Assemble launcher package
launcher_dir="${staging_dir}/launcher"
mkdir -p "${launcher_dir}/bin"

cp "${script_dir}/launcher/package.json" "${launcher_dir}/package.json"
cp "${script_dir}/launcher/bin/super-trouper.cjs" "${launcher_dir}/bin/super-trouper.cjs"
cp "${script_dir}/../../README.md" "${launcher_dir}/README.md"
cp "${script_dir}/../../LICENSE" "${launcher_dir}/LICENSE"

sed -i.bak "s/\"0\.0\.0\"/\"${version}\"/g" "${launcher_dir}/package.json"
rm -f "${launcher_dir}/package.json.bak"

# Validate
node \
  --input-type=module \
  -e '
    import { readFileSync } from "node:fs";
	const pkg = JSON.parse(readFileSync(process.argv[1], "utf8"));
	if (pkg.version !== process.argv[2]) {
	  throw new Error("version substitution failed")
    }
  ' \
  "${launcher_dir}/package.json" \
  "${version}"

# Publish platform packages first (note: provenance generation only supported in CI)
publish_args=(--access public)

if [[ "${GITHUB_ACTIONS:-false}" == true ]]; then
  publish_args+=(--provenance)
fi

if [[ "${dry_run}" == true ]]; then
  publish_args+=(--dry-run)
fi

for platform in "${platforms[@]}"; do
  IFS='|' read -r npm_suffix _ <<< "${platform}"
  package_name="@crissyfield/super-trouper-${npm_suffix}"

  # Skip packages that are already published so partial runs can be resumed
  if [[ "${dry_run}" == false ]] && npm view "${package_name}@${version}" version >/dev/null 2>&1; then
    printf 'skipping %s@%s, already on the registry\n' "${package_name}" "${version}"
    continue
  fi

  (
	cd "${staging_dir}/${npm_suffix}" && \
	npm publish "${publish_args[@]}"
  )
done

# Wait for all packages to become visible
if [[ "${dry_run}" == false ]]; then
  # Iterate packages
  for platform in "${platforms[@]}"; do
    IFS='|' read -r npm_suffix _ <<< "${platform}"
    package_name="@crissyfield/super-trouper-${npm_suffix}"
    
	# Check for up to five minutes
	visible=false
    for _ in {1..60}; do
      if npm view "${package_name}@${version}" version >/dev/null 2>&1; then
        visible=true
        break
      fi
      sleep 5
    done

	# If not visible after five minutes, exit
    if [[ "${visible}" == false ]]; then
      printf '%s@%s did not become visible on the registry\n' "${package_name}" "${version}" >&2
      exit 1
    fi
  done
fi

# Publish launcher package unless it is already on the registry
if [[ "${dry_run}" == false ]] && npm view "@crissyfield/super-trouper@${version}" version >/dev/null 2>&1; then
  printf 'skipping @crissyfield/super-trouper@%s, already on the registry\n' "${version}"
else
  (cd "${launcher_dir}" && npm publish "${publish_args[@]}")
fi
