#!/usr/bin/env bash
# Download NIST ACVP test vectors for ML-KEM and ML-DSA
# Source: https://github.com/usnistgov/ACVP-Server
set -euo pipefail

VECTORS_DIR="$(cd "$(dirname "$0")/../tests/vectors" && pwd)"
BASE_URL="https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files"

echo "Downloading NIST ACVP test vectors to ${VECTORS_DIR}..."
mkdir -p "${VECTORS_DIR}"

curl -sL "${BASE_URL}/ML-KEM-keyGen-FIPS203/internalProjection.json" \
  -o "${VECTORS_DIR}/mlkem-keygen.json"
echo "  ✓ ML-KEM keyGen"

curl -sL "${BASE_URL}/ML-KEM-encapDecap-FIPS203/internalProjection.json" \
  -o "${VECTORS_DIR}/mlkem-encapdecap.json"
echo "  ✓ ML-KEM encapDecap"

curl -sL "${BASE_URL}/ML-DSA-keyGen-FIPS204/internalProjection.json" \
  -o "${VECTORS_DIR}/mldsa-keygen.json"
echo "  ✓ ML-DSA keyGen"

curl -sL "${BASE_URL}/ML-DSA-sigGen-FIPS204/internalProjection.json" \
  -o "${VECTORS_DIR}/mldsa-siggen.json"
echo "  ✓ ML-DSA sigGen"

curl -sL "${BASE_URL}/ML-DSA-sigVer-FIPS204/internalProjection.json" \
  -o "${VECTORS_DIR}/mldsa-sigver.json"
echo "  ✓ ML-DSA sigVer"

echo ""
echo "Done. Vector files:"
ls -lh "${VECTORS_DIR}"/*.json
