#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CC_BIN="${CC:-cc}"
SRC="${REPO_ROOT}/native/cipher_openssl_shim.c"
OUT_OBJ="${REPO_ROOT}/native/cipher_openssl_shim.o"

echo "==> Building optional Cipher OpenSSL C shim (${OUT_OBJ}) using ${CC_BIN}..."
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        "${CC_BIN}" -O2 -Wall -Wextra -c "${SRC}" -o "${OUT_OBJ}"
        ;;
    Linux*)
        "${CC_BIN}" -O2 -fPIC -Wall -Wextra -c "${SRC}" -o "${OUT_OBJ}"
        ;;
    *)
        "${CC_BIN}" -O2 -fPIC -Wall -Wextra -c "${SRC}" -o "${OUT_OBJ}"
        ;;
esac
echo "==> Built: ${OUT_OBJ}"
