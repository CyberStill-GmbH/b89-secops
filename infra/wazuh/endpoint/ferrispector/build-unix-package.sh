#!/bin/sh
set -eu
VERSION=1.24.0
ARCH="${1:-}"
OUT="${2:-}"
case "$ARCH" in arm64|x64) ;; *) echo "Uso: $0 arm64|x64 salida.zip" >&2; exit 2 ;; esac
[ -n "$OUT" ] || { echo "Indica el archivo ZIP de salida." >&2; exit 2; }
for tool in curl tar python3 zip; do command -v "$tool" >/dev/null 2>&1 || { echo "Se requiere $tool." >&2; exit 1; }; done
if command -v shasum >/dev/null 2>&1; then
  sha_file() { shasum -a 256 "$1" | awk '{print $1}'; }
elif command -v sha256sum >/dev/null 2>&1; then
  sha_file() { sha256sum "$1" | awk '{print $1}'; }
else
  echo "Se requiere shasum o sha256sum." >&2; exit 1
fi
case "$(uname -s)" in Darwin) OS=apple-darwin ;; Linux) OS=unknown-linux-gnu ;; *) echo "El builder se ejecuta en macOS o Linux." >&2; exit 1 ;; esac
case "$ARCH" in arm64) TARGET=aarch64 ;; x64) TARGET=x86_64 ;; esac
case "$(uname -m)-$TARGET" in aarch64-aarch64|arm64-aarch64|x86_64-x86_64|amd64-x86_64) ;; *) echo "La arquitectura del paquete debe coincidir con la máquina que ejecuta el builder." >&2; exit 1 ;; esac
ASSET="yara-x-v$VERSION-$TARGET-$OS.tar.gz"
case "$OS-$ARCH" in
  apple-darwin-arm64) EXPECTED=20f8231df466a24e2c15db82dc4001c76dd52c3d38ef9cda72e04b4f50d9e0a6 ;;
  apple-darwin-x64) EXPECTED=20edd3f0a6ace6cbd5d5302b77ddca51f22abaae0153bc26dfde9aded561a6fc ;;
  unknown-linux-gnu-arm64) EXPECTED=65ec287b7acb8fd815fe2ff4097f35937abeefe93427f49f68686e1394acecd8 ;;
  unknown-linux-gnu-x64) EXPECTED=b98628160a5dcbb6afcbba6886b0f4a275df930923ae3bb3553d83115744fb29 ;;
esac
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/b89-ferrispector-build.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
ARCHIVE="$TMP/$ASSET"
URL="https://github.com/VirusTotal/yara-x/releases/download/v$VERSION/$ASSET"
curl --fail --location --silent --show-error "$URL" -o "$ARCHIVE"
ACTUAL="$(sha_file "$ARCHIVE")"
[ "$ACTUAL" = "$EXPECTED" ] || { echo "Hash SHA-256 de YARA-X no coincide; esperado $EXPECTED, recibido $ACTUAL." >&2; exit 1; }
mkdir -p "$TMP/unpacked"
tar -xzf "$ARCHIVE" -C "$TMP/unpacked"
YR="$(find "$TMP/unpacked" -type f -name yr -perm -u+x -print -quit)"
[ -n "$YR" ] || { echo "El paquete verificado no contiene el ejecutable yr." >&2; exit 1; }
STAGE="$TMP/package"
mkdir -p "$STAGE/bin" "$STAGE/policy"
install -m 0755 "$YR" "$STAGE/bin/yr"
install -m 0644 "$ROOT/policy/starter-credentials.yar" "$STAGE/policy/approved-dlp-rules.yar"
install -m 0644 "$ROOT/policy/fingerprints.sha256" "$STAGE/policy/fingerprints.sha256"
"$STAGE/bin/yr" compile "$STAGE/policy/approved-dlp-rules.yar" --output "$STAGE/policy/dlp-rules.yarc"
rm "$STAGE/policy/approved-dlp-rules.yar"
install -m 0644 "$ROOT/THIRD-PARTY-NOTICES.txt" "$STAGE/THIRD-PARTY-NOTICES.txt"
install -m 0644 "$ROOT/README.md" "$STAGE/README.md"
install -m 0644 "$ROOT/policy/README.md" "$STAGE/policy/README.md"
install -m 0644 "$ROOT/ferrispector.py" "$STAGE/ferrispector.py"
install -m 0755 "$ROOT/install-unix-endpoint.sh" "$STAGE/install-unix-endpoint.sh"
ENGINE_SHA="$(sha_file "$STAGE/bin/yr")"
RULES_SHA="$(sha_file "$STAGE/policy/dlp-rules.yarc")"
python3 - "$STAGE/manifest.json" "$VERSION" "$OS" "$ARCH" "$URL" "$EXPECTED" "$ENGINE_SHA" "$RULES_SHA" <<'PY'
import json, sys
path, version, target, arch, url, archive_sha, engine_sha, rules_sha = sys.argv[1:]
with open(path, "w", encoding="utf-8") as stream:
    json.dump({"product":"B89 Ferrispector", "engine":"YARA-X CLI", "engineVersion":version,
               "platform":target, "architecture":arch, "policyName":"approved-dlp-rules",
               "policyVersion":"1.0.0", "rulesSha256":rules_sha, "sourceUrl":url,
               "sourceArchiveSha256":archive_sha, "engineBinarySha256":engine_sha,
               "licenseNotice":"THIRD-PARTY-NOTICES.txt",
               "installMode":"detection-only; approved local roots only"}, stream, indent=2)
    stream.write("\n")
PY
OUT="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$OUT")"
[ ! -e "$OUT" ] || { echo "El destino ya existe: $OUT" >&2; exit 1; }
mkdir -p "$(dirname "$OUT")"
(cd "$STAGE" && zip -qr "$OUT" .)
PACKAGE_SHA="$(sha_file "$OUT")"
printf '%s  %s\n' "$PACKAGE_SHA" "$(basename "$OUT")" > "$OUT.sha256"
echo "Paquete listo: $OUT (YARA-X v$VERSION, $OS, $ARCH, SHA-256 $PACKAGE_SHA)."
