#!/usr/bin/env python3
"""Build reproducible, integrity-checked RabbitDLP endpoint ZIPs for supported platforms."""

from __future__ import annotations

import hashlib
import io
import json
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile


VERSION = "1.24.0"
ROOT = pathlib.Path(__file__).resolve().parent
ASSETS = {
    "windows-x64": ("yara-x-v1.24.0-x86_64-pc-windows-msvc.zip", "8b68b49e051b2d2787a74df5588fcf65d41bd21b27689061fd16a80516cb9336", "windows"),
    "windows-arm64": ("yara-x-v1.24.0-aarch64-pc-windows-msvc.zip", "aa1a8986ac7b06f33a8f0941ca1482acf31eb1b158c7f9a517ec940fffa84311", "windows"),
    "macos-x64": ("yara-x-v1.24.0-x86_64-apple-darwin.tar.gz", "20edd3f0a6ace6cbd5d5302b77ddca51f22abaae0153bc26dfde9aded561a6fc", "unix"),
    "macos-arm64": ("yara-x-v1.24.0-aarch64-apple-darwin.tar.gz", "20f8231df466a24e2c15db82dc4001c76dd52c3d38ef9cda72e04b4f50d9e0a6", "unix"),
    "linux-x64": ("yara-x-v1.24.0-x86_64-unknown-linux-gnu.tar.gz", "b98628160a5dcbb6afcbba6886b0f4a275df930923ae3bb3553d83115744fb29", "unix"),
    "linux-arm64": ("yara-x-v1.24.0-aarch64-unknown-linux-gnu.tar.gz", "65ec287b7acb8fd815fe2ff4097f35937abeefe93427f49f68686e1394acecd8", "unix"),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch_verified(name: str, expected: str, directory: pathlib.Path) -> bytes:
    path = directory / name
    url = f"https://github.com/VirusTotal/yara-x/releases/download/v{VERSION}/{name}"
    request = urllib.request.Request(url, headers={"User-Agent": "B89-Ferrispector-Builder/1"})
    with urllib.request.urlopen(request, timeout=120) as response, path.open("wb") as output:
        shutil.copyfileobj(response, output)
    data = path.read_bytes()
    actual = sha256(data)
    if actual != expected:
        raise RuntimeError(f"SHA-256 mismatch for {name}: expected {expected}, got {actual}")
    return data


def binary_from_archive(name: str, data: bytes, platform: str, target: pathlib.Path) -> None:
    member_name = "yr.exe" if platform == "windows" else "yr"
    if platform == "windows":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            matches = [item for item in archive.infolist() if pathlib.PurePosixPath(item.filename).name == member_name]
            if len(matches) != 1:
                raise RuntimeError(f"Expected one {member_name} in {name}")
            target.write_bytes(archive.read(matches[0]))
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            matches = [item for item in archive.getmembers() if pathlib.PurePosixPath(item.name).name == member_name and item.isfile()]
            if len(matches) != 1:
                raise RuntimeError(f"Expected one executable {member_name} in {name}")
            stream = archive.extractfile(matches[0])
            if stream is None:
                raise RuntimeError(f"Could not read {member_name} in {name}")
            target.write_bytes(stream.read())
        target.chmod(0o755)


def compile_policy(source: pathlib.Path, compiler: pathlib.Path, output: pathlib.Path) -> None:
    subprocess.run([str(compiler), "compile", str(source), "--output", str(output)], check=True)


def build_package(platform: str, expected: str, kind: str,
                  binary: pathlib.Path, compiled_policy: pathlib.Path,
                  policy_sha: str, catalog_sha: str, output: pathlib.Path) -> None:
    is_windows = kind == "windows"
    files: dict[str, pathlib.Path] = {
        "bin/yr.exe" if is_windows else "bin/yr": binary,
        "policy/dlp-rules.yarc": compiled_policy,
        "policy/fingerprints.sha256": ROOT / "policy" / "fingerprints.sha256",
        "THIRD-PARTY-NOTICES.txt": ROOT / "THIRD-PARTY-NOTICES.txt",
    }
    if is_windows:
        files["ferrispector.ps1"] = ROOT / "ferrispector.ps1"
        files["install-windows-endpoint.ps1"] = ROOT / "install-windows-endpoint.ps1"
        files["rabbitdlp-device-control.ps1"] = ROOT / "rabbitdlp-device-control.ps1"
        files["rabbitdlp-quarantine.ps1"] = ROOT / "rabbitdlp-quarantine.ps1"
        files["restore-quarantined-file.ps1"] = ROOT / "restore-quarantined-file.ps1"
    else:
        files["README.md"] = ROOT / "README.md"
        files["policy/README.md"] = ROOT / "policy" / "README.md"
        files["ferrispector.py"] = ROOT / "ferrispector.py"
        files["install-unix-endpoint.sh"] = ROOT / "install-unix-endpoint.sh"

    manifest = {
        "product": "RabbitDLP",
        "engine": "YARA-X CLI",
        "engineVersion": VERSION,
        "platform": platform.split("-", 1)[0],
        "architecture": platform.split("-", 1)[1],
        "policyName": "approved-dlp-rules",
        "policyVersion": "1.0.0",
        "policySourceSha256": policy_sha,
        "fingerprintCatalogSha256": catalog_sha,
        "sourceUrl": f"https://github.com/VirusTotal/yara-x/releases/download/v{VERSION}/{ASSETS[platform][0]}",
        "sourceArchiveSha256": expected,
        "engineBinarySha256": sha256(binary.read_bytes()),
        "rulesSha256": sha256(compiled_policy.read_bytes()),
        "licenseNotice": "THIRD-PARTY-NOTICES.txt",
        "installMode": "detection, exact-fingerprint quarantine and optional Defender device control; monitored roots are operator supplied",
    }
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for archive_name, path in files.items():
            if not path.is_file():
                raise RuntimeError(f"Missing package input: {path}")
            archive.write(path, archive_name)
        archive.writestr("manifest.json", json.dumps(manifest, indent=2) + "\n")
    output.with_suffix(output.suffix + ".sha256").write_text(
        f"{sha256(output.read_bytes())}  {output.name}\n", encoding="ascii"
    )


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: build-release-packages.py OUTPUT_DIRECTORY")
    output = pathlib.Path(sys.argv[1]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    source_policy = ROOT / "policy" / "starter-credentials.yar"
    fingerprints = ROOT / "policy" / "fingerprints.sha256"
    policy_sha = sha256(source_policy.read_bytes())
    catalog_sha = sha256(fingerprints.read_bytes())
    with tempfile.TemporaryDirectory(prefix="b89-ferrispector-") as temporary:
        work = pathlib.Path(temporary)
        downloaded: dict[str, bytes] = {}
        for platform, (name, expected, _) in ASSETS.items():
            downloaded[platform] = fetch_verified(name, expected, work)

        compiler = work / "yr-compile"
        binary_from_archive(ASSETS["linux-x64"][0], downloaded["linux-x64"], "unix", compiler)
        compiled_policy = work / "dlp-rules.yarc"
        compile_policy(source_policy, compiler, compiled_policy)

        for platform, (name, expected, kind) in ASSETS.items():
            suffix = ".exe" if kind == "windows" else ""
            binary = work / f"{platform}-yr{suffix}"
            binary_from_archive(name, downloaded[platform], kind, binary)
            package = output / f"RabbitDLP-{platform}.zip"
            build_package(platform, expected, kind, binary,
                          compiled_policy, policy_sha, catalog_sha, package)
            print(f"Built {package.name} sha256={sha256(package.read_bytes())}")


if __name__ == "__main__":
    main()
