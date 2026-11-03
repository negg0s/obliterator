#!/usr/bin/env python3
"""
CycloneDX SBOM generator for Obliterator.
Scans project files, computes SHA-256 hashes, and outputs CycloneDX v1.5 JSON.
"""

import argparse
import datetime
import hashlib
import json
import os
import sys
import uuid

EXCLUDED_DIRS = {
    ".git",
    ".github",
    "build",
    "bin",
    "out",
    ".cache",
    "__pycache__"
}

INCLUDED_EXTENSIONS = {
    ".cpp",
    ".hpp",
    ".h",
    ".manifest",
    ".rc",
    ".in",
    ".txt",
    ".json",
    ".md"
}

def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def scan_project_files(root_dir: str):
    components = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Exclude directories
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for fname in sorted(filenames):
            ext = os.path.splitext(fname)[1].lower()
            if ext in INCLUDED_EXTENSIONS or fname in {"LICENSE", "CMakeLists.txt"}:
                full_path = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(full_path, root_dir).replace("\\", "/")
                file_hash = compute_sha256(full_path)
                components.append({
                    "type": "file",
                    "bom-ref": f"file:{rel_path}",
                    "name": rel_path,
                    "version": "0.2.0",
                    "hashes": [
                        {
                            "alg": "SHA-256",
                            "content": file_hash
                        }
                    ],
                    "licenses": [
                        {
                            "license": {
                                "id": "MIT"
                            }
                        }
                    ]
                })
    return components

def generate_sbom(root_dir: str, version: str) -> dict:
    components = scan_project_files(root_dir)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    serial = f"urn:uuid:{uuid.uuid4()}"

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "vendor": "negg0s",
                    "name": "generate_sbom.py",
                    "version": "1.0.0"
                }
            ],
            "authors": [
                {
                    "name": "negg0s"
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": f"pkg:generic/obliterator@{version}",
                "name": "obliterator",
                "version": version,
                "description": "Force uninstaller and system cleaner for Windows",
                "licenses": [
                    {
                        "license": {
                            "id": "MIT"
                        }
                    }
                ],
                "purl": f"pkg:generic/obliterator@{version}"
            },
            "properties": [
                {
                    "name": "dependencies:description",
                    "value": "Zero external dependencies. Pure Win32 and static C++ runtime."
                }
            ]
        },
        "components": components,
        "dependencies": [
            {
                "ref": f"pkg:generic/obliterator@{version}",
                "dependsOn": []
            }
        ]
    }
    return sbom

def main():
    parser = argparse.ArgumentParser(description="Generate CycloneDX SBOM for Obliterator")
    parser.add_argument("--root", default=".", help="Project root directory")
    parser.add_argument("--output", default="sbom.cdx.json", help="Output JSON path")
    parser.add_argument("--version", default="0.2.0", help="Project release version")
    args = parser.parse_args()

    root_dir = os.path.abspath(args.root)
    output_path = os.path.abspath(args.output)

    sbom = generate_sbom(root_dir, args.version)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"Generated CycloneDX SBOM at {output_path} ({len(sbom['components'])} components)")

if __name__ == "__main__":
    main()
