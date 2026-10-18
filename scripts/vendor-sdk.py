#!/usr/bin/env python3
"""Copy a release-pinned SDK source snapshot into an application repository."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

p=argparse.ArgumentParser();p.add_argument('project',type=Path);p.add_argument('language',choices=['java','swift','dart','python']);a=p.parse_args()
root=Path(__file__).resolve().parents[1];source=root/'sdk'/a.language;target=a.project/'vendor/common-relay'/a.language
if target.exists(): raise SystemExit(f'Refusing to overwrite existing snapshot: {target}')
ignore=shutil.ignore_patterns('.build','.swiftpm','.dart_tool','.gradle','build','test','Tests','test_integration.py','__pycache__','local.properties')
shutil.copytree(source,target,ignore=ignore)
if a.language == 'swift':
    (target/'Package.swift').write_text('''// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "CommonRelay",
    platforms: [.macOS(.v13), .iOS(.v15)],
    products: [.library(name: "CommonRelay", type: .static, targets: ["CommonRelay"])],
    dependencies: [.package(url: "https://github.com/jedisct1/swift-sodium.git", exact: "0.11.0")],
    targets: [.target(name: "CommonRelay", dependencies: [.product(name: "Clibsodium", package: "swift-sodium")])]
)
''')
license=root/'LICENSE'
if license.exists(): shutil.copy2(license,target/'LICENSE')
manifest={str(f.relative_to(target)):hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(target.rglob('*')) if f.is_file()}
(target/'SOURCE.json').write_text(json.dumps({'upstream':'https://github.com/JunWeiUp/common-relay','version':'0.1.0-dev','files':manifest},indent=2)+'\n')
print(target)
