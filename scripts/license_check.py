#!/usr/bin/env python3
import json
import os
import re
import subprocess
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ALLOWED = {
    item.strip()
    for item in os.environ.get(
        "ALLOWED_GO",
        "Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,BlueOak-1.0.0,0BSD,MPL-2.0",
    ).split(",")
    if item.strip()
}
INCLUDE_TEST_DEPS = os.environ.get("INCLUDE_TEST_DEPS", "0") == "1"


def load_go_packages():
    cmd = ["go", "list", "-deps", "-json"]
    if INCLUDE_TEST_DEPS:
        cmd.insert(3, "-test")
    cmd.append("./...")
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(proc.returncode)

    decoder = json.JSONDecoder()
    data = proc.stdout
    index = 0
    while index < len(data):
        while index < len(data) and data[index].isspace():
            index += 1
        if index >= len(data):
            break
        obj, index = decoder.raw_decode(data, index)
        yield obj


def license_files(module_dir):
    try:
        names = os.listdir(module_dir)
    except OSError:
        return []

    preferred = []
    fallback = []
    for name in names:
        lower = name.lower()
        path = os.path.join(module_dir, name)
        if not os.path.isfile(path):
            continue
        if re.match(r"^(licen[sc]e|copying)([._-].*)?$", lower):
            preferred.append(path)
        elif re.match(r"^(notice|readme)([._-].*)?$", lower):
            fallback.append(path)
    return sorted(preferred) + sorted(fallback)


def normalize(text):
    return re.sub(r"\s+", " ", text.lower())


def spdx_ids(text):
    ids = set()
    for match in re.finditer(r"SPDX-License-Identifier:\s*([^\n\r*]+)", text, re.I):
        expr = match.group(1)
        ids.update(re.findall(r"[A-Za-z0-9][A-Za-z0-9.+-]*", expr))
    return ids


def detect_license(text):
    ids = spdx_ids(text)
    allowed_ids = ids & ALLOWED
    if allowed_ids:
        return sorted(allowed_ids)[0]

    body = normalize(text)
    if "apache license" in body and "version 2.0" in body:
        return "Apache-2.0"
    if "mozilla public license" in body and "2.0" in body:
        return "MPL-2.0"
    if "blue oak model license" in body or "blueoak" in body:
        return "BlueOak-1.0.0"
    if "permission is hereby granted, free of charge, to any person obtaining a copy" in body:
        return "MIT"
    if (
        "permission to use, copy, modify, and/or distribute this software for any purpose" in body
        and "the software is provided" in body
    ):
        if "with or without fee is hereby granted" in body:
            return "ISC"
        return "0BSD"
    if (
        "redistribution and use in source and binary forms" in body
        and "with or without modification" in body
    ):
        if (
            "neither the name" in body
            or "neither the names" in body
            or "neither the copyright holder" in body
        ):
            return "BSD-3-Clause"
        return "BSD-2-Clause"
    return ""


def module_license(module):
    candidates = license_files(module["Dir"])
    detected = []
    for path in candidates:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                license_id = detect_license(handle.read(256 * 1024))
        except OSError:
            continue
        if license_id:
            detected.append((license_id, path))
    return detected, candidates


def main():
    modules = {}
    missing_dir = []
    for package in load_go_packages():
        if package.get("Standard") or package.get("Goroot"):
            continue
        module = package.get("Module") or {}
        if not module or module.get("Main"):
            continue
        module_dir = module.get("Dir")
        if not module_dir:
            missing_dir.append(f"{module.get('Path', '<unknown>')} {module.get('Version', '')}".strip())
            continue
        key = (module.get("Path", ""), module.get("Version", ""), module_dir)
        modules[key] = {"Path": key[0], "Version": key[1], "Dir": key[2]}

    failures = []
    for key in sorted(modules):
        module = modules[key]
        detected, candidates = module_license(module)
        allowed = [(license_id, path) for license_id, path in detected if license_id in ALLOWED]
        label = f"{module['Path']} {module['Version']}".strip()
        if not allowed:
            if detected:
                seen = ", ".join(f"{license_id} ({os.path.basename(path)})" for license_id, path in detected)
                failures.append(f"{label}: license outside allow-list: {seen}")
            elif candidates:
                names = ", ".join(os.path.basename(path) for path in candidates)
                failures.append(f"{label}: could not identify allowed license in {names}")
            else:
                failures.append(f"{label}: no top-level license file found")

    if missing_dir:
        failures.extend(f"{item}: missing module directory from go list" for item in missing_dir)

    if failures:
        print("Go module license check failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        print(f"Allowed licenses: {', '.join(sorted(ALLOWED))}", file=sys.stderr)
        return 1

    print(f"checked {len(modules)} Go modules; all matched allowed licenses")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
