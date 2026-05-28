#!/usr/bin/env python3
"""
Template validation tests — POST each generated detector to the live
Splunk API and immediately DELETE it. Catches SignalFlow syntax errors,
invalid filter patterns, unsupported functions, and missing rules before
any real deployment.

Usage:
  python3 tests/test_templates.py --realm us1 --token $TOKEN

Exits 0 if all templates are valid, 1 if any fail.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from templates import TEMPLATE_REGISTRY
from templates.apm import APMTemplates
from core.detector_deployer import _build_detector_payload, _normalize_signalflow

# Representative service/env used for all validation tests
_TEST_SVC = "_validation_test_svc_"
_TEST_ENV = "_validation_test_env_"


def _api_post(api_base: str, token: str, body: dict) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{api_base}/v2/detector", data=data,
        headers={"X-SF-Token": token, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        chunks = []
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            chunks.append(chunk)
        return json.loads(b"".join(chunks).decode())


def _api_delete(api_base: str, token: str, det_id: str) -> None:
    req = urllib.request.Request(
        f"{api_base}/v2/detector/{det_id}",
        headers={"X-SF-Token": token},
        method="DELETE",
    )
    with urllib.request.urlopen(req, timeout=10):
        pass


def validate_template(api_base: str, token: str, det) -> str | None:
    """Returns None on success, error string on failure."""
    try:
        payload = _build_detector_payload(det, _TEST_SVC, _TEST_ENV)
        result = _api_post(api_base, token, payload)
        _api_delete(api_base, token, result["id"])
        return None
    except urllib.error.HTTPError as e:
        return e.read().decode()[:300]
    except Exception as e:
        return str(e)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate all detector templates against live Splunk API")
    parser.add_argument("--realm", required=True)
    parser.add_argument("--token", default=os.environ.get("SPLUNK_ACCESS_TOKEN"))
    parser.add_argument("--template", help="Only test this template key (e.g. jvm, redis)")
    args = parser.parse_args()

    if not args.token:
        print("ERROR: --token required", file=sys.stderr)
        return 1

    api_base = f"https://api.{args.realm}.signalfx.com"

    # Collect all template classes to test (deduplicated)
    classes_to_test: dict[str, type] = {}
    if args.template:
        cls = TEMPLATE_REGISTRY.get(args.template)
        if not cls:
            print(f"Unknown template: {args.template}", file=sys.stderr)
            return 1
        classes_to_test[args.template] = cls
    else:
        # APM always included
        classes_to_test["apm"] = APMTemplates
        for key, cls in TEMPLATE_REGISTRY.items():
            classes_to_test.setdefault(cls.__name__, cls)

    total = passed = failed = 0
    failures: list[tuple[str, str, str]] = []

    for label, cls in sorted(classes_to_test.items(), key=lambda x: x[0]):
        try:
            dets = cls.templates(_TEST_SVC, _TEST_ENV)
        except Exception as e:
            print(f"  ERROR generating {label}: {e}")
            continue

        for det in dets:
            total += 1
            err = validate_template(api_base, token=args.token, det=det)
            if err is None:
                passed += 1
                print(f"  OK  [{label}] {det.name}")
            else:
                failed += 1
                failures.append((label, det.name, err))
                print(f"  FAIL [{label}] {det.name}")
                print(f"       {err[:200]}")

    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed")
    if failures:
        print(f"\nFailed detectors:")
        for label, name, err in failures:
            print(f"  [{label}] {name}")
            print(f"    {err[:150]}")
    print(f"{'='*60}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
