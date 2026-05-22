#!/usr/bin/env python3
"""
Auto-Detector Provisioner for Splunk Observability Cloud

Automatically discovers services, detects their tech stack / frameworks /
libraries from live telemetry, learns behavioral baselines, and provisions
best-practice detectors tuned to the application's actual behavior.

Usage:
  # Dry run — show what detectors would be created
  python3 provision.py --realm us1 --token $TOKEN --environment production

  # Scope to a specific service
  python3 provision.py --realm us1 --token $TOKEN --environment production --service my-service

  # Auto-deploy detectors
  python3 provision.py --realm us1 --token $TOKEN --environment production --auto-deploy

  # Include low-confidence detectors in dry run
  python3 provision.py --realm us1 --token $TOKEN --environment production --include-low-confidence

  # Skip baseline learning (use fixed thresholds only)
  python3 provision.py --realm us1 --token $TOKEN --environment production --skip-baseline
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from core.discovery import discover_services
from core.baseline_learner import learn_baseline, load_baseline
from core.detector_generator import generate_detectors, format_dry_run_report
from core.detector_deployer import deploy_detectors, format_deploy_summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Auto-provision Splunk Observability detectors based on live telemetry",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    conn = parser.add_argument_group("connection")
    conn.add_argument("--realm", required=True, help="Splunk Observability realm (e.g. us1, us0, eu0)")
    conn.add_argument("--token", default=os.environ.get("SPLUNK_ACCESS_TOKEN"),
                      help="API token (or set SPLUNK_ACCESS_TOKEN env var)")

    scope = parser.add_argument_group("scope")
    scope.add_argument("--environment", "--env", help="Filter to a specific environment")
    scope.add_argument("--service", help="Filter to a specific service name")

    baseline = parser.add_argument_group("baseline")
    baseline.add_argument("--skip-baseline", action="store_true",
                          help="Skip baseline learning — use fixed best-practice thresholds only")
    baseline.add_argument("--baseline-window-hours", type=int, default=24, metavar="N",
                          help="Lookback window for baseline learning (default: 24h)")
    baseline.add_argument("--baseline-dir", type=Path, default=Path("data/baselines"),
                          help="Directory to store/load learned baselines")

    deploy = parser.add_argument_group("deployment")
    deploy.add_argument("--auto-deploy", action="store_true",
                        help="Deploy detectors automatically (default: dry run only)")
    deploy.add_argument("--include-low-confidence", action="store_true",
                        help="Include low-confidence detectors (heuristic-based)")

    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if not args.token:
        print("ERROR: --token is required (or set SPLUNK_ACCESS_TOKEN)", file=sys.stderr)
        return 1

    dry_run = not args.auto_deploy
    mode = "DRY RUN" if dry_run else "AUTO-DEPLOY"

    print(f"\n{'='*60}", file=sys.stderr)
    print(f"Auto-Detector Provisioner  [{mode}]", file=sys.stderr)
    print(f"Realm: {args.realm}  Env: {args.environment or 'all'}  Service: {args.service or 'all'}", file=sys.stderr)
    print(f"{'='*60}\n", file=sys.stderr)

    # ── Step 1: Discover services ────────────────────────────────────────────
    print("Step 1: Discovering services and detecting tech stack...", file=sys.stderr)
    profiles = discover_services(
        realm=args.realm,
        token=args.token,
        environment=args.environment,
    )

    if args.service:
        profiles = [p for p in profiles if p.service == args.service]

    if not profiles:
        print("No services found. Check your realm, token, and environment.", file=sys.stderr)
        return 1

    print(f"  Found {len(profiles)} service(s)\n", file=sys.stderr)

    total_deployed = 0
    total_failed = 0

    for profile in profiles:
        print(f"\nProcessing: {profile.service} (env={profile.environment})", file=sys.stderr)
        if profile.stacks or profile.frameworks or profile.libraries:
            detected = profile.stacks + profile.frameworks + profile.libraries
            print(f"  Detected: {', '.join(detected)}", file=sys.stderr)
        else:
            print("  Detected: APM only (no specific stack/library identified)", file=sys.stderr)

        # ── Step 2: Learn baseline ───────────────────────────────────────────
        baseline = None
        if not args.skip_baseline:
            print("  Learning baseline...", file=sys.stderr)

            # Check for cached baseline
            baseline_path = args.baseline_dir / f"{profile.environment}__{profile.service}.json"
            baseline = load_baseline(baseline_path)

            if baseline:
                print(f"  Using cached baseline (learned {baseline.window_hours}h window)", file=sys.stderr)
            else:
                baseline = learn_baseline(
                    realm=args.realm,
                    token=args.token,
                    service=profile.service,
                    environment=profile.environment,
                    window_hours=args.baseline_window_hours,
                    output_dir=args.baseline_dir,
                )

            if baseline.is_reliable():
                print(f"  Baseline: latency={baseline.latency_mean_ms:.1f}ms "
                      f"error_rate={baseline.error_rate_pct:.2f}% "
                      f"samples={baseline.sample_count}", file=sys.stderr)
            else:
                print(f"  Baseline: insufficient samples ({baseline.sample_count}) — using fixed thresholds", file=sys.stderr)
                baseline = None

        # ── Step 3: Generate detectors ───────────────────────────────────────
        detectors = generate_detectors(
            profile=profile,
            baseline=baseline,
            include_low_confidence=args.include_low_confidence,
        )

        # Print dry run report
        report = format_dry_run_report(profile, detectors, baseline)
        print(report)

        # ── Step 4: Deploy ───────────────────────────────────────────────────
        results = deploy_detectors(
            realm=args.realm,
            token=args.token,
            service=profile.service,
            environment=profile.environment,
            detectors=detectors,
            dry_run=dry_run,
        )

        summary = format_deploy_summary(results, dry_run)
        print(summary)

        total_deployed += sum(1 for r in results if r.success)
        total_failed += sum(1 for r in results if not r.success)

    # ── Final summary ────────────────────────────────────────────────────────
    print(f"\n{'='*60}", file=sys.stderr)
    action = "Would create" if dry_run else "Created"
    print(f"{action} {total_deployed} detectors across {len(profiles)} service(s)", file=sys.stderr)
    if total_failed:
        print(f"Failed: {total_failed}", file=sys.stderr)
    if dry_run:
        print("\nRun with --auto-deploy to create these detectors.", file=sys.stderr)
    print(f"{'='*60}\n", file=sys.stderr)

    return 0 if total_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
