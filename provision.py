#!/usr/bin/env python3
"""
Auto-Detector Provisioner for Splunk Observability Cloud

Automatically discovers services, detects their tech stack / frameworks /
libraries from live telemetry, learns behavioral baselines, and provisions
best-practice detectors tuned to the application's actual behavior.

Usage:
  # Dry run — show what detectors would be created
  python3 provision.py --realm us1 --token $TOKEN --environment production

  # Auto-deploy detectors
  python3 provision.py --realm us1 --token $TOKEN --environment production --auto-deploy

  # Continuous watch mode — auto-provision new services, retune on drift
  python3 provision.py --realm us1 --token $TOKEN --environment production --watch

  # Retune existing detectors based on updated baseline
  python3 provision.py --realm us1 --token $TOKEN --environment production --retune

  # Mute a service during deployment
  python3 provision.py --realm us1 --token $TOKEN --environment production --service my-svc --mute 30

  # Unmute a service
  python3 provision.py --realm us1 --token $TOKEN --environment production --service my-svc --unmute

  # Archive a decommissioned service (delete its detectors)
  python3 provision.py --realm us1 --token $TOKEN --environment production --service my-svc --archive

  # Scan for stale services and archive them
  python3 provision.py --realm us1 --token $TOKEN --environment production --archive-stale
"""
from __future__ import annotations

import argparse
import datetime
import logging
import os
import sys
import time
from pathlib import Path

from core.discovery import discover_services
from core.baseline_learner import learn_baseline, load_baseline, find_similar_baseline
from core.detector_generator import generate_detectors, format_dry_run_report
from core.detector_deployer import deploy_detectors, reconcile_detectors, format_deploy_summary
from core.html_report import generate_html_report, _det_id
from core.report_server import ReportServer
from core.state import ProvisionerState, DetectorRecord, STATE_FILE
from core.retune import retune_service, baseline_hash, signalflow_hash, format_retune_summary, audit_detector_effectiveness
from core.mute import mute_service, unmute_service, list_active_mutes, format_mute_list
from core.archive import archive_service, archive_stale_services, format_archive_summary
from core.watch import WatchDaemon, WatchConfig


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
    baseline.add_argument("--baseline-window-hours", type=int, default=168, metavar="N",
                          help="Lookback window for baseline learning (default: 168h = 7 days)")
    baseline.add_argument("--baseline-dir", type=Path, default=Path("data/baselines"),
                          help="Directory to store/load learned baselines")

    deploy = parser.add_argument_group("deployment")
    deploy.add_argument("--auto-deploy", action="store_true",
                        help="Deploy detectors automatically (default: dry run only)")
    deploy.add_argument("--html-report", type=Path, metavar="FILE",
                        help="Write interactive HTML report to FILE and open in browser "
                             "(keeps a local server running so you can deploy from the UI)")
    deploy.add_argument("--report-port", type=int, default=7777, metavar="PORT",
                        help="Local port for the HTML report deploy server (default: 7777)")
    deploy.add_argument("--include-low-confidence", action="store_true",
                        help="Include low-confidence detectors (heuristic-based)")
    deploy.add_argument("--state-file", type=Path, default=STATE_FILE,
                        help="Path to provisioner state file (default: data/provisioned_state.json)")
    deploy.add_argument("--force-reprovision", action="store_true",
                        help="Re-provision even if service is already in state")
    deploy.add_argument("--reconcile", action="store_true",
                        help="Diff existing detectors against current templates and update only changed ones")
    deploy.add_argument("--notify", metavar="INTEGRATION_ID", action="append", default=[],
                        help="Splunk Observability integration ID to notify on alert "
                             "(repeat for multiple, e.g. --notify abc123 --notify def456). "
                             "Find integration IDs at Settings > Integrations.")

    lifecycle = parser.add_argument_group("lifecycle")
    lifecycle.add_argument("--retune", action="store_true",
                           help="Retune existing detectors based on updated baseline")
    lifecycle.add_argument("--mute", type=int, metavar="MINUTES",
                           help="Mute detectors for SERVICE for N minutes")
    lifecycle.add_argument("--unmute", action="store_true",
                           help="Remove muting rules for SERVICE")
    lifecycle.add_argument("--list-mutes", action="store_true",
                           help="List all active muting rules")
    lifecycle.add_argument("--delete", action="store_true",
                           help="Delete all detectors for SERVICE and remove from state (use for cleanup/reset)")
    lifecycle.add_argument("--archive", action="store_true",
                           help="Archive SERVICE — delete its detectors and mark decommissioned")
    lifecycle.add_argument("--archive-stale", action="store_true",
                           help="Scan for services not seen in --stale-days and archive them")
    lifecycle.add_argument("--status", action="store_true",
                           help="Show all provisioned services, their detectors, and current state")
    lifecycle.add_argument("--audit", action="store_true",
                           help="Audit detector effectiveness — show alert event rates and noisy/silent detectors")
    lifecycle.add_argument("--stale-days", type=float, default=7.0, metavar="N",
                           help="Days of inactivity before a service is considered stale (default: 7)")

    watch = parser.add_argument_group("watch mode")
    watch.add_argument("--watch", action="store_true",
                       help="Run continuously — auto-provision new services and retune on drift")
    watch.add_argument("--poll-interval", type=int, default=60, metavar="MINUTES",
                       help="Polling interval in watch mode (default: 60m)")
    watch.add_argument("--retune-interval-days", type=float, default=7.0,
                       help="Days between forced retune in watch mode (default: 7)")
    watch.add_argument("--auto-archive", action="store_true",
                       help="Automatically archive stale services in watch mode")

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

    state = ProvisionerState(args.state_file)
    dry_run = not args.auto_deploy

    # ── Lifecycle commands (don't provision) ─────────────────────────────────

    if args.status:
        services = state.all_services()
        if not services:
            print("No services provisioned yet.")
            return 0
        active = [s for s in services if not s.archived]
        archived = [s for s in services if s.archived]
        print(f"\nPROVISIONED SERVICES ({len(active)} active, {len(archived)} archived)")
        print("─" * 60)
        now = time.time()
        for svc in sorted(services, key=lambda s: (s.archived, f"{s.environment}/{s.service}")):
            status_label = "archived" if svc.archived else ("muted" if svc.is_muted() else "active")
            prov_dt = datetime.datetime.utcfromtimestamp(svc.provisioned_at).strftime("%Y-%m-%d %H:%M UTC")
            retune_dt = (datetime.datetime.utcfromtimestamp(svc.last_retune_at).strftime("%Y-%m-%d %H:%M UTC")
                         if svc.last_retune_at else "never")
            det_ids = svc.detector_ids()
            id_preview = ", ".join(det_ids[:4]) + ("…" if len(det_ids) > 4 else "")
            print(f"\n  {svc.environment}/{svc.service}  [{status_label}]")
            print(f"    Provisioned:  {prov_dt}")
            print(f"    Last retune:  {retune_dt}")
            print(f"    Baseline:     {svc.baseline_hash or 'none'}")
            print(f"    Detectors:    {len(det_ids)}  {id_preview}")
            if svc.is_muted():
                mute_dt = datetime.datetime.utcfromtimestamp(svc.muted_until).strftime("%Y-%m-%d %H:%M UTC")
                print(f"    Muted until:  {mute_dt}")
        print()
        return 0

    if args.audit:
        report = audit_detector_effectiveness(
            realm=args.realm,
            token=args.token,
            state=state,
            environment=args.environment,
        )
        if not report:
            print("No provisioned detectors found to audit.")
            return 0
        noisy = [r for r in report if r["verdict"] == "noisy"]
        silent = [r for r in report if r["verdict"] == "silent"]
        ok = [r for r in report if r["verdict"] == "ok"]
        print(f"\nDETECTOR AUDIT (last 7 days)  — {len(report)} detectors")
        print("─" * 60)
        if noisy:
            print(f"\nNOISY (>{10}/day) — consider widening thresholds:")
            for r in sorted(noisy, key=lambda x: -x["events_per_day"]):
                print(f"  {r['events_per_day']:5.1f}/day  {r['environment']}/{r['service']}  {r['detector_name']}")
        if silent:
            print(f"\nSILENT (0 events) — verify metric data exists:")
            for r in silent:
                print(f"        —  {r['environment']}/{r['service']}  {r['detector_name']}")
        if ok:
            print(f"\nOK ({len(ok)} detectors firing within normal range)")
        print()
        return 0

    if args.list_mutes:
        windows = list_active_mutes(args.realm, args.token, args.environment)
        print(format_mute_list(windows))
        return 0

    if args.mute is not None:
        if not args.service:
            print("ERROR: --mute requires --service", file=sys.stderr)
            return 1
        window = mute_service(
            realm=args.realm, token=args.token,
            service=args.service, environment=args.environment or "",
            duration_minutes=args.mute,
            reason="manual mute via CLI",
            state=state, dry_run=dry_run,
        )
        if window:
            print(f"Muted {args.service} for {args.mute}m (rule id: {window.rule_id})")
        return 0 if window else 1

    if args.unmute:
        if not args.service:
            print("ERROR: --unmute requires --service", file=sys.stderr)
            return 1
        ok = unmute_service(
            realm=args.realm, token=args.token,
            service=args.service, environment=args.environment or "",
            state=state,
        )
        print(f"{'Unmuted' if ok else 'No active mute rules found for'} {args.service}")
        return 0

    if args.delete:
        if not args.service:
            print("ERROR: --delete requires --service", file=sys.stderr)
            return 1
        result = archive_service(
            realm=args.realm, token=args.token,
            service=args.service, environment=args.environment or "",
            state=state, dry_run=dry_run,
            reason="manual delete via --delete flag",
        )
        print(f"\n{'[DRY RUN] Would delete' if dry_run else 'Deleted'} {result.detectors_deleted} "
              f"detectors for {args.service}.")
        if not dry_run and result.action == "archived":
            # Remove from state entirely (unlike archive, --delete allows re-provisioning)
            key = f"{args.environment or ''}/{args.service}"
            state._services.pop(key, None)
            state.save()
            print(f"Removed {args.service} from state — re-run without --delete to re-provision.")
        return 0 if result.action in ("archived", "skipped") else 1

    if args.archive:
        if not args.service:
            print("ERROR: --archive requires --service", file=sys.stderr)
            return 1
        result = archive_service(
            realm=args.realm, token=args.token,
            service=args.service, environment=args.environment or "",
            state=state, dry_run=dry_run,
        )
        print(format_archive_summary([result], dry_run))
        return 0 if result.action in ("archived", "skipped") else 1

    if args.archive_stale:
        results = archive_stale_services(
            realm=args.realm, token=args.token,
            state=state, stale_days=args.stale_days, dry_run=dry_run,
        )
        print(format_archive_summary(results, dry_run))
        return 0

    # ── Watch mode ────────────────────────────────────────────────────────────

    if args.watch:
        config = WatchConfig(
            realm=args.realm,
            token=args.token,
            environment=args.environment,
            poll_interval_minutes=args.poll_interval,
            retune_interval_days=args.retune_interval_days,
            stale_threshold_days=args.stale_days,
            baseline_window_hours=args.baseline_window_hours,
            baseline_dir=args.baseline_dir,
            state_path=args.state_file,
            auto_archive=args.auto_archive,
            dry_run=dry_run,
            include_low_confidence=args.include_low_confidence,
        )
        daemon = WatchDaemon(config)
        daemon.run()
        return 0

    # ── Standard provision / retune flow ─────────────────────────────────────

    mode = "DRY RUN" if dry_run else "AUTO-DEPLOY"
    if args.retune:
        mode = f"RETUNE ({'DRY RUN' if dry_run else 'LIVE'})"

    print(f"\n{'='*60}", file=sys.stderr)
    print(f"Auto-Detector Provisioner  [{mode}]", file=sys.stderr)
    print(f"Realm: {args.realm}  Env: {args.environment or 'all'}  Service: {args.service or 'all'}", file=sys.stderr)
    print(f"{'='*60}\n", file=sys.stderr)

    # Discover services
    print("Discovering services and detecting tech stack...", file=sys.stderr)
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

    total_actioned = 0
    total_failed = 0
    # Accumulate (profile, detectors, baseline) for HTML report
    html_report_data: list[tuple] = []

    for profile in profiles:
        print(f"\nProcessing: {profile.service} (env={profile.environment})", file=sys.stderr)
        detected = profile.stacks + profile.frameworks + profile.libraries
        if detected:
            print(f"  Detected: {', '.join(detected)}", file=sys.stderr)
        else:
            print("  Detected: APM only", file=sys.stderr)

        # ── Retune mode ───────────────────────────────────────────────────────
        if args.retune:
            if not state.is_provisioned(profile.service, profile.environment):
                print(f"  Skipping retune — {profile.service} not provisioned yet", file=sys.stderr)
                continue

            svc_state = state.get(profile.service, profile.environment)
            if svc_state and svc_state.is_muted():
                print(f"  Skipping retune — {profile.service} is currently muted", file=sys.stderr)
                continue

            baseline_path = args.baseline_dir / f"{profile.environment}__{profile.service}.json"
            baseline = load_baseline(baseline_path)
            if not baseline:
                baseline = learn_baseline(
                    realm=args.realm, token=args.token,
                    service=profile.service, environment=profile.environment,
                    window_hours=args.baseline_window_hours,
                    output_dir=args.baseline_dir,
                )

            results = retune_service(
                realm=args.realm, token=args.token,
                service=profile.service, environment=profile.environment,
                new_baseline=baseline, state=state, dry_run=dry_run,
                retune_interval_days=args.retune_interval_days,
            )
            print(format_retune_summary(results, dry_run))
            total_actioned += sum(1 for r in results if r.action == "updated")
            total_failed += sum(1 for r in results if r.action == "failed")
            continue

        # ── Provision mode ────────────────────────────────────────────────────
        if state.is_provisioned(profile.service, profile.environment) and not args.force_reprovision and not args.reconcile:
            print(f"  Already provisioned — skipping (use --force-reprovision or --reconcile to update)", file=sys.stderr)
            continue

        # Learn baseline — always try cache first; only skip API call if --skip-baseline
        baseline = None
        baseline_path = args.baseline_dir / f"{profile.environment}__{profile.service}.json"
        baseline = load_baseline(baseline_path)
        if baseline:
            print(f"  Using cached baseline ({baseline.window_hours}h window)", file=sys.stderr)
        elif not args.skip_baseline:
            print("  Learning baseline...", file=sys.stderr)
            baseline = learn_baseline(
                realm=args.realm, token=args.token,
                service=profile.service, environment=profile.environment,
                window_hours=args.baseline_window_hours,
                output_dir=args.baseline_dir,
            )
            # If service has no telemetry history, borrow from a similar same-env service
            if baseline and not baseline.is_reliable():
                borrowed = find_similar_baseline(
                    service=profile.service,
                    environment=profile.environment,
                    stacks=profile.stacks,
                    baseline_dir=args.baseline_dir,
                )
                if borrowed:
                    print(f"  Baseline: borrowed from similar service in {profile.environment}", file=sys.stderr)
                    baseline = borrowed
        if baseline and baseline.is_reliable():
            err_str = f"{baseline.error_rate_pct:.2f}%" if baseline.error_rate_pct is not None else "n/a"
            print(f"  Baseline: latency={baseline.latency_mean_ms:.1f}ms "
                  f"error_rate={err_str} "
                  f"samples={baseline.sample_count}", file=sys.stderr)
        else:
            print(f"  Baseline: insufficient samples — using fixed thresholds", file=sys.stderr)
            baseline = None

        # Generate (with metric existence probe to drop ghost detectors)
        detectors = generate_detectors(
            profile=profile,
            baseline=baseline,
            include_low_confidence=args.include_low_confidence,
            realm=args.realm,
            token=args.token,
        )
        print(format_dry_run_report(profile, detectors, baseline))

        # Collect for HTML report
        html_report_data.append((profile, detectors, baseline))

        # Deploy or reconcile
        if args.reconcile:
            results = reconcile_detectors(
                realm=args.realm, token=args.token,
                service=profile.service, environment=profile.environment,
                detectors=detectors, dry_run=dry_run,
                notify=args.notify or [],
            )
        else:
            results = deploy_detectors(
                realm=args.realm, token=args.token,
                service=profile.service, environment=profile.environment,
                detectors=detectors, dry_run=dry_run,
                notify=args.notify or [],
            )
        print(format_deploy_summary(results, dry_run))

        # Record in state
        b_hash = baseline_hash(baseline) if baseline else "no-baseline"
        records = [
            DetectorRecord(
                detector_id=r.detector_id or "dry-run",
                detector_name=r.detector_name,
                provisioned_at=time.time(),
                signalflow_hash=signalflow_hash(
                    next((d.signalflow for d in detectors if d.name == r.detector_name), "")
                ),
                threshold_type=next(
                    (d.threshold_type for d in detectors if d.name == r.detector_name), "fixed"
                ),
                tags=next((d.tags for d in detectors if d.name == r.detector_name), []),
            )
            for r in results if r.success
        ]
        if not dry_run:
            b_snapshot = {
                "latency_mean_ms": baseline.latency_mean_ms if baseline else None,
                "latency_p95_ms": baseline.latency_p95_ms if baseline else None,
                "latency_p99_ms": baseline.latency_p99_ms if baseline else None,
                "latency_stddev_ms": baseline.latency_stddev_ms if baseline else None,
                "error_rate_pct": baseline.error_rate_pct if baseline else None,
                "error_rate_stddev_pct": baseline.error_rate_stddev_pct if baseline else None,
                "sample_count": baseline.sample_count if baseline else 0,
            }
            state.record_provision(
                service=profile.service,
                environment=profile.environment,
                baseline_hash=b_hash,
                detector_records=records,
                baseline_snapshot=b_snapshot,
            )

        total_actioned += sum(1 for r in results if r.success)
        total_failed += sum(1 for r in results if not r.success)

    # ── HTML report ───────────────────────────────────────────────────────────
    if args.html_report and html_report_data:
        report_path = Path(args.html_report)
        generated_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        # Build detector lookup maps for the deploy server
        detector_map: dict[str, object] = {}
        detector_context: dict[str, tuple[str, str]] = {}
        for profile, dets, _ in html_report_data:
            for det in dets:
                did = _det_id(profile.service, det.name)
                detector_map[did] = det
                detector_context[did] = (profile.service, profile.environment)

        html_content = generate_html_report(
            profiles_detectors=html_report_data,
            realm=args.realm,
            environment=args.environment or "all",
            generated_at=generated_at,
            server_port=args.report_port,
            dry_run=dry_run,
        )
        report_path.write_text(html_content, encoding="utf-8")
        print(f"\nHTML report written to: {report_path}", file=sys.stderr)

        server = ReportServer(
            realm=args.realm,
            token=args.token,
            detector_map=detector_map,
            detector_context=detector_context,
            report_path=report_path,
            port=args.report_port,
            notify=args.notify or None,
        )
        server.start()
        server.open_browser()
        print(f"Deploy server running on http://127.0.0.1:{args.report_port}", file=sys.stderr)
        print("Use the 'Deploy Selected' button in the report to deploy detectors.", file=sys.stderr)
        print("Press Ctrl-C to stop.\n", file=sys.stderr)
        server.wait()

    # ── Final summary ─────────────────────────────────────────────────────────
    print(f"\n{'='*60}", file=sys.stderr)
    if args.retune:
        print(f"Retuned {total_actioned} detectors across {len(profiles)} service(s)", file=sys.stderr)
    else:
        action = "Would create" if dry_run else "Created"
        print(f"{action} {total_actioned} detectors across {len(profiles)} service(s)", file=sys.stderr)
    if total_failed:
        print(f"Failed: {total_failed}", file=sys.stderr)
    if dry_run and not args.retune:
        print("\nRun with --auto-deploy to create these detectors.", file=sys.stderr)
    print(f"{'='*60}\n", file=sys.stderr)

    return 0 if total_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
