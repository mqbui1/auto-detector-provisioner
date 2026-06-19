"""
Local HTTP server that serves the HTML report and handles Deploy POSTs.

When provision.py runs with --html-report, it:
  1. Generates the HTML report (with all detector data + server port embedded)
  2. Writes it to a temp file and opens it in the browser
  3. Starts this server, which stays alive to handle deploy requests

The server has two endpoints:
  GET  /          → redirect to the report file (so browser refresh works)
  POST /deploy    → deploy the selected detectors and return JSON results
  GET  /ping      → health check (used by JS to confirm server is up)
"""
from __future__ import annotations

import json
import logging
import os
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from templates.apm import DetectorTemplate
from .detector_deployer import deploy_detectors, DeployResult
from .html_report import _det_id

logger = logging.getLogger(__name__)

# CORS headers so the browser page (file://) can POST to localhost
_CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}


class _Handler(BaseHTTPRequestHandler):
    # Injected by ReportServer before starting
    realm: str = ""
    token: str = ""
    notify: list[str] = []
    # {det_id: DetectorTemplate}
    detector_map: dict[str, DetectorTemplate] = {}
    # {det_id: (service, environment)}
    detector_context: dict[str, tuple[str, str]] = {}
    report_path: Path | None = None

    def log_message(self, fmt: str, *args: Any) -> None:  # silence default access log
        logger.debug("report_server: " + fmt, *args)

    def _send_json(self, code: int, data: dict) -> None:
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in _CORS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        for k, v in _CORS.items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self) -> None:
        if self.path in ("/ping", "/ping/"):
            self._send_json(200, {"ok": True})
            return
        # Serve the report HTML directly so browser refresh works
        if self.report_path and self.report_path.exists():
            body = self.report_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for k, v in _CORS.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
        else:
            self._send_json(404, {"error": "report not found"})

    def do_POST(self) -> None:
        if self.path not in ("/deploy", "/deploy/"):
            self._send_json(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
        except Exception:
            self._send_json(400, {"error": "invalid JSON"})
            return

        selected_ids: list[str] = payload.get("selected") or []
        if not selected_ids:
            self._send_json(400, {"error": "no detectors selected"})
            return

        # Group selected detectors by (service, environment)
        by_svc: dict[tuple[str, str], list[DetectorTemplate]] = {}
        unknown = []
        for det_id in selected_ids:
            det = self.detector_map.get(det_id)
            ctx = self.detector_context.get(det_id)
            if det and ctx:
                by_svc.setdefault(ctx, []).append(det)
            else:
                unknown.append(det_id)

        all_results = []
        for (service, environment), dets in by_svc.items():
            results = deploy_detectors(
                realm=self.realm,
                token=self.token,
                service=service,
                environment=environment,
                detectors=dets,
                dry_run=False,
                notify=self.notify or None,
            )
            for r in results:
                all_results.append({
                    "name": r.detector_name,
                    "success": r.success,
                    "detector_id": r.detector_id,
                    "error": r.error,
                })

        for uid in unknown:
            all_results.append({
                "name": uid,
                "success": False,
                "detector_id": None,
                "error": "detector not found in session — re-run provision.py",
            })

        succeeded = sum(1 for r in all_results if r["success"])
        message = f"Done: {succeeded}/{len(all_results)} detectors deployed successfully."
        self._send_json(200, {"results": all_results, "message": message})


class ReportServer:
    """
    Thin wrapper around HTTPServer. Call start() to launch in a background
    thread and open_browser() to open the report in the default browser.
    """

    def __init__(
        self,
        realm: str,
        token: str,
        detector_map: dict[str, DetectorTemplate],
        detector_context: dict[str, tuple[str, str]],
        report_path: Path,
        port: int = 7777,
        notify: list[str] | None = None,
    ) -> None:
        self.port = port
        self.report_path = report_path

        # Patch class-level attributes on the handler
        _Handler.realm = realm
        _Handler.token = token
        _Handler.notify = notify or []
        _Handler.detector_map = detector_map
        _Handler.detector_context = detector_context
        _Handler.report_path = report_path

        HTTPServer.allow_reuse_address = True
        self._server = HTTPServer(("127.0.0.1", port), _Handler)

    def start(self) -> None:
        t = threading.Thread(target=self._server.serve_forever, daemon=True)
        t.start()
        logger.info("report_server: listening on http://127.0.0.1:%d", self.port)

    def open_browser(self) -> None:
        # Open file:// for instant load; server handles /deploy POST separately
        webbrowser.open(self.report_path.resolve().as_uri())

    def wait(self) -> None:
        """Block until Ctrl-C."""
        try:
            self._server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self._server.shutdown()
