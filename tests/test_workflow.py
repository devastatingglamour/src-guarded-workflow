from __future__ import annotations

import hashlib
import io
import json
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

import yaml


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'scripts'))
import guarded_http  # noqa: E402
PYTHON = sys.executable
TEST_TMP = PROJECT / '.test-tmp'
TEST_TMP.mkdir(exist_ok=True)


def run_script(name: str, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [PYTHON, str(PROJECT / "scripts" / name), *args],
        cwd=PROJECT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )


def make_scope(path: Path, port: int, *, methods: list[str] | None = None) -> None:
    scope = {
        "version": 1,
        "program": {
            "name": "test-src",
            "platform": "test-platform",
            "policy_url": "https://example.com/policy",
            "contact": "security@example.com",
            "authorization_source": "test-only",
        },
        "authorization_confirmed": True,
        "scope": {
            "allowed_hosts": ["127.0.0.1"],
            "denied_hosts": [],
            "allowed_ports": [port],
            "allowed_paths": ["/"],
            "denied_paths": ["/admin"],
            "allowed_methods": methods or ["GET", "HEAD", "OPTIONS"],
        },
        "rate_limit": {
            "requests_per_second": 50,
            "max_requests_per_run": 50,
            "timeout_seconds": 5,
            "max_redirects": 2,
        },
        "accounts": [],
        "data": {
            "save_response_body_default": False,
            "redact_headers": ["cookie", "authorization", "set-cookie"],
            "allow_real_user_data": False,
            "retain_evidence_days": 0,
        },
        "ai": {"autonomous_execution_allowed": False, "human_verification_required": True},
        "approval": {"token_env": "SRC_APPROVAL_TOKEN", "required_operations": ["POST", "auth_flow"]},
    }
    path.write_text(yaml.safe_dump(scope, sort_keys=False), encoding="utf-8")


def make_run(tmp: Path, scope: Path) -> Path:
    result = run_script("new_run.py", "--scope", str(scope), "--program", "test-src", "--output-root", str(tmp / "runs"))
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return Path(result.stdout.strip())


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://example.invalid/")
            self.end_headers()
            return
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        body = b"posted"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002
        return


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_scope_allows_localhost_and_denies_path(self):
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as tmp:
            scope_path = Path(tmp) / "scope.yaml"
            make_scope(scope_path, self.port)
            allowed = run_script(
                "check_scope.py", "--scope", str(scope_path), "--url", f"http://127.0.0.1:{self.port}/"
            )
            denied = run_script(
                "check_scope.py", "--scope", str(scope_path), "--url", f"http://127.0.0.1:{self.port}/admin"
            )
            self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)
            self.assertEqual(denied.returncode, 2, denied.stdout + denied.stderr)

    def test_dry_run_does_not_send_request(self):
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as tmp:
            scope_path = Path(tmp) / "scope.yaml"
            make_scope(scope_path, self.port)
            result = run_script(
                "guarded_http.py",
                "--scope",
                str(scope_path),
                "--url",
                f"http://127.0.0.1:{self.port}/",
                "--method",
                "GET",
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('"mode": "dry-run"', result.stdout)

    def test_write_requires_approval(self):
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as tmp:
            scope_path = Path(tmp) / "scope.yaml"
            make_scope(scope_path, self.port, methods=["GET", "POST"])
            run_dir = make_run(Path(tmp), scope_path)
            result = run_script(
                "guarded_http.py",
                "--scope",
                str(scope_path),
                "--url",
                f"http://127.0.0.1:{self.port}/",
                "--method",
                "POST",
                "--run-dir",
                str(run_dir),
                "--execute",
            )
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("human approval token", result.stderr)

    def test_guarded_get_records_evidence(self):
        class FakeResponse:
            status = 200
            headers = {"Content-Type": "text/plain"}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self, limit):
                return b"ok"

        class FakeOpener:
            def open(self, request, timeout):
                return FakeResponse()

        with tempfile.TemporaryDirectory(dir=TEST_TMP) as tmp:
            scope_path = Path(tmp) / "scope.yaml"
            make_scope(scope_path, self.port)
            run_dir = make_run(Path(tmp), scope_path)
            argv = [
                "guarded_http.py",
                "--scope",
                str(scope_path),
                "--url",
                f"http://127.0.0.1:{self.port}/",
                "--method",
                "GET",
                "--run-dir",
                str(run_dir),
                "--execute",
                "--save-body",
            ]
            output = io.StringIO()
            with mock.patch.object(guarded_http, "build_opener", return_value=FakeOpener()), mock.patch.object(sys, "argv", argv), redirect_stdout(output):
                code = guarded_http.main()
            self.assertEqual(code, 0, output.getvalue())
            data = json.loads(output.getvalue())
            self.assertEqual(data["status"], 200)
            self.assertTrue((run_dir / data["evidence"]).is_file())
            self.assertTrue((run_dir / data["response_body"]).is_file())

    def test_out_of_scope_redirect_is_blocked(self):
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as tmp:
            scope_path = Path(tmp) / "scope.yaml"
            make_scope(scope_path, self.port)
            scope = guarded_http.load_scope(scope_path)
            handler = guarded_http.GuardedRedirectHandler(scope, 2)
            request = SimpleNamespace(full_url=f"http://127.0.0.1:{self.port}/redirect", get_method=lambda: "GET")
            with self.assertRaises(guarded_http.ScopeError):
                handler.redirect_request(request, None, 302, "Found", {}, "http://example.invalid/")

    def test_verified_finding_and_report_render(self):
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as tmp:
            scope_path = Path(tmp) / "scope.yaml"
            make_scope(scope_path, self.port)
            run_dir = make_run(Path(tmp), scope_path)
            evidence = run_dir / "evidence" / "proof.txt"
            evidence.write_text("test-only evidence", encoding="utf-8")
            digest = hashlib.sha256(evidence.read_bytes()).hexdigest()
            finding = {
                "schema_version": 1,
                "finding_id": "finding-001",
                "program": "test-src",
                "title": "Test-only verified finding",
                "asset": f"http://127.0.0.1:{self.port}/",
                "method": "GET",
                "vulnerability_class": "authorization",
                "status": "verified",
                "severity": "medium",
                "confidence": "high",
                "in_scope": True,
                "human_verified": True,
                "ai_generated": True,
                "data_sensitivity": "synthetic",
                "real_user_data_approved": False,
                "summary": "Test-only summary.",
                "preconditions": ["A test account is available."],
                "reproduction_steps": ["Send the recorded request.", "Observe the recorded response."],
                "evidence": [{
                    "type": "log",
                    "path": "evidence/proof.txt",
                    "description": "Test-only evidence",
                    "sha256": digest,
                    "timestamp": "2026-01-01T00:00:00Z",
                }],
                "impact": "Test-only impact.",
                "remediation": "Test-only remediation.",
                "reviewer": {"reviewer": "unit-test", "status": "passed", "notes": "Synthetic test only."},
            }
            finding_path = run_dir / "candidates" / "finding-001.json"
            finding_path.write_text(json.dumps(finding), encoding="utf-8")
            validation = run_script(
                "validate_finding.py", "--finding", str(finding_path), "--run-dir", str(run_dir)
            )
            self.assertEqual(validation.returncode, 0, validation.stdout + validation.stderr)
            rendered = run_script(
                "render_report.py", "--finding", str(finding_path), "--run-dir", str(run_dir)
            )
            self.assertEqual(rendered.returncode, 0, rendered.stdout + rendered.stderr)
            report_path = Path(rendered.stdout.strip())
            self.assertTrue(report_path.is_file())
            self.assertIn("DRAFT FOR HUMAN REVIEW", report_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()


