"""Bounded surface-discovery helpers for the SRC MCP server."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import socket
from typing import Any
from urllib.parse import urljoin, urlsplit

from scope_rules import evaluate_url


def _server():
    import src_guarded_mcp
    return src_guarded_mcp


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def approval_hint(run_id: str, method: str, risk: str, url: str, max_uses: int) -> dict[str, Any]:
    return {
        "ok": True,
        "status": "approval_required",
        "run_id": run_id,
        "suggested_request": {
            "run_id": run_id,
            "method": method,
            "risk": risk,
            "url": url,
            "reason": f"Approve bounded {risk} operation for the in-scope test asset.",
            "max_uses": max_uses,
        },
        "message": "Call src_request_approval, ask the human to reply APPROVE <code>, then call src_confirm_approval before retrying.",
    }


def js_inventory(args: dict[str, Any]) -> dict[str, Any]:
    server = _server()
    run_dir, run_meta = server.load_run(str(args.get("run_id", "")))
    scope = server.load_scope_for_run(run_dir, run_meta)
    asset = str(args.get("asset") or run_meta.get("asset", ""))
    decision = evaluate_url(scope, asset, "GET")
    if not decision.allowed:
        return {"ok": False, "status": "asset_not_in_scope", "message": decision.reason}
    max_assets = max(1, min(int(args.get("max_assets", 10)), 20))
    approval_code = str(args.get("approval_code", "")).strip()
    if not approval_code:
        return approval_hint(str(run_meta.get("run_id")), "GET", "js_inventory", asset, max_assets + 1)
    first = server.guarded_http({
        "run_id": run_meta["run_id"],
        "url": asset,
        "method": "GET",
        "risk": "js_inventory",
        "execute": True,
        "save_body": True,
        "approval_code": approval_code,
        "approval_note": str(args.get("approval_note", "bounded JS inventory")),
    })
    if first.get("status") != "request_complete":
        return first
    first_result = first.get("result") or {}
    page_body_path = first_result.get("response_body")
    if not page_body_path:
        return {"ok": False, "status": "no_page_body", "message": "Baseline response body was not saved"}
    page_text = (run_dir / str(page_body_path)).read_bytes().decode("utf-8", errors="replace")
    base_host = urlsplit(asset).hostname
    refs: set[str] = set()
    patterns = [
        r'<script[^>]+src=["\']([^"\']+)',
        r'<link[^>]+href=["\']([^"\']+)',
        r'<form[^>]+action=["\']([^"\']+)',
        r'fetch\(["\']([^"\']+)',
        r'axios\.[a-z]+\(["\']([^"\']+)',
    ]
    for pattern in patterns:
        for ref in re.findall(pattern, page_text, flags=re.IGNORECASE):
            target = urljoin(asset, ref)
            if urlsplit(target).hostname == base_host and evaluate_url(scope, target, "GET").allowed:
                refs.add(target)
    js_urls = [url for url in sorted(refs) if urlsplit(url).path.lower().endswith(".js")][:max_assets]
    endpoints: set[str] = set()
    source_maps: set[str] = set()
    warnings: list[str] = []
    js_records: list[dict[str, Any]] = []
    for js_url in js_urls:
        fetched = server.guarded_http({
            "run_id": run_meta["run_id"],
            "url": js_url,
            "method": "GET",
            "risk": "js_inventory",
            "execute": True,
            "save_body": True,
            "approval_code": approval_code,
            "approval_note": str(args.get("approval_note", "bounded JS asset inventory")),
        })
        js_records.append({"url": js_url, "status": fetched.get("status"), "result": fetched.get("result")})
        if fetched.get("status") != "request_complete":
            warnings.append(f"JS fetch failed or approval exhausted: {js_url}")
            continue
        result = fetched.get("result") or {}
        body_path = result.get("response_body")
        if not body_path:
            continue
        text = (run_dir / str(body_path)).read_bytes().decode("utf-8", errors="replace")
        for match in re.findall(r'["\']((?:/|https?://)[^"\'\s]{1,300})["\']', text):
            target = urljoin(js_url, match)
            if urlsplit(target).hostname == base_host and evaluate_url(scope, target, "GET").allowed:
                endpoints.add(target)
        for match in re.findall(r'[?&]([A-Za-z_][A-Za-z0-9_]{1,40})=', text):
            endpoints.add(f"parameter:{match}")
        for match in re.findall(r'sourceMappingURL=([^\s*]+)', text):
            target = urljoin(js_url, match)
            if urlsplit(target).hostname == base_host and evaluate_url(scope, target, "GET").allowed:
                source_maps.add(target)
    record = {
        "timestamp": _now(),
        "asset": asset,
        "discovered_refs": sorted(refs),
        "js_assets": js_urls,
        "endpoints": sorted(endpoints),
        "source_maps": sorted(source_maps),
        "warnings": warnings,
    }
    evidence = run_dir / "evidence" / "js-inventory.json"
    evidence.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    with (run_dir / "attack-surface.md").open("a", encoding="utf-8") as handle:
        handle.write(f"\n## JS and endpoint inventory {record['timestamp']}\n\n")
        handle.write(f"- JS assets reviewed: {len(js_urls)}\n")
        handle.write(f"- Endpoints/parameters observed: {len(endpoints)}\n")
        for endpoint in sorted(endpoints)[:100]:
            handle.write(f"- `{endpoint}`\n")
        for warning in warnings:
            handle.write(f"- Warning: {warning}\n")
    return {"ok": True, "status": "js_inventory_complete", "run_id": run_meta["run_id"], "evidence": str(evidence), "record": record, "js_records": js_records}

def import_har(args: dict[str, Any]) -> dict[str, Any]:
    server = _server()
    run_dir, run_meta = server.load_run(str(args.get("run_id", "")))
    scope = server.load_scope_for_run(run_dir, run_meta)
    raw_path = Path(str(args.get("har_path", "")))
    har_path = (run_dir / raw_path).resolve() if not raw_path.is_absolute() else raw_path.resolve()
    try:
        har_path.relative_to(run_dir)
    except ValueError:
        return {"ok": False, "status": "har_path_outside_run", "message": "HAR must be stored under the run directory"}
    if not har_path.is_file():
        return {"ok": False, "status": "har_not_found", "message": str(har_path)}
    try:
        har = json.loads(har_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "status": "invalid_har", "message": str(exc)}
    entries = har.get("log", {}).get("entries", []) if isinstance(har, dict) else []
    observed = []
    skipped = []
    for entry in entries:
        request = entry.get("request", {}) if isinstance(entry, dict) else {}
        url = str(request.get("url", ""))
        method = str(request.get("method", "GET")).upper()
        decision = evaluate_url(scope, url, method)
        if not decision.allowed:
            skipped.append({"url": url, "reason": decision.reason})
            continue
        params = []
        for item in request.get("queryString", []) or []:
            params.append(f"query:{item.get('name', '')}")
        post_data = request.get("postData", {}) or {}
        for item in post_data.get("params", []) or []:
            params.append(f"body:{item.get('name', '')}")
        response = entry.get("response", {}) or {}
        observed.append({
            "method": method,
            "url": url,
            "status": response.get("status"),
            "resource_type": entry.get("_resourceType"),
            "parameters": sorted(set(params)),
            "response_size": (response.get("content", {}) or {}).get("size"),
        })
    record = {"timestamp": _now(), "har": str(har_path), "requests": observed, "skipped_out_of_scope": skipped}
    evidence = run_dir / "evidence" / "har-inventory.json"
    evidence.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    with (run_dir / "attack-surface.md").open("a", encoding="utf-8") as handle:
        handle.write(f"\n## Browser/HAR inventory {record['timestamp']}\n\n")
        handle.write(f"- In-scope requests: {len(observed)}\n")
        for item in observed:
            handle.write(f"- `{item['method']} {item['url']}` status={item['status']} params={', '.join(item['parameters']) or 'none'}\n")
    return {"ok": True, "status": "har_imported", "run_id": run_meta["run_id"], "evidence": str(evidence), "record": record}

def path_probe(args: dict[str, Any]) -> dict[str, Any]:
    server = _server()
    run_dir, run_meta = server.load_run(str(args.get("run_id", "")))
    scope = server.load_scope_for_run(run_dir, run_meta)
    base_url = str(args.get("base_url") or run_meta.get("asset", ""))
    paths = [str(item) for item in (args.get("paths") or [])]
    if not paths or len(paths) > 25:
        return {"ok": False, "status": "invalid_path_count", "message": "paths must contain 1-25 entries"}
    method = str(args.get("method", "GET")).upper()
    urls = [urljoin(base_url, item) for item in paths]
    for url in urls:
        decision = evaluate_url(scope, url, method)
        if not decision.allowed:
            return {"ok": False, "status": "path_not_in_scope", "message": f"{url}: {decision.reason}"}
    approval_code = str(args.get("approval_code", "")).strip()
    if not approval_code:
        return approval_hint(str(run_meta.get("run_id")), method, "path_scan", base_url, len(urls))
    results = []
    for url in urls:
        result = server.guarded_http({
            "run_id": run_meta["run_id"],
            "url": url,
            "method": method,
            "risk": "path_scan",
            "execute": True,
            "save_body": False,
            "approval_code": approval_code,
            "approval_note": str(args.get("approval_note", "bounded path probe")),
        })
        results.append({"url": url, "result": result})
        if result.get("status") == "approval_rejected":
            break
    record = {"timestamp": _now(), "base_url": base_url, "method": method, "results": results}
    evidence = run_dir / "evidence" / "path-probe.json"
    evidence.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    with (run_dir / "attack-surface.md").open("a", encoding="utf-8") as handle:
        handle.write(f"\n## Bounded path probe {record['timestamp']}\n\n")
        for item in results:
            handle.write(f"- `{method} {item['url']}`\n")
    return {"ok": True, "status": "path_probe_complete", "run_id": run_meta["run_id"], "evidence": str(evidence), "record": record}


def port_probe(args: dict[str, Any]) -> dict[str, Any]:
    server = _server()
    run_dir, run_meta = server.load_run(str(args.get("run_id", "")))
    scope = server.load_scope_for_run(run_dir, run_meta)
    asset = str(run_meta.get("asset", ""))
    host = urlsplit(asset).hostname or ""
    ports = [int(item) for item in (args.get("ports") or [])]
    if not ports or len(ports) > 20:
        return {"ok": False, "status": "invalid_port_count", "message": "ports must contain 1-20 entries"}
    allowed_ports = {int(item) for item in scope.get("scope", {}).get("allowed_ports", [])}
    forbidden = [port for port in ports if port not in allowed_ports]
    if forbidden:
        return {"ok": False, "status": "port_not_in_scope", "message": f"Ports not allowed by scope: {forbidden}"}
    approval_code = str(args.get("approval_code", "")).strip()
    if not approval_code:
        return approval_hint(str(run_meta.get("run_id")), "PORT", "port_scan", asset, len(ports))
    timeout = float(scope.get("rate_limit", {}).get("timeout_seconds", 5))
    results = []
    for port in ports:
        ok, message = server.consume_approval(run_dir, approval_code, "PORT", asset, "port_scan")
        if not ok:
            results.append({"port": port, "open": False, "error": message})
            break
        started = __import__("time").time()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                elapsed = round((__import__("time").time() - started) * 1000, 2)
                results.append({"port": port, "open": True, "elapsed_ms": elapsed})
        except OSError as exc:
            elapsed = round((__import__("time").time() - started) * 1000, 2)
            results.append({"port": port, "open": False, "elapsed_ms": elapsed, "error": str(exc)})
    record = {"timestamp": _now(), "host": host, "ports": results}
    evidence = run_dir / "evidence" / "port-probe.json"
    evidence.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    with (run_dir / "attack-surface.md").open("a", encoding="utf-8") as handle:
        handle.write(f"\n## Bounded port probe {record['timestamp']}\n\n")
        for item in results:
            handle.write(f"- port {item['port']}: {'open' if item['open'] else 'closed/filtered'}\n")
    return {"ok": True, "status": "port_probe_complete", "run_id": run_meta["run_id"], "evidence": str(evidence), "record": record}

