"""Passive external asset-intelligence providers for authorized SRC work."""

from __future__ import annotations

from datetime import datetime, timezone
import base64
import json
import os
from typing import Any
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from scope_rules import evaluate_url


PROVIDERS = {
    "fofa": ["FOFA_EMAIL", "FOFA_KEY"],
    "shodan": ["SHODAN_API_KEY"],
    "quake": ["QUAKE_API_KEY"],
    "hunter": ["HUNTER_API_KEY"],
    "zoomeye": ["ZOOMEYE_API_KEY"],
    "urlscan": [],
}


def _server():
    import src_guarded_mcp
    return src_guarded_mcp


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def provider_status() -> dict[str, Any]:
    return {
        name: {
            "configured": all(os.getenv(key) for key in keys),
            "env": keys,
        }
        for name, keys in PROVIDERS.items()
    }


def _json_request(url: str, *, headers: dict[str, str] | None = None, data: bytes | None = None) -> Any:
    request = Request(url, headers=headers or {}, data=data, method="POST" if data is not None else "GET")
    with urlopen(request, timeout=15) as response:
        return json.loads(response.read(2_000_000))


def _normalize(source: str, url: str, scope: dict[str, Any], *, ip: str | None = None, port: int | None = None, title: str | None = None, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    if url and not url.startswith(("http://", "https://")):
        url = "https://" + url
    host = urlsplit(url).hostname if url else None
    decision = evaluate_url(scope, url, "GET") if url else None
    return {
        "source": source,
        "url": url,
        "host": host or ip,
        "ip": ip,
        "port": port,
        "title": title,
        "in_scope": bool(decision and decision.allowed),
        "scope_reason": decision.reason if decision else "no URL to evaluate",
        "extra": extra or {},
    }


def _fofa(query: str, limit: int, scope: dict[str, Any]) -> list[dict[str, Any]]:
    email = os.environ["FOFA_EMAIL"]
    key = os.environ["FOFA_KEY"]
    qbase64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
    url = "https://fofa.info/api/v1/search/all?" + urlencode({
        "email": email,
        "key": key,
        "qbase64": qbase64,
        "size": limit,
        "fields": "host,ip,port,domain,title,server,protocol",
    })
    payload = _json_request(url)
    records = []
    for item in payload.get("results", [])[:limit]:
        if isinstance(item, dict):
            host = str(item.get("host", ""))
            records.append(_normalize("fofa", host, scope, ip=item.get("ip"), port=item.get("port"), title=item.get("title"), extra={"domain": item.get("domain"), "server": item.get("server"), "protocol": item.get("protocol")}))
    return records


def _shodan(query: str, limit: int, scope: dict[str, Any]) -> list[dict[str, Any]]:
    url = "https://api.shodan.io/shodan/host/search?" + urlencode({"key": os.environ["SHODAN_API_KEY"], "query": query, "limit": limit})
    payload = _json_request(url)
    records = []
    for item in payload.get("matches", [])[:limit]:
        http = item.get("http", {}) or {}
        host = item.get("hostnames", [None])[0] if item.get("hostnames") else item.get("ip_str")
        records.append(_normalize("shodan", f"https://{host}" if host else "", scope, ip=item.get("ip_str"), port=item.get("port"), title=http.get("title"), extra={"product": item.get("product"), "org": item.get("org")}))
    return records


def _quake(query: str, limit: int, scope: dict[str, Any]) -> list[dict[str, Any]]:
    body = json.dumps({"query": query, "start": 0, "size": limit}).encode("utf-8")
    payload = _json_request("https://quake.360.net/api/v3/search/quake_service", headers={"X-QuakeToken": os.environ["QUAKE_API_KEY"], "Content-Type": "application/json"}, data=body)
    records = []
    for item in (payload.get("data") or [])[:limit]:
        service = item.get("service", {}) or {}
        http = service.get("http", {}) or {}
        host = item.get("ip") or item.get("domain")
        records.append(_normalize("quake", f"https://{host}" if host else "", scope, ip=item.get("ip"), port=item.get("port"), title=http.get("title"), extra={"service": service.get("name")}))
    return records


def _hunter(query: str, limit: int, scope: dict[str, Any]) -> list[dict[str, Any]]:
    url = "https://hunter.qianxin.com/openApi/search?" + urlencode({"api-key": os.environ["HUNTER_API_KEY"], "search": query, "page": 1, "page_size": limit})
    payload = _json_request(url)
    records = []
    for item in ((payload.get("data") or {}).get("arr") or [])[:limit]:
        url_value = item.get("url") or item.get("domain")
        records.append(_normalize("hunter", str(url_value or ""), scope, ip=item.get("ip"), port=item.get("port"), title=item.get("web_title"), extra={"company": item.get("company")}))
    return records


def _zoomeye(query: str, limit: int, scope: dict[str, Any]) -> list[dict[str, Any]]:
    url = "https://api.zoomeye.org/web/search?" + urlencode({"query": query, "page": 1, "pagesize": limit})
    payload = _json_request(url, headers={"API-KEY": os.environ["ZOOMEYE_API_KEY"]})
    records = []
    for item in payload.get("matches", [])[:limit]:
        url_value = item.get("url") or item.get("site")
        records.append(_normalize("zoomeye", str(url_value or ""), scope, ip=item.get("ip"), port=item.get("port"), title=item.get("title"), extra={"domain": item.get("domain")}))
    return records


def _urlscan(query: str, limit: int, scope: dict[str, Any]) -> list[dict[str, Any]]:
    url = "https://urlscan.io/api/v1/search/?" + urlencode({"q": query, "size": limit})
    payload = _json_request(url)
    records = []
    for item in payload.get("results", [])[:limit]:
        page = item.get("page", {}) or {}
        records.append(_normalize("urlscan", str(page.get("url") or ""), scope, extra={"domain": page.get("domain"), "asn": item.get("asn")}))
    return records


PROVIDER_FUNCS = {
    "fofa": _fofa,
    "shodan": _shodan,
    "quake": _quake,
    "hunter": _hunter,
    "zoomeye": _zoomeye,
    "urlscan": _urlscan,
}


def asset_intel(args: dict[str, Any]) -> dict[str, Any]:
    server = _server()
    run_dir, run_meta = server.load_run(str(args.get("run_id", "")))
    scope = server.load_scope_for_run(run_dir, run_meta)
    query = str(args.get("query", "")).strip()
    if not query:
        return {"ok": False, "status": "invalid_query", "message": "query is required"}
    limit = max(1, min(int(args.get("max_results", 20)), 50))
    requested = args.get("providers") or [name for name, keys in PROVIDERS.items() if all(os.getenv(key) for key in keys)]
    if not requested:
        return {"ok": False, "status": "no_providers_configured", "message": "Configure at least one provider API key, or use the public urlscan provider without a key.", "provider_status": provider_status()}
    unknown = [name for name in requested if name not in PROVIDER_FUNCS]
    if unknown:
        return {"ok": False, "status": "unknown_provider", "message": f"Unknown providers: {unknown}", "available": sorted(PROVIDER_FUNCS)}
    missing_config = [
        name for name in requested
        if PROVIDERS.get(name) and not all(os.getenv(key) for key in PROVIDERS[name])
    ]
    if missing_config and len(missing_config) == len(requested):
        return {
            "ok": False,
            "status": "no_providers_configured",
            "message": "None of the requested providers have API keys configured.",
            "missing": missing_config,
            "provider_status": provider_status(),
        }
    results = []
    provider_errors = []
    for name in requested:
        if PROVIDERS.get(name) and not all(os.getenv(key) for key in PROVIDERS[name]):
            provider_errors.append({"provider": name, "error": "missing API credentials"})
            continue
        fn = PROVIDER_FUNCS[name]
        try:
            results.extend(fn(query, limit, scope))
        except Exception as exc:  # noqa: BLE001 - provider failures are reported, not fatal
            provider_errors.append({"provider": name, "error": str(exc)})
    record = {
        "timestamp": _now(),
        "query": query,
        "providers": requested,
        "results": results,
        "provider_errors": provider_errors,
        "note": "Search-engine results are leads. Only in_scope=true assets may be tested.",
    }
    evidence = run_dir / "evidence" / "asset-intel.json"
    evidence.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    with (run_dir / "attack-surface.md").open("a", encoding="utf-8") as handle:
        handle.write(f"\n## External asset intelligence {record['timestamp']}\n\n")
        handle.write(f"- Query: `{query}`\n")
        for item in results:
            handle.write(f"- [{item['source']}] `{item['url'] or item['host']}` in_scope={item['in_scope']}\n")
    return {"ok": True, "status": "asset_intel_complete", "run_id": run_meta["run_id"], "evidence": str(evidence), "record": record, "provider_status": provider_status()}

