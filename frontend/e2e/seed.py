"""Seed a running MIZAR with the synthetic scenarios: python3 e2e/seed.py URL TOKEN SCENARIOS_DIR"""

import json
import sys
import time
import urllib.request
from pathlib import Path

base, token, scenarios = sys.argv[1], sys.argv[2], Path(sys.argv[3])


def call(method: str, path: str, body: bytes | None = None, content_type: str = "application/json") -> object:
    request = urllib.request.Request(f"{base}{path}", data=body, method=method)
    request.add_header("X-MIZAR-Token", token)
    request.add_header("Content-Type", content_type)
    with urllib.request.urlopen(request) as response:  # noqa: S310 (local test server)
        return json.loads(response.read())


def wait(case_id: str) -> None:
    for _ in range(600):
        jobs = call("GET", f"/api/cases/{case_id}/jobs")
        if not any(j["status"] in ("queued", "running") for j in jobs):  # type: ignore[union-attr]
            return
        time.sleep(0.2)
    raise SystemExit("jobs did not finish")


case = call("POST", "/api/cases", json.dumps({"name": "Intrusion at srv01 and DC01", "analyst_name": "R. Analyst", "reference": "INC-2026-0042"}).encode())
case_id = case["case_id"]  # type: ignore[index]
for name in ("linux_intrusion", "web_intrusion", "windows_spray", "network_scan"):
    truth = json.loads((scenarios / name / "ground_truth.json").read_text())
    for spec in truth["files"]:
        query = "&".join(f"{k}={v}" for k, v in {"filename": spec["path"], **spec.get("hints", {})}.items())
        call("POST", f"/api/cases/{case_id}/files?{query}", (scenarios / name / spec["path"]).read_bytes(), "application/octet-stream")
wait(case_id)
call("POST", f"/api/cases/{case_id}/runs", b"{}")
wait(case_id)
print(case_id)
