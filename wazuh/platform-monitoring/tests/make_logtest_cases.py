#!/usr/bin/env python3
"""Generate logtest-cases.jsonl + logtest-expected.txt (``<rule id>:<level>`` per line).

Synthetic data only (RFC 5737 / .example). Run after changing the rules:
    python wazuh/platform-monitoring/tests/make_logtest_cases.py
"""

import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
T = "2026-11-08T06:00:00Z"


def health(check, status="problem", severity="warning", **extra):
    h = {"check": check, "status": status, "severity": severity, "source": extra.pop("source", "snyk"),
         "key": f"{check}:x", "summary": f"caso sintético {check}"}
    h.update(extra)
    return {"b89": {"vendor": "b89-platform", "source": "monitor", "event_type": "health", "collected_at": T, "health": h}}


def canary(vendor, source="b89-canary"):
    return {"b89": {"vendor": vendor, "source": source, "event_type": "canary", "collected_at": T,
                    "canary": {"id": f"b89-canary-{vendor}-20261108T060000Z-abc123", "pipeline": vendor,
                               "label": "sintético/canary · no requiere acción", "injected_at": T}}}


def snyk(severity, priority=None, mature=False, status="open"):
    event = {"b89": {"vendor": "snyk", "source": "issues", "event_type": "issue", "collected_at": T},
             "snyk": {"issue": {"id": "00000000-0000-4000-8000-000000000001", "title": "Synthetic issue",
                                "status": status, "severity": severity, "ignored": "false",
                                "exploit_maturity": "Mature" if mature else "No Known Exploit",
                                "fixable": "false", "problems": ["CVE-2021-44228", "SNYK-JAVA-0000"]},
                      "org_id": "org", "project": {"id": "p1", "name": "demo/app.example"}}}
    if priority:
        event["b89"]["vuln"] = {"priority": priority, "reason": "caso", "cve": "CVE-2021-44228", "kev": "true",
                                "epss": 0.97, "exposed": "false", "fix": "false", "epss_band": "high"}
    return event


def finding(priority, exposed="false"):
    return {"b89": {"vendor": "b89-vulnprio", "source": "wazuh-vd", "event_type": "finding", "collected_at": T,
                    "vuln": {"priority": priority, "previous_priority": "none", "reason": "kev", "cve": "CVE-2021-44228",
                             "kev": "true", "epss": 0.97, "exposed": exposed, "asset": "host.example",
                             "asset_type": "agent", "severity": "High"}}}


def vd(cve, severity):
    return {"vulnerability": {"cve": cve, "status": "Active", "severity": severity,
                              "package": {"name": "pkg-sintetico", "version": "1.0"}, "title": cve}}


CASES = [
    (health("source_status", "ok", "info", source_state="ok"), "101801:3"),
    (health("source_silent", "ok", "info"), "101802:3"),
    (health("source_silent"), "101804:10"),
    (health("collector_failing"), "101805:8"),
    (health("agent_disconnected", source="wazuh", agent_name="srv01.example"), "101806:10"),
    (health("host_disk", component="/"), "101807:12"),
    (health("host_disk", severity="critical", component="/"), "101808:13"),
    (health("indexer_disk", component="node-1"), "101807:12"),
    (health("container_unhealthy", component="b89-shuffle-orborus-1"), "101809:10"),
    (health("container_unhealthy", severity="critical", component="b89-wazuh.manager-1"), "101810:12"),
    (health("indexer_cluster", component="cluster"), "101811:8"),
    (health("indexer_cluster", severity="critical", component="cluster"), "101812:12"),
    (health("ism_error"), "101814:7"),
    (health("cert_expiry", component="edge"), "101815:8"),
    (health("cert_expiry", severity="critical", component="edge"), "101816:12"),
    (health("ingestion_lag"), "101817:9"),
    (health("ingestion_lag", severity="critical"), "101818:11"),
    (health("host_memory"), "101819:8"),
    (health("host_load"), "101819:8"),
    (health("edge_unreachable", severity="critical"), "101820:12"),
    (health("vuln_intel_stale"), "101821:5"),
    (health("canary_missing"), "101822:10"),
    (health("sns_subscription"), "101823:7"),
    (health("monitor_error"), "101824:5"),
    (health("monitor_error", severity="critical"), "101825:10"),
    (health("algo_nuevo"), "101829:5"),
    (canary("bitdefender", "gravityzone"), "101830:3"),
    (canary("snyk", "issues"), "101831:3"),
    (canary("cloudflare", "security"), "101832:3"),
    (canary("aws", "eventbridge"), "101833:3"),
    (canary("b89-platform", "monitor"), "101834:3"),
    (canary("b89-vulnprio", "vulnprio"), "101866:3"),
    ("Nov  8 06:00:00 b89-soc b89-canary: B89 canary b89-canary-agent-20261108T060000Z-abc123 pipeline=agent sintético/canary", "101835:3"),
    (snyk("critical", "P1"), "101850:14"),
    (snyk("critical", "P1", mature=True), "101851:14"),
    (snyk("high", "P1"), "101852:13"),
    (snyk("high", "P1", mature=True), "101853:13"),
    (snyk("medium", "P1"), "101854:12"),
    (snyk("low", "P1"), "101855:12"),
    (snyk("high", "P2"), "101856:11"),
    (snyk("medium", "P2"), "101857:10"),
    (snyk("critical", "P4"), "101858:6"),
    (snyk("high", "P4"), "101859:6"),
    (snyk("high", "P3"), "101455:10"),
    (snyk("critical"), "101456:12"),
    (snyk("critical", "P2"), "101456:12"),
    (finding("P1", "true"), "101861:14"),
    (finding("P1"), "101862:13"),
    (finding("P2"), "101863:10"),
    (finding("P3"), "101864:3"),
    ({"b89": {"vendor": "b89-vulnprio", "source": "summary", "event_type": "summary", "collected_at": T,
              "vuln_summary": {"before_high_or_critical": 40, "after_high_or_critical": 12}}}, "101865:3"),
    (vd("CVE-2021-44228", "Critical"), "101870:14"),
    (vd("CVE-2021-44228", "High"), "101871:13"),
    (vd("CVE-2021-44228", "Medium"), "101872:12"),
    (vd("CVE-2021-44228", "Low"), "101873:12"),
    (vd("CVE-2020-0001", "Critical"), "101874:6"),
    (vd("CVE-2020-0001", "High"), "101875:5"),
    (vd("CVE-2019-0002", "High"), "23505:10"),
]


def main():
    lines = [c if isinstance(c, str) else json.dumps(c, ensure_ascii=False, separators=(",", ":")) for c, _ in CASES]
    (HERE / "logtest-cases.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    (HERE / "logtest-expected.txt").write_text("\n".join(e for _, e in CASES) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(CASES)} casos")


if __name__ == "__main__":
    main()
