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


def snyk(severity, priority=None, mature=False, status="open", project="demo/app.example"):
    event = {"b89": {"vendor": "snyk", "source": "issues", "event_type": "issue", "collected_at": T},
             "snyk": {"issue": {"id": "00000000-0000-4000-8000-000000000001", "title": "Synthetic issue",
                                "status": status, "severity": severity, "ignored": "false",
                                "exploit_maturity": "Mature" if mature else "No Known Exploit",
                                "fixable": "false", "problems": ["CVE-2021-44228", "SNYK-JAVA-0000"]},
                      "org_id": "org", "project": {"id": "p1", "name": project}}}
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
    (health("source_status", "ok", "info", source_state="ok"), "102101:3"),
    (health("source_silent", "ok", "info"), "102102:3"),
    (health("source_silent"), "102104:10"),
    (health("collector_failing"), "102105:8"),
    (health("agent_disconnected", source="wazuh", agent_name="srv01.example"), "102106:10"),
    (health("host_disk", component="/"), "102107:12"),
    (health("host_disk", severity="critical", component="/"), "102108:13"),
    (health("indexer_disk", component="node-1"), "102107:12"),
    (health("container_unhealthy", component="b89-shuffle-orborus-1"), "102109:10"),
    (health("container_unhealthy", severity="critical", component="b89-wazuh.manager-1"), "102110:12"),
    (health("indexer_cluster", component="cluster"), "102111:8"),
    (health("indexer_cluster", severity="critical", component="cluster"), "102112:12"),
    (health("ism_error"), "102114:7"),
    (health("cert_expiry", component="edge"), "102115:8"),
    (health("cert_expiry", severity="critical", component="edge"), "102116:12"),
    (health("ingestion_lag"), "102117:9"),
    (health("ingestion_lag", severity="critical"), "102118:11"),
    (health("host_memory"), "102119:8"),
    (health("host_load"), "102119:8"),
    (health("edge_unreachable", severity="critical"), "102120:12"),
    (health("vuln_intel_stale"), "102121:5"),
    (health("canary_missing"), "102122:10"),
    (health("sns_subscription"), "102123:7"),
    (health("monitor_error"), "102124:5"),
    (health("monitor_error", severity="critical"), "102125:10"),
    (health("algo_nuevo"), "102129:5"),
    (canary("bitdefender", "gravityzone"), "102130:3"),
    (canary("snyk", "issues"), "102131:3"),
    (canary("cloudflare", "security"), "102132:3"),
    (canary("aws", "eventbridge"), "102133:3"),
    (canary("b89-platform", "monitor"), "102134:3"),
    (canary("b89-vulnprio", "vulnprio"), "102166:3"),
    ("Nov  8 06:00:00 b89-soc b89-canary: B89 canary b89-canary-agent-20261108T060000Z-abc123 pipeline=agent sintético/canary", "102135:3"),
    (snyk("critical", "P1"), "102150:14"),
    (snyk("critical", "P1", mature=True), "102151:14"),
    (snyk("high", "P1"), "102152:13"),
    (snyk("high", "P1", mature=True), "102153:13"),
    (snyk("medium", "P1"), "102154:12"),
    (snyk("low", "P1"), "102155:12"),
    (snyk("high", "P2"), "102156:11"),
    (snyk("medium", "P2"), "102157:10"),
    (snyk("critical", "P4"), "102158:6"),
    (snyk("high", "P4"), "102159:6"),
    # Con la calibración de detección cargada (101732-101734): sin KEV/EPSS manda la calibración.
    (snyk("high", "P3"), "101733:7"),
    (snyk("critical"), "101734:10"),
    (snyk("low"), "101732:2"),
    (snyk("critical", "P2"), "102167:12"),
    # Proyecto expuesto (lista b89-internet-facing-projects): la calibración no aplica.
    (snyk("critical", "P3", project="web/portal.example"), "101456:12"),
    (snyk("high", "P1", project="web/portal.example"), "102152:13"),
    (snyk("critical", "P1", mature=True, project="web/portal.example"), "101730:14"),
    (finding("P1", "true"), "102161:14"),
    (finding("P1"), "102162:13"),
    (finding("P2"), "102163:10"),
    (finding("P3"), "102164:3"),
    ({"b89": {"vendor": "b89-vulnprio", "source": "summary", "event_type": "summary", "collected_at": T,
              "vuln_summary": {"before_high_or_critical": 40, "after_high_or_critical": 12}}}, "102165:3"),
    (vd("CVE-2021-44228", "Critical"), "102170:14"),
    (vd("CVE-2021-44228", "High"), "102171:13"),
    (vd("CVE-2021-44228", "Medium"), "102172:12"),
    (vd("CVE-2021-44228", "Low"), "102173:12"),
    (vd("CVE-2020-0001", "Critical"), "102174:6"),
    (vd("CVE-2020-0001", "High"), "102175:5"),
    (vd("CVE-2019-0002", "High"), "23505:10"),
]


def main():
    lines = [c if isinstance(c, str) else json.dumps(c, ensure_ascii=False, separators=(",", ":")) for c, _ in CASES]
    (HERE / "logtest-cases.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    (HERE / "logtest-expected.txt").write_text("\n".join(e for _, e in CASES) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(CASES)} casos")


if __name__ == "__main__":
    main()
