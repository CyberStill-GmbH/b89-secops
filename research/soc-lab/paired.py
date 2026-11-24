"""Comparaciones pareadas (mismas semillas = mismo tráfico) sobre los CSV de run-all.ts.

python research/soc-lab/paired.py
"""
import csv
import math
import statistics as st
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
OUT = Path(__file__).parent / "out"


def load(name, key):
    rows = list(csv.DictReader((OUT / name).open(encoding="utf-8")))
    grouped = {}
    for row in rows:
        grouped.setdefault(key(row), {})[int(row["semilla"])] = row
    return grouped


def paired(a, b, field, scale=1.0):
    diffs = [(float(a[s][field]) - float(b[s][field])) * scale for s in a]
    mean = st.mean(diffs)
    ci = 1.96 * st.stdev(diffs) / math.sqrt(len(diffs))
    wins = sum(d > 0 for d in diffs)
    return f"{mean:+.2f} ± {ci:.2f} (>0 en {wins}/{len(diffs)})"


e1 = load("e1-riesgo-cobertura.csv", lambda r: r["politica"])
print("| A − B | Δ cobertura (pp) | Δ TP suprimidos | Δ inseguros activos |")
print("|---|---:|---:|---:|")
for a, b in [
    ("jerárquica q=0.97", "conteo N=5"),
    ("jerárquica q=0.97", "conteo N=10"),
    ("CP q=0.97", "conteo N=5"),
    ("CP q=0.95", "conteo N=20"),
    ("jerárquica q=0.99", "CP q=0.97"),
]:
    print(
        f"| {a} − {b} | {paired(e1[a], e1[b], 'cobertura', 100)} | "
        f"{paired(e1[a], e1[b], 'tp_suprimidos')} | {paired(e1[a], e1[b], 'patrones_inseguros_activos')} |"
    )

e2 = load("e2-muestreo.csv", lambda r: (r["politica"], r["muestreo"]))
print()
print("| Política | Δ ataque suprimido (adaptativo − uniforme) |")
print("|---|---:|")
for policy in ["conteo N=5", "CP q=0.97"]:
    adaptive = e2[(policy, "adaptativo 10 % (piso 2 %)")]
    uniform = e2[(policy, "uniforme 10 %")]
    print(f"| {policy} | {paired(adaptive, uniform, 'ataque_suprimidos')} |")
