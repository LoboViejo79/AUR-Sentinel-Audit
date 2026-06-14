#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AUR Sentinel Audit
Auditoría defensiva para Arch Linux y derivadas compatibles con AUR.

Modo por defecto: solo lectura.
No elimina paquetes, no modifica configuraciones y pregunta antes de instalar herramientas.
"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import html
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich import box
except Exception:
    print("Falta la librería 'rich'. Ejecuta: ./install.sh")
    sys.exit(1)

APP_NAME = "AUR Sentinel Audit"
REPORT_DIR = Path("aur_sentinel_reportes")
REPORT_DIR.mkdir(exist_ok=True)

console = Console()

SUSPICIOUS_PATTERNS = {
    "curl | bash": r"curl\s+.*\|\s*(bash|sh)",
    "wget | sh": r"wget\s+.*\|\s*(bash|sh)",
    "npm install": r"\bnpm\s+install\b",
    "base64 decode": r"base64\s+(-d|--decode)",
    "chmod +x": r"chmod\s+\+x",
    "sudo": r"\bsudo\b",
    "systemctl enable": r"systemctl\s+enable",
    "crontab": r"\bcrontab\b",
    "uso de /tmp": r"(/tmp|/var/tmp)",
    "nc/ncat/socat": r"\b(nc|ncat|socat)\b",
    "python -c": r"python[0-9.]*\s+-c",
    "bash -c": r"bash\s+-c",
    "eval": r"\beval\b",
    "exec": r"\bexec\b",
    "dd": r"\bdd\s+if=",
    "eBPF": r"\b(eBPF|bpftrace|bpftool)\b",
    "rootkit": r"\brootkit\b",
    "descarga remota": r"(https?|ftp)://",
}

RISK_WEIGHTS = {
    "curl | bash": 35,
    "wget | sh": 35,
    "npm install": 15,
    "base64 decode": 25,
    "chmod +x": 10,
    "sudo": 20,
    "systemctl enable": 25,
    "crontab": 25,
    "uso de /tmp": 10,
    "nc/ncat/socat": 30,
    "python -c": 20,
    "bash -c": 20,
    "eval": 25,
    "exec": 10,
    "dd": 20,
    "eBPF": 35,
    "rootkit": 45,
    "descarga remota": 8,
}

RECOMMENDED_TOOLS = ["arch-audit", "bind-tools", "lsof", "nmap", "whois", "git", "curl"]


@dataclass
class CommandResult:
    command: str
    returncode: int
    stdout: str
    stderr: str


def run_cmd(cmd: List[str], timeout: int = 60, sudo: bool = False) -> CommandResult:
    full_cmd = cmd[:]
    if sudo:
        full_cmd = ["sudo"] + full_cmd
    try:
        p = subprocess.run(
            full_cmd,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        return CommandResult(" ".join(full_cmd), p.returncode, p.stdout.strip(), p.stderr.strip())
    except FileNotFoundError:
        return CommandResult(" ".join(full_cmd), 127, "", f"Comando no encontrado: {cmd[0]}")
    except subprocess.TimeoutExpired:
        return CommandResult(" ".join(full_cmd), 124, "", "Tiempo agotado")
    except Exception as e:
        return CommandResult(" ".join(full_cmd), 1, "", str(e))


def which(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def read_file(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def get_os_release() -> Dict[str, str]:
    data = {}
    content = read_file("/etc/os-release")
    for line in content.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k] = v.strip().strip('"')
    return data


def is_arch_like(osr: Dict[str, str]) -> bool:
    joined = " ".join([osr.get("ID", ""), osr.get("ID_LIKE", ""), osr.get("NAME", "")]).lower()
    known = ["arch", "cachyos", "endeavouros", "manjaro", "garuda", "arcolinux"]
    return any(x in joined for x in known) or which("pacman")


def detect_aur_helper() -> str:
    for helper in ["yay", "paru", "trizen", "pikaur", "aura"]:
        if which(helper):
            return helper
    return "solo pacman"


def get_desktop() -> str:
    return os.environ.get("XDG_CURRENT_DESKTOP") or os.environ.get("DESKTOP_SESSION") or "No detectado"


def system_info() -> Dict[str, str]:
    osr = get_os_release()
    hostctl = run_cmd(["hostnamectl"], timeout=10).stdout
    return {
        "app": APP_NAME,
        "fecha": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "usuario": getpass.getuser(),
        "hostname": socket.gethostname(),
        "distro": osr.get("PRETTY_NAME", osr.get("NAME", "Desconocida")),
        "distro_id": osr.get("ID", "desconocida"),
        "arch_like": str(is_arch_like(osr)),
        "kernel": platform.release(),
        "arquitectura": platform.machine(),
        "desktop": get_desktop(),
        "aur_helper": detect_aur_helper(),
        "python": platform.python_version(),
        "hostnamectl": hostctl,
    }


def get_aur_packages() -> List[Dict[str, str]]:
    res = run_cmd(["pacman", "-Qm"], timeout=60)
    packages = []
    if res.returncode != 0 and not res.stdout:
        return packages
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            name, version = parts[0], " ".join(parts[1:])
            qi = run_cmd(["pacman", "-Qi", name], timeout=30)
            install_date = ""
            packager = ""
            for l in qi.stdout.splitlines():
                if l.lower().startswith("install date") or l.lower().startswith("fecha de instalación"):
                    install_date = l.split(":", 1)[-1].strip()
                if l.lower().startswith("packager") or l.lower().startswith("empaquetador"):
                    packager = l.split(":", 1)[-1].strip()
            packages.append({
                "name": name,
                "version": version,
                "install_date": install_date,
                "packager": packager,
            })
    return packages


def aur_rpc_info(pkg_name: str) -> Dict[str, str]:
    url = f"https://aur.archlinux.org/rpc/v5/info/{pkg_name}"
    try:
        req = Request(url, headers={"User-Agent": "AUR-Sentinel-Audit/1.0"})
        with urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8", errors="ignore"))
        if data.get("resultcount", 0) > 0:
            result = data["results"][0]
            return {
                "exists": "sí",
                "maintainer": str(result.get("Maintainer") or "huérfano"),
                "votes": str(result.get("NumVotes", "")),
                "popularity": str(result.get("Popularity", "")),
                "last_modified": dt.datetime.fromtimestamp(result.get("LastModified", 0)).strftime("%Y-%m-%d") if result.get("LastModified") else "",
                "urlpath": "https://aur.archlinux.org" + result.get("URLPath", ""),
            }
        return {"exists": "no", "maintainer": "", "votes": "", "popularity": "", "last_modified": "", "urlpath": ""}
    except Exception as e:
        return {"exists": "error", "maintainer": "", "votes": "", "popularity": "", "last_modified": "", "urlpath": "", "error": str(e)}


def download_pkgbuild(pkg_name: str) -> Tuple[str, str]:
    urls = [
        f"https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={pkg_name}",
        f"https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={pkg_name}-git",
    ]
    for url in urls:
        try:
            req = Request(url, headers={"User-Agent": "AUR-Sentinel-Audit/1.0"})
            with urlopen(req, timeout=15) as r:
                text = r.read().decode("utf-8", errors="ignore")
            if text and "pkgname" in text.lower():
                return text, url
        except Exception:
            continue
    return "", ""


def analyze_pkgbuild_text(text: str) -> Dict:
    hits = []
    score = 0
    for label, pattern in SUSPICIOUS_PATTERNS.items():
        matches = re.findall(pattern, text, flags=re.IGNORECASE)
        if matches:
            score += RISK_WEIGHTS.get(label, 5)
            hits.append({
                "pattern": label,
                "weight": RISK_WEIGHTS.get(label, 5),
                "count": len(matches),
            })
    if score >= 80:
        level = "Crítico"
    elif score >= 50:
        level = "Alto"
    elif score >= 25:
        level = "Medio"
    elif score > 0:
        level = "Bajo"
    else:
        level = "Sin alertas"
    return {"risk_score": score, "risk_level": level, "hits": hits}


def analyze_aur_packages(packages: List[Dict[str, str]], fetch_pkgbuild: bool = True) -> List[Dict]:
    results = []
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TimeElapsedColumn(), console=console) as progress:
        task = progress.add_task("Analizando paquetes AUR...", total=len(packages) or 1)
        for p in packages:
            name = p["name"]
            rpc = aur_rpc_info(name)
            pkgbuild_text = ""
            pkgbuild_url = ""
            analysis = {"risk_score": 0, "risk_level": "No analizado", "hits": []}
            if fetch_pkgbuild and rpc.get("exists") == "sí":
                pkgbuild_text, pkgbuild_url = download_pkgbuild(name)
                if pkgbuild_text:
                    analysis = analyze_pkgbuild_text(pkgbuild_text)
            result = dict(p)
            result.update({
                "aur_exists": rpc.get("exists", ""),
                "maintainer": rpc.get("maintainer", ""),
                "votes": rpc.get("votes", ""),
                "popularity": rpc.get("popularity", ""),
                "last_modified": rpc.get("last_modified", ""),
                "pkgbuild_url": pkgbuild_url,
                "risk_score": analysis["risk_score"],
                "risk_level": analysis["risk_level"],
                "hits": analysis["hits"],
            })
            results.append(result)
            progress.update(task, advance=1)
    return results


def run_arch_audit() -> Dict:
    if not which("arch-audit"):
        return {"installed": False, "output": "arch-audit no está instalado.", "returncode": 127}
    res = run_cmd(["arch-audit"], timeout=120)
    return {"installed": True, "output": res.stdout or res.stderr, "returncode": res.returncode}


def pacman_integrity() -> Dict:
    res = run_cmd(["pacman", "-Qkk"], timeout=180)
    lines = res.stdout.splitlines() + res.stderr.splitlines()
    warnings = [l for l in lines if ("warning:" in l.lower() or "advertencia" in l.lower() or "error:" in l.lower())]
    return {
        "returncode": res.returncode,
        "total_lines": len(lines),
        "warnings": warnings[:300],
        "raw_limited": "\n".join(lines[:500]),
    }


def active_connections() -> Dict:
    connections = []
    res = run_cmd(["ss", "-tunap"], timeout=60)
    raw = res.stdout or res.stderr
    for line in raw.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            state = parts[1] if parts[0].lower() in ["tcp", "udp"] else ""
            local = parts[4] if len(parts) > 4 else ""
            peer = parts[5] if len(parts) > 5 else ""
            proc = " ".join(parts[6:]) if len(parts) > 6 else ""
            connections.append({"raw": line, "state": state, "local": local, "peer": peer, "process": proc})
    return {"command": res.command, "returncode": res.returncode, "connections": connections, "raw_limited": raw[:20000]}


def ports_nmap() -> Dict:
    if not which("nmap"):
        return {"installed": False, "output": "nmap no está instalado."}
    res = run_cmd(["nmap", "-sT", "-O", "127.0.0.1"], timeout=180)
    return {"installed": True, "output": res.stdout or res.stderr, "returncode": res.returncode}


def services_info() -> Dict:
    running = run_cmd(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"], timeout=60)
    enabled = run_cmd(["systemctl", "list-unit-files", "--state=enabled", "--no-pager"], timeout=60)
    return {
        "running": running.stdout or running.stderr,
        "enabled": enabled.stdout or enabled.stderr,
    }


def persistence_checks() -> Dict:
    home = Path.home()
    checks = {}
    cron = run_cmd(["crontab", "-l"], timeout=30)
    checks["crontab"] = cron.stdout or cron.stderr
    autostart = home / ".config" / "autostart"
    checks["autostart_files"] = [str(p) for p in autostart.glob("*")] if autostart.exists() else []
    systemd_dir = Path("/etc/systemd/system")
    checks["systemd_system_files"] = [str(p) for p in systemd_dir.glob("*.service")][:300] if systemd_dir.exists() else []
    tmp_proc = run_cmd(["bash", "-lc", "ps aux | egrep '(/tmp|/var/tmp)' | grep -v egrep"], timeout=30)
    checks["processes_from_tmp"] = tmp_proc.stdout or ""
    return checks


def installed_tools_status() -> Dict[str, bool]:
    return {tool: which(tool) for tool in RECOMMENDED_TOOLS}


def ask_install_tools():
    missing = [t for t, ok in installed_tools_status().items() if not ok]
    if not missing:
        console.print("[green]Todas las herramientas recomendadas parecen estar instaladas.[/green]")
        return
    console.print(f"[yellow]Herramientas faltantes:[/yellow] {', '.join(missing)}")
    if Confirm.ask("¿Deseas instalarlas con pacman? Requiere sudo", default=False):
        cmd = ["pacman", "-S", "--needed"] + missing
        res = run_cmd(cmd, timeout=600, sudo=True)
        console.print(res.stdout)
        if res.stderr:
            console.print(f"[red]{res.stderr}[/red]")


def generate_txt(report: Dict, out: Path):
    lines = []
    lines.append(f"{APP_NAME} - Reporte TXT")
    lines.append("=" * 70)
    lines.append(json.dumps(report.get("system", {}), indent=2, ensure_ascii=False))
    lines.append("\nPAQUETES AUR")
    for p in report.get("aur_analysis", []):
        lines.append(f"- {p.get('name')} {p.get('version')} | Riesgo: {p.get('risk_level')} | Mantenedor: {p.get('maintainer')}")
    lines.append("\nARCH-AUDIT")
    lines.append(report.get("arch_audit", {}).get("output", ""))
    lines.append("\nCONEXIONES")
    for c in report.get("connections", {}).get("connections", [])[:300]:
        lines.append(c.get("raw", ""))
    out.write_text("\n".join(lines), encoding="utf-8")


def esc(x) -> str:
    return html.escape(str(x or ""))


def risk_badge(level: str) -> str:
    cls = {
        "Crítico": "critical",
        "Alto": "high",
        "Medio": "medium",
        "Bajo": "low",
        "Sin alertas": "ok",
        "No analizado": "unknown",
    }.get(level, "unknown")
    return f'<span class="badge {cls}">{esc(level)}</span>'


def general_risk(report: Dict) -> str:
    levels = [p.get("risk_level") for p in report.get("aur_analysis", [])]
    if "Crítico" in levels:
        return "Crítico"
    if "Alto" in levels:
        return "Alto"
    if "Medio" in levels:
        return "Medio"
    if report.get("arch_audit", {}).get("returncode", 0) not in [0, None, 127]:
        return "Medio"
    return "Bajo"


def generate_html(report: Dict, out: Path):
    sysinfo = report.get("system", {})
    aur = report.get("aur_analysis", [])
    connections = report.get("connections", {}).get("connections", [])
    arch_audit = report.get("arch_audit", {})
    integ = report.get("integrity", {})
    services = report.get("services", {})
    persistence = report.get("persistence", {})
    risk = general_risk(report)

    aur_rows = []
    for p in aur:
        hits = ", ".join([h["pattern"] for h in p.get("hits", [])]) or "Sin patrones detectados"
        aur_rows.append(f"""
        <tr>
          <td>{esc(p.get('name'))}</td>
          <td>{esc(p.get('version'))}</td>
          <td>{esc(p.get('aur_exists'))}</td>
          <td>{esc(p.get('maintainer'))}</td>
          <td>{risk_badge(p.get('risk_level'))}</td>
          <td>{esc(p.get('risk_score'))}</td>
          <td>{esc(hits)}</td>
        </tr>
        """)

    conn_rows = []
    for c in connections[:300]:
        conn_rows.append(f"<tr><td>{esc(c.get('state'))}</td><td>{esc(c.get('local'))}</td><td>{esc(c.get('peer'))}</td><td>{esc(c.get('process'))}</td></tr>")

    html_doc = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>{APP_NAME} - Reporte</title>
<style>
:root {{
  --bg:#080d14; --card:#101824; --card2:#131f2e; --text:#e6edf3; --muted:#98a6b3;
  --blue:#1793ff; --red:#ff3131; --yellow:#ffd400; --green:#00d26a; --border:#263445;
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:linear-gradient(135deg,#06090f,#101824); color:var(--text); font-family:Arial, Helvetica, sans-serif; }}
header {{ padding:28px 34px; border-bottom:1px solid var(--border); background:#05080d; }}
h1 {{ margin:0; font-size:34px; letter-spacing:.5px; }}
h1 span {{ color:var(--blue); }}
.subtitle {{ color:var(--muted); margin-top:8px; }}
.container {{ padding:24px 34px; }}
.grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(260px,1fr)); gap:16px; }}
.card {{ background:var(--card); border:1px solid var(--border); border-radius:14px; padding:18px; box-shadow:0 10px 30px rgba(0,0,0,.25); }}
.card h2 {{ margin-top:0; font-size:20px; }}
.kpi {{ font-size:34px; font-weight:800; }}
table {{ width:100%; border-collapse:collapse; margin-top:12px; overflow:hidden; border-radius:12px; }}
th,td {{ border-bottom:1px solid var(--border); padding:10px; text-align:left; vertical-align:top; font-size:14px; }}
th {{ color:#fff; background:#0c1420; }}
pre {{ white-space:pre-wrap; overflow:auto; max-height:420px; background:#05080d; border:1px solid var(--border); padding:14px; border-radius:12px; }}
.badge {{ padding:5px 9px; border-radius:999px; font-weight:700; display:inline-block; }}
.critical {{ background:#4d0000; color:#ffb4b4; border:1px solid #ff3131; }}
.high {{ background:#4d1b00; color:#ffc28a; border:1px solid #ff7a00; }}
.medium {{ background:#4d4100; color:#fff1a8; border:1px solid #ffd400; }}
.low {{ background:#00314d; color:#a6dcff; border:1px solid #1793ff; }}
.ok {{ background:#003a1d; color:#9fffc8; border:1px solid #00d26a; }}
.unknown {{ background:#333; color:#ddd; border:1px solid #666; }}
.footer {{ color:var(--muted); padding:30px 34px; border-top:1px solid var(--border); }}
.warn {{ color:var(--yellow); }}
</style>
</head>
<body>
<header>
  <h1>🛡️ AUR <span>Sentinel</span> Audit</h1>
  <div class="subtitle">Reporte defensivo de auditoría para Arch Linux y derivadas compatibles con AUR</div>
</header>
<div class="container">
  <div class="grid">
    <div class="card"><h2>Riesgo general</h2><div class="kpi">{risk_badge(risk)}</div></div>
    <div class="card"><h2>Distro</h2><div class="kpi">{esc(sysinfo.get('distro'))}</div><p>{esc(sysinfo.get('kernel'))}</p></div>
    <div class="card"><h2>Paquetes AUR</h2><div class="kpi">{len(aur)}</div><p>Detectados con pacman -Qm</p></div>
    <div class="card"><h2>Conexiones</h2><div class="kpi">{len(connections)}</div><p>Detectadas con ss -tunap</p></div>
  </div>

  <div class="card">
    <h2>Resumen del sistema</h2>
    <table>
      <tr><th>Campo</th><th>Valor</th></tr>
      {''.join(f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>" for k,v in sysinfo.items() if k != "hostnamectl")}
    </table>
  </div>

  <div class="card">
    <h2>Paquetes AUR analizados</h2>
    <p class="warn">Nota: un patrón marcado no prueba infección. Indica que debe revisarse manualmente el PKGBUILD.</p>
    <table>
      <tr><th>Paquete</th><th>Versión</th><th>Existe en AUR</th><th>Mantenedor</th><th>Riesgo</th><th>Puntaje</th><th>Motivos</th></tr>
      {''.join(aur_rows)}
    </table>
  </div>

  <div class="card">
    <h2>Resultado arch-audit</h2>
    <pre>{esc(arch_audit.get("output"))}</pre>
  </div>

  <div class="card">
    <h2>Integridad pacman -Qkk</h2>
    <p>Alertas encontradas: {len(integ.get("warnings", []))}</p>
    <pre>{esc("\\n".join(integ.get("warnings", [])) or integ.get("raw_limited", ""))}</pre>
  </div>

  <div class="card">
    <h2>Conexiones activas</h2>
    <table>
      <tr><th>Estado</th><th>Local</th><th>Remoto</th><th>Proceso</th></tr>
      {''.join(conn_rows)}
    </table>
  </div>

  <div class="card">
    <h2>Servicios en ejecución</h2>
    <pre>{esc(services.get("running"))}</pre>
  </div>

  <div class="card">
    <h2>Servicios habilitados al inicio</h2>
    <pre>{esc(services.get("enabled"))}</pre>
  </div>

  <div class="card">
    <h2>Persistencia básica</h2>
    <h3>Crontab</h3><pre>{esc(persistence.get("crontab"))}</pre>
    <h3>Autostart</h3><pre>{esc("\\n".join(persistence.get("autostart_files", [])))}</pre>
    <h3>Procesos desde /tmp o /var/tmp</h3><pre>{esc(persistence.get("processes_from_tmp"))}</pre>
  </div>

  <div class="card">
    <h2>Recomendaciones</h2>
    <ul>
      <li>Prioriza repositorios oficiales antes de instalar desde AUR.</li>
      <li>Revisa siempre el PKGBUILD antes de compilar o instalar.</li>
      <li>Evita paquetes huérfanos o con cambios recientes sospechosos.</li>
      <li>Actualiza el sistema y ejecuta arch-audit periódicamente.</li>
      <li>No elimines paquetes sin verificar dependencias y origen.</li>
      <li>Si detectas actividad sospechosa, desconecta la red y realiza análisis forense.</li>
    </ul>
  </div>
</div>
<div class="footer">
  Generado por {APP_NAME}. Modo solo lectura. Fecha: {esc(sysinfo.get("fecha"))}
</div>
</body>
</html>"""
    out.write_text(html_doc, encoding="utf-8")


def save_report(report: Dict) -> Tuple[Path, Path, Path]:
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = REPORT_DIR / f"aur_sentinel_reporte_{ts}.json"
    txt_path = REPORT_DIR / f"aur_sentinel_reporte_{ts}.txt"
    html_path = REPORT_DIR / f"aur_sentinel_reporte_{ts}.html"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    generate_txt(report, txt_path)
    generate_html(report, html_path)
    return html_path, txt_path, json_path


def quick_scan() -> Dict:
    info = system_info()
    packages = get_aur_packages()
    audit = run_arch_audit()
    conns = active_connections()
    report = {
        "system": info,
        "aur_packages": packages,
        "aur_analysis": [],
        "arch_audit": audit,
        "connections": conns,
        "integrity": {},
        "services": {},
        "persistence": {},
        "tools": installed_tools_status(),
        "scan_type": "rápido",
    }
    return report


def full_scan() -> Dict:
    info = system_info()
    packages = get_aur_packages()
    analysis = analyze_aur_packages(packages, fetch_pkgbuild=True)
    report = {
        "system": info,
        "aur_packages": packages,
        "aur_analysis": analysis,
        "arch_audit": run_arch_audit(),
        "integrity": pacman_integrity(),
        "connections": active_connections(),
        "ports": ports_nmap(),
        "services": services_info(),
        "persistence": persistence_checks(),
        "tools": installed_tools_status(),
        "scan_type": "completo",
    }
    return report


def show_system_header():
    info = system_info()
    title = f"[bold cyan]{APP_NAME}[/bold cyan]\n[white]{info['distro']}[/white] | Kernel {info['kernel']} | AUR helper: {info['aur_helper']}"
    console.print(Panel(title, subtitle=f"{info['usuario']}@{info['hostname']} - {info['fecha']}", border_style="cyan"))


def print_aur_table(packages: List[Dict[str, str]]):
    table = Table(title="Paquetes instalados desde AUR / externos", box=box.SIMPLE_HEAVY)
    table.add_column("Paquete", style="cyan")
    table.add_column("Versión", style="white")
    table.add_column("Fecha instalación", style="yellow")
    table.add_column("Packager", style="magenta")
    for p in packages:
        table.add_row(p.get("name",""), p.get("version",""), p.get("install_date",""), p.get("packager",""))
    console.print(table)


def print_analysis_table(analysis: List[Dict]):
    table = Table(title="Análisis de PKGBUILD", box=box.SIMPLE_HEAVY)
    table.add_column("Paquete", style="cyan")
    table.add_column("Existe AUR")
    table.add_column("Mantenedor")
    table.add_column("Riesgo")
    table.add_column("Motivos")
    for p in analysis:
        hits = ", ".join([h["pattern"] for h in p.get("hits", [])]) or "-"
        table.add_row(p.get("name",""), p.get("aur_exists",""), p.get("maintainer",""), p.get("risk_level",""), hits)
    console.print(table)


def main_menu():
    last_report: Optional[Dict] = None
    while True:
        show_system_header()
        console.print("""
[bold]Menú principal[/bold]
[cyan]1)[/cyan] Escaneo rápido
[cyan]2)[/cyan] Escaneo completo
[cyan]3)[/cyan] Revisar paquetes AUR instalados
[cyan]4)[/cyan] Analizar PKGBUILD de paquetes AUR
[cyan]5)[/cyan] Ver conexiones activas
[cyan]6)[/cyan] Revisar servicios en ejecución
[cyan]7)[/cyan] Revisar puertos abiertos
[cyan]8)[/cyan] Instalar herramientas necesarias
[cyan]9)[/cyan] Generar reporte HTML del último escaneo
[cyan]0)[/cyan] Salir
""")
        choice = Prompt.ask("Selecciona una opción", choices=[str(i) for i in range(10)], default="1")
        if choice == "0":
            console.print("[green]Saliendo.[/green]")
            break
        elif choice == "1":
            last_report = quick_scan()
            html_path, txt_path, json_path = save_report(last_report)
            console.print(f"[green]Escaneo rápido finalizado.[/green]\nHTML: {html_path}\nTXT: {txt_path}\nJSON: {json_path}")
        elif choice == "2":
            if Confirm.ask("El escaneo completo puede tardar varios minutos. ¿Continuar?", default=True):
                last_report = full_scan()
                html_path, txt_path, json_path = save_report(last_report)
                console.print(f"[green]Escaneo completo finalizado.[/green]\nHTML: {html_path}\nTXT: {txt_path}\nJSON: {json_path}")
        elif choice == "3":
            packages = get_aur_packages()
            print_aur_table(packages)
        elif choice == "4":
            packages = get_aur_packages()
            analysis = analyze_aur_packages(packages, fetch_pkgbuild=True)
            print_analysis_table(analysis)
            last_report = {"system": system_info(), "aur_packages": packages, "aur_analysis": analysis, "arch_audit": {}, "connections": {}, "integrity": {}, "services": {}, "persistence": {}, "tools": installed_tools_status(), "scan_type": "pkgbuild"}
        elif choice == "5":
            data = active_connections()
            console.print(Panel(data.get("raw_limited", ""), title="Conexiones activas ss -tunap"))
        elif choice == "6":
            data = services_info()
            console.print(Panel(data.get("running", ""), title="Servicios en ejecución"))
        elif choice == "7":
            data = ports_nmap()
            console.print(Panel(data.get("output", ""), title="Puertos abiertos / nmap localhost"))
        elif choice == "8":
            ask_install_tools()
        elif choice == "9":
            if not last_report:
                console.print("[yellow]No hay escaneo previo. Ejecuta primero opción 1 o 2.[/yellow]")
            else:
                html_path, txt_path, json_path = save_report(last_report)
                console.print(f"[green]Reporte generado.[/green]\nHTML: {html_path}\nTXT: {txt_path}\nJSON: {json_path}")
        input("\nPresiona ENTER para continuar...")


def cli():
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--quick", action="store_true", help="Ejecutar escaneo rápido y generar reporte")
    parser.add_argument("--full", action="store_true", help="Ejecutar escaneo completo y generar reporte")
    parser.add_argument("--no-menu", action="store_true", help="No mostrar menú")
    args = parser.parse_args()

    osr = get_os_release()
    if not is_arch_like(osr):
        console.print("[yellow]Advertencia:[/yellow] no parece ser Arch Linux o derivada. Algunas funciones pueden fallar.")

    if args.quick:
        report = quick_scan()
        paths = save_report(report)
        console.print(f"[green]Reporte generado:[/green] {paths[0]}")
    elif args.full:
        report = full_scan()
        paths = save_report(report)
        console.print(f"[green]Reporte generado:[/green] {paths[0]}")
    elif not args.no_menu:
        main_menu()


if __name__ == "__main__":
    cli()
