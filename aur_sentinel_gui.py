#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AUR Sentinel Audit GUI
Interfaz gráfica portable para Arch Linux y derivadas.
"""

from __future__ import annotations

import datetime as dt
import getpass
import html
import ipaddress
import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from urllib.request import Request, urlopen

from PySide6.QtCore import Qt, QThread, Signal, QTimer, QProcess
from PySide6.QtGui import QFont, QTextDocument, QIcon, QAction, QCursor
from PySide6.QtPrintSupport import QPrinter
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QLabel,
    QMainWindow,
    QMessageBox,
    QInputDialog,
    QPushButton,
    QProgressBar,
    QPlainTextEdit,
    QScrollArea,
    QSplitter,
    QHeaderView,
    QAbstractItemView,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QSystemTrayIcon,
    QMenu,
    QButtonGroup,
    QWidget,
)

APP_NAME = "AUR Sentinel Audit"
APP_ICON_PATH = Path("assets/aur_sentinel.svg")
REPORT_DIR = Path("aur_sentinel_reportes")
REPORT_DIR.mkdir(exist_ok=True)

RECOMMENDED_TOOLS = ["arch-audit", "bind-tools", "whois", "lsof", "nmap", "curl", "git"]

# Fuentes comunitarias usadas SOLO para comparación defensiva.
# Se actualizan al ejecutar el análisis si hay Internet.
# Fuentes oficiales/comunitarias del incidente AUR
ARCH_OFFICIAL_AFFECTED_LIST_URL = "https://md.archlinux.org/s/SxbqukK6IA/download"
AUR_GENERAL_REPORT_THREAD_URL = "https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/FGXPCB3ZVCJIV7FX323SBAX2JHYB7ZS4/"

MALWARE_DB_URLS = [
    ARCH_OFFICIAL_AFFECTED_LIST_URL,
    AUR_GENERAL_REPORT_THREAD_URL,
    "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/package_list.txt",
    "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/malicious_npm_packages.txt",
    "https://paste.cachyos.org/73a714d",
]
LOCAL_MALWARE_DB = Path("data/aur_malware_package_list.txt")
LOCAL_MALWARE_DB.parent.mkdir(exist_ok=True)


CONFIG_DIR = Path("config")
CONFIG_DIR.mkdir(exist_ok=True)
API_KEYS_FILE = CONFIG_DIR / "api_keys.json"

TRUSTED_ASN_OWNERS = [
    "cloudflare",
    "google",
    "google llc",
    "microsoft",
    "amazon",
    "amazon.com",
    "amazon technologies",
    "akamai",
    "fastly",
    "discord",
    "apple",
    "github",
    "mozilla",
    "cloudfront",
    "meta platforms",
    "facebook",
]

TRUSTED_PROCESS_HINTS = [
    "Discord",
    "discord",
    "chrome",
    "chromium",
    "firefox",
    "brave",
    "vivaldi",
    "steam",
    "code",
    "visual-studio-code",
    "telegram",
]

INCIDENT_INFO_LINKS = [
    {
        "name": "CachyOS - AUR Compromised 1500+ packages",
        "url": "https://discuss.cachyos.org/t/aur-compromised-1500-packages-affected-20260611/31040",
        "note": "Hilo principal con seguimiento, advertencias y discusión técnica."
    },
    {
        "name": "CachyOS - How to check compromised packages",
        "url": "https://discuss.cachyos.org/t/how-to-check-for-compromised-packages-from-the-current-aur-malware-attack/31077",
        "note": "Publicación orientada a chequeo de exposición real. Indica que las listas siguen actualizándose."
    },
    {
        "name": "Garuda Linux - Attack wave on AUR packages",
        "url": "https://forum.garudalinux.org/t/attack-wave-on-aur-packages/48124",
        "note": "Aviso comunitario para usuarios Garuda/Arch sobre la ola de ataque."
    },
    {
        "name": "Garuda / Chaotic-AUR reports",
        "url": "https://forum.garudalinux.org/t/chaotic-aur-packages-requests-recompilation-reports/26/1238",
        "note": "Hilo de reportes y recompilación de paquetes."
    },
    {
        "name": "GitHub - lenucksi/aur-malware-check",
        "url": "https://github.com/lenucksi/aur-malware-check",
        "note": "Herramienta comunitaria y listas consolidadas para el ataque atomic-lockfile."
    },
    {
        "name": "Arch aur-general official report thread",
        "url": AUR_GENERAL_REPORT_THREAD_URL,
        "note": "Hilo oficial de aur-general donde Arch pidió reportar paquetes maliciosos en un solo lugar. El programa extrae nombres desde enlaces AUR del hilo."
    },
    {
        "name": "Arch affected packages live list",
        "url": ARCH_OFFICIAL_AFFECTED_LIST_URL,
        "note": "Lista oficial/viva mencionada por Arch con paquetes afectados conocidos. El programa la consulta automáticamente."
    },
    {
        "name": "Arch Security Advisories",
        "url": "https://security.archlinux.org/",
        "note": "Fuente oficial para vulnerabilidades conocidas de paquetes oficiales de Arch. arch-audit consulta esta información."
    },
]

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
    "eBPF/rootkit": r"\b(eBPF|bpftrace|bpftool|rootkit)\b",
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
    "eBPF/rootkit": 45,
    "descarga remota": 8,
}


# Reglas tipo "antivirus" para detectar el incidente AUR atomic-lockfile/js-digest
# y patrones de alto riesgo en PKGBUILD / .install.
AUR_MALWARE_SIGNATURES = {
    "INCIDENTE_AUR_atomic_lockfile": {
        "patterns": [
            r"\bnpm\s+install\s+atomic-lockfile\b",
            r"\bpnpm\s+(install|add)\s+atomic-lockfile\b",
            r"\byarn\s+add\s+atomic-lockfile\b",
            r"\bbun\s+add\s+atomic-lockfile\b",
            r"\batomic-lockfile\b",
        ],
        "risk": "Crítico",
        "score": 100,
        "description": "Firma relacionada con el incidente AUR atomic-lockfile.",
    },
    "INCIDENTE_AUR_js_digest": {
        "patterns": [
            r"\bnpm\s+install\s+js-digest\b",
            r"\bpnpm\s+(install|add)\s+js-digest\b",
            r"\bbun\s+add\s+js-digest\b",
            r"\bjs-digest\b",
            r"@gsdigest/gsdigest",
            r"\bgsdigest\b",
        ],
        "risk": "Crítico",
        "score": 100,
        "description": "Firma relacionada con payload npm/js-digest/gsdigest.",
    },
    "BPF_rootkit_indicators": {
        "patterns": [
            r"/sys/fs/bpf/hidden_",
            r"\bbpftool\b",
            r"\bbpftrace\b",
            r"\bebpf\b",
            r"\brootkit\b",
        ],
        "risk": "Crítico",
        "score": 90,
        "description": "Indicadores compatibles con persistencia/ocultamiento mediante eBPF/rootkit.",
    },
    "Hooks_or_deps_suspicious": {
        "patterns": [
            r"src/hooks/deps",
            r"\.install\b.*(npm|pnpm|bun|curl|wget)",
        ],
        "risk": "Alto",
        "score": 70,
        "description": "Uso sospechoso de hooks/dependencias durante instalación.",
    },
}

PACMAN_LOG = Path("/var/log/pacman.log")


def run_cmd(cmd, timeout=90, sudo=False):
    full = list(cmd)
    if sudo:
        full = ["sudo"] + full
    try:
        p = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return {
            "cmd": " ".join(full),
            "returncode": p.returncode,
            "stdout": p.stdout.strip(),
            "stderr": p.stderr.strip(),
        }
    except FileNotFoundError:
        return {"cmd": " ".join(full), "returncode": 127, "stdout": "", "stderr": f"No encontrado: {cmd[0]}"}
    except subprocess.TimeoutExpired:
        return {"cmd": " ".join(full), "returncode": 124, "stdout": "", "stderr": "Tiempo agotado"}
    except Exception as e:
        return {"cmd": " ".join(full), "returncode": 1, "stdout": "", "stderr": str(e)}


def which(cmd):
    return shutil.which(cmd) is not None


def read_file(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def get_os_release():
    data = {}
    for line in read_file("/etc/os-release").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k] = v.strip().strip('"')
    return data


def detect_logo_and_distro():
    osr = get_os_release()
    name = osr.get("PRETTY_NAME", osr.get("NAME", "Linux"))
    joined = " ".join([osr.get("ID", ""), osr.get("ID_LIKE", ""), osr.get("NAME", "")]).lower()

    if "cachy" in joined:
        return name, "⚡"
    if "endeavour" in joined:
        return name, "🚀"
    if "manjaro" in joined:
        return name, "🟩"
    if "garuda" in joined:
        return name, "🦅"
    if "arch" in joined:
        return name, "🔷"
    return name, "🐧"


def is_arch_like():
    osr = get_os_release()
    joined = " ".join([osr.get("ID", ""), osr.get("ID_LIKE", ""), osr.get("NAME", "")]).lower()
    return which("pacman") or any(x in joined for x in ["arch", "cachyos", "endeavouros", "manjaro", "garuda"])


def detect_aur_helper():
    for h in ["yay", "paru", "trizen", "pikaur", "aura"]:
        if which(h):
            return h
    return "solo pacman"


def system_info():
    distro, logo = detect_logo_and_distro()
    return {
        "app": APP_NAME,
        "fecha": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "usuario": getpass.getuser(),
        "hostname": socket.gethostname(),
        "distro": distro,
        "logo": logo,
        "arch_like": is_arch_like(),
        "kernel": platform.release(),
        "arquitectura": platform.machine(),
        "desktop": os.environ.get("XDG_CURRENT_DESKTOP") or os.environ.get("DESKTOP_SESSION") or "No detectado",
        "aur_helper": detect_aur_helper(),
        "python": platform.python_version(),
    }


def get_aur_packages():
    res = run_cmd(["pacman", "-Qm"], timeout=90)
    packages = []
    if res["returncode"] != 0 and not res["stdout"]:
        return packages
    for line in res["stdout"].splitlines():
        parts = line.split()
        if len(parts) >= 2:
            name = parts[0]
            version = " ".join(parts[1:])
            qi = run_cmd(["pacman", "-Qi", name], timeout=45)
            install_date = ""
            packager = ""
            for l in qi["stdout"].splitlines():
                low = l.lower()
                if low.startswith("install date") or low.startswith("fecha de instalación"):
                    install_date = l.split(":", 1)[-1].strip()
                if low.startswith("packager") or low.startswith("empaquetador"):
                    packager = l.split(":", 1)[-1].strip()
            packages.append({"name": name, "version": version, "install_date": install_date, "packager": packager})
    return packages


def aur_rpc_info(pkg_name):
    url = f"https://aur.archlinux.org/rpc/v5/info/{pkg_name}"
    try:
        req = Request(url, headers={"User-Agent": "AUR-Sentinel-Audit-GUI/1.0"})
        with urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8", errors="ignore"))
        if data.get("resultcount", 0) > 0:
            x = data["results"][0]
            return {
                "exists": "sí",
                "maintainer": str(x.get("Maintainer") or "huérfano"),
                "votes": str(x.get("NumVotes", "")),
                "popularity": str(x.get("Popularity", "")),
                "last_modified": dt.datetime.fromtimestamp(x.get("LastModified", 0)).strftime("%Y-%m-%d") if x.get("LastModified") else "",
            }
        return {"exists": "no", "maintainer": "", "votes": "", "popularity": "", "last_modified": ""}
    except Exception as e:
        return {"exists": "error", "maintainer": "", "votes": "", "popularity": "", "last_modified": "", "error": str(e)}


def download_pkgbuild(pkg_name):
    url = f"https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={pkg_name}"
    try:
        req = Request(url, headers={"User-Agent": "AUR-Sentinel-Audit-GUI/1.0"})
        with urlopen(req, timeout=15) as r:
            text = r.read().decode("utf-8", errors="ignore")
        if "pkgname" in text.lower():
            return text, url
    except Exception:
        pass
    return "", ""


def antivirus_signature_scan(text):
    """
    Escaneo de firmas tipo antivirus sobre PKGBUILD/.install.
    Devuelve coincidencias críticas conocidas del incidente AUR.
    """
    findings = []
    total_score = 0
    highest = "Sin alertas"
    order = {"Sin alertas": 0, "Bajo": 1, "Medio": 2, "Alto": 3, "Crítico": 4}

    for sig_name, sig in AUR_MALWARE_SIGNATURES.items():
        matched = []
        for pattern in sig.get("patterns", []):
            if re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE | re.DOTALL):
                matched.append(pattern)
        if matched:
            findings.append({
                "signature": sig_name,
                "risk": sig.get("risk", "Alto"),
                "score": sig.get("score", 50),
                "description": sig.get("description", ""),
                "patterns": matched,
            })
            total_score += sig.get("score", 50)
            if order.get(sig.get("risk", "Alto"), 0) > order.get(highest, 0):
                highest = sig.get("risk", "Alto")

    return {
        "signature_score": total_score,
        "signature_risk": highest,
        "signature_hits": findings,
    }


def analyze_pkgbuild_text(text):
    score = 0
    hits = []
    for label, pattern in SUSPICIOUS_PATTERNS.items():
        found = re.findall(pattern, text, flags=re.IGNORECASE)
        if found:
            weight = RISK_WEIGHTS.get(label, 5)
            score += weight
            hits.append({"pattern": label, "weight": weight, "count": len(found)})
    signature_result = antivirus_signature_scan(text)
    score += signature_result.get("signature_score", 0)

    # Las firmas del incidente tienen prioridad sobre heurísticas normales.
    if signature_result.get("signature_risk") == "Crítico":
        level = "Crítico"
    elif signature_result.get("signature_risk") == "Alto":
        level = "Alto"
    elif score >= 80:
        level = "Crítico"
    elif score >= 50:
        level = "Alto"
    elif score >= 25:
        level = "Medio"
    elif score > 0:
        level = "Bajo"
    else:
        level = "Sin alertas"

    for sig_hit in signature_result.get("signature_hits", []):
        hits.append({
            "pattern": "FIRMA: " + sig_hit.get("signature", ""),
            "weight": sig_hit.get("score", 0),
            "count": len(sig_hit.get("patterns", [])),
            "description": sig_hit.get("description", ""),
        })

    return {
        "risk_score": score,
        "risk_level": level,
        "hits": hits,
        "signature_hits": signature_result.get("signature_hits", []),
    }


def run_arch_audit():
    if not which("arch-audit"):
        return {"installed": False, "output": "arch-audit no está instalado.", "returncode": 127}
    res = run_cmd(["arch-audit"], timeout=180)
    return {"installed": True, "output": res["stdout"] or res["stderr"], "returncode": res["returncode"]}


def pacman_integrity():
    res = run_cmd(["pacman", "-Qkk"], timeout=240)
    lines = (res["stdout"] + "\n" + res["stderr"]).splitlines()
    warnings = [l for l in lines if "warning:" in l.lower() or "advertencia" in l.lower() or "error:" in l.lower()]
    return {"returncode": res["returncode"], "warnings": warnings[:500], "raw_limited": "\n".join(lines[:600])}



def load_api_keys():
    keys = {
        "virustotal": os.environ.get("VT_API_KEY", ""),
        "abuseipdb": os.environ.get("ABUSEIPDB_API_KEY", ""),
        "otx": os.environ.get("OTX_API_KEY", ""),
    }
    if API_KEYS_FILE.exists():
        try:
            data = json.loads(API_KEYS_FILE.read_text(encoding="utf-8", errors="ignore"))
            keys["virustotal"] = data.get("virustotal_api_key") or keys["virustotal"]
            keys["abuseipdb"] = data.get("abuseipdb_api_key") or keys["abuseipdb"]
            keys["otx"] = data.get("otx_api_key") or keys["otx"]
        except Exception:
            pass
    return keys


def extract_ip_from_peer(peer):
    peer = str(peer or "").strip()
    if not peer or peer in ["*", "*:*", "0.0.0.0:*", "[::]:*"]:
        return ""
    if peer.startswith("[") and "]" in peer:
        return peer[1:peer.index("]")]
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", peer)
    if m:
        return m.group(1)
    candidate = peer.rsplit(":", 1)[0] if ":" in peer else peer
    candidate = candidate.split("%", 1)[0]
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except Exception:
        return ""


def classify_ip(ip):
    try:
        obj = ipaddress.ip_address(ip)
    except Exception:
        return "inválida"
    if obj.is_loopback:
        return "loopback"
    if obj.is_private:
        return "privada"
    if obj.is_multicast:
        return "multicast"
    if obj.is_link_local:
        return "link-local"
    if obj.is_reserved:
        return "reservada"
    return "pública"


def vt_ip_lookup(ip, api_key):
    if not api_key:
        return {"enabled": False, "status": "Sin API key", "malicious": None, "suspicious": None, "harmless": None}
    try:
        req = Request(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key, "accept": "application/json", "User-Agent": "AUR-Sentinel-Audit/1.2"}
        )
        with urlopen(req, timeout=20) as r:
            data = json.loads(r.read().decode("utf-8", errors="ignore"))
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "enabled": True,
            "status": "OK",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "country": attrs.get("country", ""),
            "asn": attrs.get("asn", ""),
            "as_owner": attrs.get("as_owner", ""),
            "reputation": attrs.get("reputation", ""),
        }
    except Exception as e:
        return {"enabled": True, "status": f"Error VT: {e}", "malicious": None, "suspicious": None, "harmless": None}


def abuseipdb_lookup(ip, api_key):
    if not api_key:
        return {"enabled": False, "status": "Sin API key", "abuse_score": None, "total_reports": None}
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose=false"
        req = Request(url, headers={"Key": api_key, "Accept": "application/json", "User-Agent": "AUR-Sentinel-Audit/1.2"})
        with urlopen(req, timeout=20) as r:
            data = json.loads(r.read().decode("utf-8", errors="ignore"))
        d = data.get("data", {})
        return {
            "enabled": True,
            "status": "OK",
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "country": d.get("countryCode", ""),
            "isp": d.get("isp", ""),
            "usage_type": d.get("usageType", ""),
            "domain": d.get("domain", ""),
        }
    except Exception as e:
        return {"enabled": True, "status": f"Error AbuseIPDB: {e}", "abuse_score": None, "total_reports": None}


def otx_ip_lookup(ip, api_key=""):
    try:
        headers = {"Accept": "application/json", "User-Agent": "AUR-Sentinel-Audit/1.2"}
        if api_key:
            headers["X-OTX-API-KEY"] = api_key
        req = Request(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general", headers=headers)
        with urlopen(req, timeout=20) as r:
            data = json.loads(r.read().decode("utf-8", errors="ignore"))
        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", []) or []
        return {
            "enabled": True,
            "status": "OK",
            "pulse_count": pulse_info.get("count", len(pulses)),
            "first_pulse": pulses[0].get("name", "") if pulses else "",
        }
    except Exception as e:
        return {"enabled": True, "status": f"Error OTX: {e}", "pulse_count": None, "first_pulse": ""}



def rdap_lookup_ip(ip):
    """
    Consulta RDAP público para obtener ASN/organización/red.
    No requiere API key.
    Si falla, devuelve error sin detener el análisis.
    """
    try:
        req = Request(
            f"https://rdap.org/ip/{ip}",
            headers={"Accept": "application/json", "User-Agent": "AUR-Sentinel-Audit/1.3"}
        )
        with urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode("utf-8", errors="ignore"))

        name = data.get("name", "")
        handle = data.get("handle", "")
        country = data.get("country", "")
        remarks = []
        for rem in data.get("remarks", []) or []:
            desc = rem.get("description", [])
            if isinstance(desc, list):
                remarks.extend(desc)
        entities = []
        for ent in data.get("entities", []) or []:
            vcard = ent.get("vcardArray", [])
            if isinstance(vcard, list) and len(vcard) > 1:
                for row in vcard[1]:
                    if row and row[0] in ["fn", "org"]:
                        entities.append(str(row[3]))
        owner_text = " ".join([name, handle, country] + remarks + entities)
        return {
            "status": "OK",
            "name": name,
            "handle": handle,
            "country": country,
            "owner_text": owner_text,
        }
    except Exception as e:
        return {
            "status": f"Error RDAP: {e}",
            "name": "",
            "handle": "",
            "country": "",
            "owner_text": "",
        }


def is_trusted_infra(owner_text, processes):
    joined_owner = str(owner_text or "").lower()
    joined_proc = " ".join(processes or [])
    infra = any(x in joined_owner for x in TRUSTED_ASN_OWNERS)
    common_proc = any(x in joined_proc for x in TRUSTED_PROCESS_HINTS)
    return infra, common_proc


def summarize_ip_reason(vt, abuse, otx, rdap, trusted_infra, common_proc):
    reasons = []
    if trusted_infra:
        reasons.append("Proveedor/CDN reconocido por RDAP")
    if common_proc:
        reasons.append("Proceso habitual de usuario")
    if vt.get("malicious") is not None:
        reasons.append(f"VT M:{vt.get('malicious')} S:{vt.get('suspicious')}")
    else:
        reasons.append(vt.get("status", "VT no disponible"))
    if abuse.get("abuse_score") is not None:
        reasons.append(f"AbuseIPDB score:{abuse.get('abuse_score')}")
    else:
        reasons.append(abuse.get("status", "AbuseIPDB no disponible"))
    if otx.get("pulse_count") is not None:
        reasons.append(f"OTX pulses:{otx.get('pulse_count')}")
    else:
        reasons.append(otx.get("status", "OTX no disponible"))
    if rdap.get("name") or rdap.get("handle"):
        reasons.append(f"RDAP:{rdap.get('name') or rdap.get('handle')}")
    return " | ".join([r for r in reasons if r])

def analyze_ip_reputation(connections):
    """
    Analiza reputación de IPs externas.
    Mejora v1.3:
    - RDAP/WHOIS público para ASN/organización.
    - Reduce falsos positivos de Cloudflare/Google/Microsoft/Akamai/Fastly/AWS.
    - No marca como alto solo por OTX si la IP pertenece a CDN reconocido y el proceso es habitual.
    - VirusTotal y AbuseIPDB tienen más peso si hay API key.
    """
    keys = load_api_keys()
    seen = {}
    results = []

    for c in connections.get("connections", []):
        ip = extract_ip_from_peer(c.get("peer", ""))
        if not ip or ip in seen:
            continue

        seen[ip] = True
        ip_type = classify_ip(ip)
        related = sorted(set([
            x.get("process", "")
            for x in connections.get("connections", [])
            if extract_ip_from_peer(x.get("peer", "")) == ip and x.get("process", "")
        ]))[:5]

        base = {
            "ip": ip,
            "type": ip_type,
            "status": "✅ Conexión local/confiable" if ip_type != "pública" else "⏳ Analizando",
            "risk": "Bajo" if ip_type != "pública" else "Pendiente",
            "vt": {},
            "abuseipdb": {},
            "otx": {},
            "rdap": {},
            "trusted_infra": False,
            "common_process": False,
            "reason": "",
            "related_processes": related,
        }

        if ip_type != "pública":
            base["reason"] = "IP privada/local/reservada. No se consulta reputación externa."
            results.append(base)
            continue

        rdap = rdap_lookup_ip(ip)
        trusted_infra, common_proc = is_trusted_infra(rdap.get("owner_text", ""), related)

        vt = vt_ip_lookup(ip, keys.get("virustotal", ""))
        abuse = abuseipdb_lookup(ip, keys.get("abuseipdb", ""))
        otx = otx_ip_lookup(ip, keys.get("otx", ""))

        base["vt"] = vt
        base["abuseipdb"] = abuse
        base["otx"] = otx
        base["rdap"] = rdap
        base["trusted_infra"] = trusted_infra
        base["common_process"] = common_proc

        vt_bad = (vt.get("malicious") or 0) + (vt.get("suspicious") or 0)
        abuse_bad = abuse.get("abuse_score") if abuse.get("abuse_score") is not None else 0
        otx_bad = otx.get("pulse_count") if otx.get("pulse_count") is not None else 0

        # Reglas de decisión:
        # 1) VT/AbuseIPDB pesan más que OTX.
        # 2) OTX en CDNs genera muchos falsos positivos, por eso no sube a Alto solo.
        # 3) Sin API keys se marca como "no verificado" salvo que OTX sea fuerte y no sea CDN.
        if vt_bad >= 2 or abuse_bad >= 50:
            base["status"] = "❌ Sospechosa"
            base["risk"] = "Alto"
        elif vt_bad == 1 or abuse_bad >= 15:
            base["status"] = "⚠️ Revisar"
            base["risk"] = "Medio"
        elif otx_bad >= 10 and not trusted_infra:
            base["status"] = "❌ Sospechosa por OTX"
            base["risk"] = "Alto"
        elif otx_bad >= 1 and not trusted_infra:
            base["status"] = "⚠️ Revisar por OTX"
            base["risk"] = "Medio"
        elif trusted_infra and common_proc:
            base["status"] = "✅ CDN/servicio reconocido"
            base["risk"] = "Bajo"
        elif trusted_infra:
            base["status"] = "✅ Infraestructura reconocida"
            base["risk"] = "Bajo"
        elif not keys.get("virustotal") and not keys.get("abuseipdb"):
            base["status"] = "ℹ️ Sin verificación externa completa"
            base["risk"] = "No verificado"
        else:
            base["status"] = "✅ Sin reportes relevantes"
            base["risk"] = "Bajo"

        base["reason"] = summarize_ip_reason(vt, abuse, otx, rdap, trusted_infra, common_proc)
        results.append(base)

    return {
        "api_keys_configured": {
            "virustotal": bool(keys.get("virustotal")),
            "abuseipdb": bool(keys.get("abuseipdb")),
            "otx": bool(keys.get("otx")),
        },
        "trusted_asn_owners": TRUSTED_ASN_OWNERS,
        "results": results,
    }


def active_connections():
    res = run_cmd(["ss", "-tunap"], timeout=90)
    raw = res["stdout"] or res["stderr"]
    connections = []
    for line in raw.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            connections.append({
                "raw": line,
                "state": parts[1] if len(parts) > 1 else "",
                "local": parts[4] if len(parts) > 4 else "",
                "peer": parts[5] if len(parts) > 5 else "",
                "process": " ".join(parts[6:]) if len(parts) > 6 else "",
            })
    return {"raw_limited": raw[:30000], "connections": connections}


def services_info():
    running = run_cmd(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"], timeout=90)
    enabled = run_cmd(["systemctl", "list-unit-files", "--state=enabled", "--no-pager"], timeout=90)
    return {"running": running["stdout"] or running["stderr"], "enabled": enabled["stdout"] or enabled["stderr"]}


def ports_info():
    if which("nmap"):
        res = run_cmd(["nmap", "-sT", "127.0.0.1"], timeout=180)
        return {"tool": "nmap", "output": res["stdout"] or res["stderr"]}
    res = run_cmd(["ss", "-tulpen"], timeout=90)
    return {"tool": "ss", "output": res["stdout"] or res["stderr"]}


def persistence_checks():
    home = Path.home()
    cron = run_cmd(["crontab", "-l"], timeout=45)
    tmp_proc = run_cmd(["bash", "-lc", "ps aux | egrep '(/tmp|/var/tmp)' | grep -v egrep"], timeout=45)
    autostart = home / ".config" / "autostart"
    return {
        "crontab": cron["stdout"] or cron["stderr"],
        "autostart_files": [str(p) for p in autostart.glob("*")] if autostart.exists() else [],
        "processes_from_tmp": tmp_proc["stdout"] or "",
    }


def installed_tools_status():
    return {tool: which(tool) for tool in RECOMMENDED_TOOLS}


def extract_packages_from_arch_mailing_thread(html_text):
    """
    Extrae nombres de paquetes desde links de:
    - aur.archlinux.org/packages/<pkg>
    - aur.archlinux.org/cgit/aur.git/commit/?h=<pkg>
    - aur.archlinux.org/<pkg>.git
    La fuente es el hilo aur-general usado por Arch para reportes del incidente.
    """
    names = set()
    patterns = [
        r"aur\.archlinux\.org/packages/([A-Za-z0-9@._+:-]+)",
        r"aur\.archlinux\.org/cgit/aur\.git/commit/\?h=([A-Za-z0-9@._+:-]+)",
        r"aur\.archlinux\.org/([A-Za-z0-9@._+:-]+)\.git",
        r"activity\?ref=([A-Za-z0-9@._+:-]+)",
    ]
    for pat in patterns:
        for m in re.findall(pat, html_text, flags=re.IGNORECASE):
            pkg = m.strip().strip("/").strip()
            if pkg and not pkg.lower().startswith(("http", "www")):
                names.add(pkg)
    return names


def parse_package_names_from_text(text):
    names = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Evita capturar comandos enteros. Toma solo tokens compatibles con nombres de paquetes.
        token = re.split(r"[\s,;]+", line)[0].strip().strip("'\"")
        if re.fullmatch(r"[A-Za-z0-9@._+:-]{2,}", token):
            names.add(token)
    return names


def load_local_malware_db():
    if LOCAL_MALWARE_DB.exists():
        return parse_package_names_from_text(LOCAL_MALWARE_DB.read_text(encoding="utf-8", errors="ignore"))
    return set()


def update_malware_db():
    """
    Descarga una lista comunitaria actualizada de paquetes reportados.
    Si no hay Internet, usa la copia local.
    """
    combined = set()
    errors = []
    raw_collected = []
    for url in MALWARE_DB_URLS:
        try:
            req = Request(url, headers={"User-Agent": "AUR-Sentinel-Audit-GUI/1.1"})
            with urlopen(req, timeout=15) as r:
                txt = r.read().decode("utf-8", errors="ignore")
            if "lists.archlinux.org/archives/list/aur-general" in url:
                names = extract_packages_from_arch_mailing_thread(txt)
            else:
                names = parse_package_names_from_text(txt)
            combined.update(names)
            raw_collected.append(f"# Fuente: {url}\n# Paquetes extraídos: {len(names)}\n{txt}\n")
        except Exception as e:
            errors.append(f"{url}: {e}")

    if combined:
        LOCAL_MALWARE_DB.write_text("\n".join(raw_collected), encoding="utf-8")
        return combined, {"source": "remota + cache local", "count": len(combined), "errors": errors}

    local = load_local_malware_db()
    return local, {"source": "cache local", "count": len(local), "errors": errors}



def force_update_malware_db_for_ui():
    malware_db, meta = update_malware_db()
    return {
        "ok": bool(malware_db),
        "count": len(malware_db),
        "meta": meta,
        "cache": str(LOCAL_MALWARE_DB),
    }


def incident_sources_status():
    """
    Devuelve fuentes informativas para mostrar en la GUI y en el reporte.
    """
    return {
        "links": INCIDENT_INFO_LINKS,
        "database_urls": MALWARE_DB_URLS,
        "local_cache": str(LOCAL_MALWARE_DB),
        "recommendation": (
            "Las listas comunitarias pueden seguir actualizándose. "
            "Repite el análisis luego de actualizar el sistema o instalar paquetes AUR."
        ),
    }


def run_external_aur_malware_check():
    """
    Ejecuta opcionalmente una copia local del script comunitario si fue descargado.
    No ejecuta curl | bash por seguridad.
    """
    script_path = Path("data/aur_check-v2.sh")
    url = "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/aur_check-v2.sh"
    try:
        req = Request(url, headers={"User-Agent": "AUR-Sentinel-Audit-GUI/1.1"})
        with urlopen(req, timeout=15) as r:
            script = r.read().decode("utf-8", errors="ignore")
        if "#!/usr/bin/env bash" in script and "AUR Malware Check" in script:
            script_path.write_text(script, encoding="utf-8")
            os.chmod(script_path, 0o755)
            res = run_cmd(["bash", str(script_path), "--full"], timeout=240)
            return {"available": True, "command": res["cmd"], "returncode": res["returncode"], "output": res["stdout"] or res["stderr"]}
        return {"available": False, "output": "El script remoto no pasó la validación básica."}
    except Exception as e:
        return {"available": False, "output": f"No se pudo ejecutar chequeo externo: {e}"}


def general_risk(report):
    levels = [p.get("risk_level") for p in report.get("aur_analysis", [])]
    ip_risks = [x.get("risk") for x in report.get("ip_reputation", {}).get("results", [])]
    if "Crítico" in levels:
        return "Crítico"
    if "Alto" in levels or "Alto" in ip_risks:
        return "Alto"
    if "Medio" in levels or "Medio" in ip_risks:
        return "Medio"
    return "Bajo"


def esc(x):
    return html.escape(str(x or ""))


def badge_class(level):
    return {
        "Crítico": "critical",
        "Alto": "high",
        "Medio": "medium",
        "Bajo": "low",
        "Sin alertas": "ok",
    }.get(level, "unknown")


def generate_pdf_from_html(html_path, pdf_path):
    """
    Genera PDF desde el HTML usando Qt.
    No necesita wkhtmltopdf ni navegador externo.
    """
    try:
        doc = QTextDocument()
        doc.setHtml(Path(html_path).read_text(encoding="utf-8", errors="ignore"))
        printer = QPrinter(QPrinter.HighResolution)
        printer.setOutputFormat(QPrinter.PdfFormat)
        printer.setOutputFileName(str(pdf_path))
        printer.setPageMargins(12, 12, 12, 12, QPrinter.Millimeter)
        doc.print_(printer)
        return True, ""
    except Exception as e:
        return False, str(e)


def generate_html(report):
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = REPORT_DIR / f"aur_sentinel_gui_reporte_{ts}.html"
    json_out = REPORT_DIR / f"aur_sentinel_gui_reporte_{ts}.json"
    txt_out = REPORT_DIR / f"aur_sentinel_gui_reporte_{ts}.txt"
    pdf_out = REPORT_DIR / f"aur_sentinel_gui_reporte_{ts}.pdf"

    sysinfo = report.get("system", {})
    aur = report.get("aur_analysis", [])
    connections = report.get("connections", {}).get("connections", [])
    risk = general_risk(report)

    rows = ""
    for p in aur:
        hits = ", ".join([h["pattern"] for h in p.get("hits", [])]) or "Sin patrones detectados"
        status = p.get("incident_status") or ("❌ REPORTADO / INFECTADO" if p.get("incident_reported") else "✅ No figura en base del incidente")
        rows += f"""
        <tr>
          <td>{esc(status)}</td>
          <td>{esc(p.get('name'))}</td>
          <td>{esc(p.get('version'))}</td>
          <td>{esc(p.get('aur_exists'))}</td>
          <td>{esc(p.get('maintainer'))}</td>
          <td><span class="badge {badge_class(p.get('risk_level'))}">{esc(p.get('risk_level'))}</span></td>
          <td>{esc(p.get('risk_score'))}</td>
          <td>{esc(hits)}</td>
        </tr>"""

    conn_rows = ""
    for c in connections[:300]:
        conn_rows += f"<tr><td>{esc(c.get('state'))}</td><td>{esc(c.get('local'))}</td><td>{esc(c.get('peer'))}</td><td>{esc(c.get('process'))}</td></tr>"

    ip_rows = ""
    for r in report.get("ip_reputation", {}).get("results", []):
        vt = r.get("vt", {})
        abuse = r.get("abuseipdb", {})
        otx = r.get("otx", {})
        vt_txt = vt.get("status", "")
        if vt.get("malicious") is not None:
            vt_txt = f"M:{vt.get('malicious')} S:{vt.get('suspicious')} H:{vt.get('harmless')}"
        abuse_txt = abuse.get("status", "")
        if abuse.get("abuse_score") is not None:
            abuse_txt = f"Score:{abuse.get('abuse_score')} Reports:{abuse.get('total_reports')}"
        otx_txt = otx.get("status", "")
        if otx.get("pulse_count") is not None:
            otx_txt = f"Pulses:{otx.get('pulse_count')} {otx.get('first_pulse', '')}"
        rdap = r.get("rdap", {})
        rdap_txt = rdap.get("name") or rdap.get("handle") or rdap.get("status", "")
        ip_rows += f"<tr><td>{esc(r.get('status'))}</td><td>{esc(r.get('ip'))}</td><td>{esc(r.get('type'))}</td><td>{esc(r.get('risk'))}</td><td>{esc(rdap_txt)}</td><td>{esc(vt_txt)}</td><td>{esc(abuse_txt)}</td><td>{esc(otx_txt)}</td><td>{esc(r.get('reason'))}</td><td>{esc(', '.join(r.get('related_processes', [])))}</td></tr>"

    html_doc = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>AUR Sentinel Audit - Reporte</title>
<style>
body {{ margin:0; background:#07101d; color:#e8eef5; font-family:Arial, sans-serif; }}
header {{ padding:28px; background:#05080e; border-bottom:1px solid #243449; }}
h1 {{ margin:0; font-size:34px; }}
.container {{ padding:24px; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:14px; }}
.card {{ background:#101a28; border:1px solid #26384f; border-radius:14px; padding:16px; margin-bottom:16px; }}
.kpi {{ font-size:34px; font-weight:bold; }}
table {{ width:100%; border-collapse:collapse; }}
th,td {{ padding:9px; border-bottom:1px solid #26384f; text-align:left; font-size:14px; }}
th {{ background:#0b1320; }}
a {{ color:#59b8ff; }}
pre {{ white-space:pre-wrap; max-height:420px; overflow:auto; background:#05080e; border:1px solid #26384f; padding:12px; border-radius:10px; }}
.badge {{ padding:5px 9px; border-radius:999px; font-weight:bold; display:inline-block; }}
.critical {{ background:#4d0000; color:#ffb3b3; border:1px solid #ff3131; }}
.high {{ background:#4a1a00; color:#ffc28a; border:1px solid #ff7a00; }}
.medium {{ background:#4d4100; color:#fff1a8; border:1px solid #ffd400; }}
.low {{ background:#00314d; color:#a6dcff; border:1px solid #1793ff; }}
.ok {{ background:#003a1d; color:#9fffc8; border:1px solid #00d26a; }}
.unknown {{ background:#333; color:#ddd; }}
</style>
</head>
<body>
<header>
<h1>{esc(sysinfo.get('logo'))} AUR Sentinel Audit</h1>
<p>Reporte defensivo para Arch Linux y derivadas compatibles con AUR</p>
</header>
<div class="container">
<div class="grid">
<div class="card"><h2>Riesgo general</h2><div class="kpi"><span class="badge {badge_class(risk)}">{esc(risk)}</span></div></div>
<div class="card"><h2>Distro</h2><div class="kpi">{esc(sysinfo.get('distro'))}</div><p>{esc(sysinfo.get('kernel'))}</p></div>
<div class="card"><h2>Paquetes AUR</h2><div class="kpi">{len(aur)}</div></div>
<div class="card"><h2>Base incidente</h2><div class="kpi">{esc(report.get('malware_db', {}).get('count', 0))}</div><p>{esc(report.get('malware_db', {}).get('source', ''))}</p></div>
<div class="card"><h2>Conexiones</h2><div class="kpi">{len(connections)}</div></div>
</div>
<div class="card"><h2>Guía para usuarios no técnicos</h2>
<p>Este reporte revisa si los paquetes instalados desde AUR aparecen en listas comunitarias relacionadas con el incidente de malware. También revisa señales de riesgo como conexiones activas, servicios, puertos abiertos y vulnerabilidades conocidas.</p>
<ul>
<li><b>✅ No figura en base del incidente:</b> el paquete no apareció en las listas consultadas. No significa seguridad absoluta.</li>
<li><b>❌ REPORTADO / INFECTADO:</b> el paquete coincide con una lista del incidente. Requiere revisión urgente.</li>
<li><b>Riesgo bajo/medio/alto/crítico:</b> se calcula por patrones encontrados en PKGBUILD y coincidencias con listas.</li>
<li><b>arch-audit:</b> revisa vulnerabilidades conocidas de paquetes de Arch.</li>
</ul>
</div>
<div class="card"><h2>Sistema</h2><table>{''.join(f'<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>' for k,v in sysinfo.items())}</table></div>
<div class="card"><h2>Paquetes AUR analizados</h2><p>✅ significa que el paquete instalado no figura en la base comunitaria consultada del incidente AUR. No reemplaza una revisión manual del PKGBUILD.</p><table><tr><th>Estado incidente</th><th>Paquete</th><th>Versión</th><th>AUR</th><th>Mantenedor</th><th>Riesgo</th><th>Puntaje</th><th>Motivos</th></tr>{rows}</table></div>
<div class="card"><h2>Chequeo comunitario aur-malware-check</h2><pre>{esc(report.get('external_aur_check', {}).get('output'))}</pre></div>
<div class="card"><h2>arch-audit</h2><pre>{esc(report.get('arch_audit', {}).get('output'))}</pre></div>
<div class="card"><h2>Integridad pacman -Qkk</h2><pre>{esc(chr(10).join(report.get('integrity', {}).get('warnings', [])) or report.get('integrity', {}).get('raw_limited', ''))}</pre></div>
<div class="card"><h2>Conexiones activas</h2><table><tr><th>Estado</th><th>Local</th><th>Remoto</th><th>Proceso</th></tr>{conn_rows}</table></div>
<div class="card"><h2>Reputación de IPs externas</h2><p>Se analizan IPs públicas detectadas en conexiones activas. VirusTotal y AbuseIPDB requieren API key; OTX se intenta consultar como fuente comunitaria. Las IP privadas/locales se marcan como locales.</p><table><tr><th>Estado</th><th>IP</th><th>Tipo</th><th>Riesgo</th><th>RDAP/ASN</th><th>VirusTotal</th><th>AbuseIPDB</th><th>OTX</th><th>Motivo</th><th>Procesos</th></tr>{ip_rows}</table></div>
<div class="card"><h2>Servicios en ejecución</h2><pre>{esc(report.get('services', {}).get('running'))}</pre></div>
<div class="card"><h2>Servicios habilitados</h2><pre>{esc(report.get('services', {}).get('enabled'))}</pre></div>
<div class="card"><h2>Persistencia básica</h2><pre>{esc(json.dumps(report.get('persistence', {}), indent=2, ensure_ascii=False))}</pre></div>
<div class="card"><h2>Fuentes de seguimiento y actualización</h2><p>Estas fuentes pueden actualizarse. Desde el programa puedes presionar <b>Actualizar listas</b> y luego ejecutar <b>Escaneo completo</b> nuevamente.</p><p>Base local/cache: {esc(report.get('incident_sources', {}).get('local_cache', 'data/aur_malware_package_list.txt'))}</p><ul>{''.join(f'<li><b>{esc(i.get("name"))}</b>: <a href="{esc(i.get("url"))}">{esc(i.get("url"))}</a><br>{esc(i.get("note"))}</li>' for i in report.get('incident_sources', {}).get('links', []))}</ul></div>
<div class="card"><h2>Recomendaciones</h2><ul><li>Revisa PKGBUILD antes de instalar.</li><li>Prioriza repositorios oficiales.</li><li>Evita paquetes huérfanos o con cambios recientes sospechosos.</li><li>Ejecuta arch-audit periódicamente.</li><li>Repite el análisis porque las listas comunitarias pueden actualizarse.</li><li>No borres evidencia si sospechas infección.</li></ul></div>
</div>
</body>
</html>"""

    out.write_text(html_doc, encoding="utf-8")
    json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    txt_out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    generate_pdf_from_html(out, pdf_out)
    return str(out), str(txt_out), str(json_out), str(pdf_out)


class ScanWorker(QThread):
    progress = Signal(int, str)
    log = Signal(str)
    done = Signal(dict)
    failed = Signal(str)

    def __init__(self, mode="quick"):
        super().__init__()
        self.mode = mode

    def run(self):
        try:
            report = {"system": system_info(), "scan_type": self.mode, "tools": installed_tools_status(), "incident_sources": incident_sources_status()}
            self.progress.emit(5, "Detectando sistema y herramientas...")
            self.log.emit("Sistema detectado: " + report["system"]["distro"])

            self.progress.emit(8, "Actualizando base de paquetes reportados...")
            malware_db, malware_meta = update_malware_db()
            report["malware_db"] = malware_meta
            self.log.emit(f"Base malware: {malware_meta.get('count', 0)} entradas ({malware_meta.get('source')})")
            self.log.emit("Fuentes: lenucksi/aur-malware-check + hilos CachyOS/Garuda en pestaña Fuentes")
            if malware_meta.get("errors"):
                self.log.emit("Aviso: algunas fuentes no pudieron consultarse. Se usará cache local si existe.")

            self.progress.emit(12, "Listando paquetes AUR/external con pacman -Qm...")
            packages = get_aur_packages()
            report["aur_packages"] = packages
            self.log.emit(f"Paquetes AUR/externos detectados: {len(packages)}")

            analysis = []
            if self.mode == "full":
                total = max(len(packages), 1)
                for i, p in enumerate(packages, start=1):
                    pct = 12 + int((i / total) * 38)
                    self.progress.emit(pct, f"Analizando PKGBUILD: {p['name']}")
                    rpc = aur_rpc_info(p["name"])
                    text, url = ("", "")
                    result = dict(p)
                    is_reported = p["name"] in malware_db
                    result.update({
                        "aur_exists": rpc.get("exists", ""),
                        "maintainer": rpc.get("maintainer", ""),
                        "votes": rpc.get("votes", ""),
                        "popularity": rpc.get("popularity", ""),
                        "last_modified": rpc.get("last_modified", ""),
                        "pkgbuild_url": "",
                        "risk_score": 100 if is_reported else 0,
                        "risk_level": "Crítico" if is_reported else "No analizado",
                        "hits": [{"pattern": "PAQUETE REPORTADO EN BASE DE INCIDENTE AUR", "weight": 100, "count": 1}] if is_reported else [],
                        "incident_reported": is_reported,
                        "incident_status": "❌ REPORTADO / INFECTADO" if is_reported else "✅ No figura en base del incidente",
                    })
                    if rpc.get("exists") == "sí":
                        text, url = download_pkgbuild(p["name"])
                        if text:
                            a = analyze_pkgbuild_text(text)
                            result.update(a)
                            result["pkgbuild_url"] = url
                    analysis.append(result)
                    if result.get("risk_level") in ["Alto", "Crítico"]:
                        self.log.emit(f"ALERTA {result['risk_level']}: {p['name']}")
            else:
                for p in packages:
                    is_reported = p["name"] in malware_db
                    result = dict(p)
                    result.update({
                        "aur_exists": "no analizado",
                        "maintainer": "",
                        "risk_score": 100 if is_reported else 0,
                        "risk_level": "Crítico" if is_reported else "No analizado",
                        "hits": [{"pattern": "PAQUETE REPORTADO EN BASE DE INCIDENTE AUR", "weight": 100, "count": 1}] if is_reported else [],
                        "incident_reported": is_reported,
                        "incident_status": "❌ REPORTADO / INFECTADO" if is_reported else "✅ No figura en base del incidente",
                    })
                    analysis.append(result)

            report["aur_analysis"] = analysis

            self.progress.emit(58, "Ejecutando arch-audit...")
            report["arch_audit"] = run_arch_audit()

            self.progress.emit(68, "Revisando conexiones activas...")
            report["connections"] = active_connections()

            self.progress.emit(73, "Analizando reputación de IPs externas...")
            report["ip_reputation"] = analyze_ip_reputation(report["connections"])

            self.progress.emit(78, "Revisando servicios systemd...")
            report["services"] = services_info()

            self.progress.emit(86, "Revisando puertos abiertos...")
            report["ports"] = ports_info()

            if self.mode == "full":
                self.progress.emit(88, "Ejecutando chequeo comunitario aur-malware-check...")
                report["external_aur_check"] = run_external_aur_malware_check()

                self.progress.emit(92, "Revisando integridad pacman -Qkk...")
                report["integrity"] = pacman_integrity()
                self.progress.emit(96, "Revisando persistencia básica...")
                report["persistence"] = persistence_checks()
            else:
                report["external_aur_check"] = {}
                report["integrity"] = {}
                report["persistence"] = {}

            self.progress.emit(100, "Escaneo finalizado.")
            self.done.emit(report)
        except Exception as e:
            self.failed.emit(str(e))


def get_app_icon():
    if APP_ICON_PATH.exists():
        return QIcon(str(APP_ICON_PATH))
    return QIcon.fromTheme("security-high")


def available_screen_geometry():
    screen = QApplication.screenAt(QCursor.pos()) or QApplication.primaryScreen()
    return screen.availableGeometry() if screen else None


def fit_size_to_screen(preferred_w, preferred_h, min_w=760, min_h=520, width_ratio=0.92, height_ratio=0.88):
    geo = available_screen_geometry()
    if not geo:
        return preferred_w, preferred_h
    width = min(preferred_w, int(geo.width() * width_ratio))
    height = min(preferred_h, int(geo.height() * height_ratio))
    width = max(min(min_w, geo.width()), width)
    height = max(min(min_h, geo.height()), height)
    return width, height


class MainWindow(QMainWindow):
    def __init__(self, start_minimized=False):
        super().__init__()
        self.setWindowTitle(APP_NAME + " - GUI Portable")
        self.setWindowIcon(get_app_icon())
        initial_w, initial_h = fit_size_to_screen(1180, 760)
        self.resize(initial_w, initial_h)
        self.setMinimumSize(min(720, initial_w), min(520, initial_h))
        self.start_minimized = start_minimized
        self.report = {}
        self.worker = None
        self.last_report_paths = {}
        self.tray_icon = None
        self.tray_timer = None
        self.pacman_log_position = 0
        self.guard_enabled = True
        self.guard_popups = []
        self.remove_processes = []
        self.control_buttons = []
        self.controls_layout = None

        self.setStyleSheet("""
        QMainWindow, QWidget { background-color: #07101d; color: #e8eef5; font-family: Arial; }
        QGroupBox { border: 1px solid #26384f; border-radius: 10px; margin-top: 10px; padding: 10px; font-weight: bold; }
        QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; }
        QPushButton { background-color: #1266aa; color: white; border: 0; border-radius: 8px; padding: 10px 14px; font-weight: bold; }
        QPushButton:hover { background-color: #1793ff; }
        QPushButton:disabled { background-color: #334155; color: #94a3b8; }
        QPlainTextEdit, QTableWidget { background-color: #0b1320; border: 1px solid #26384f; border-radius: 8px; color: #e8eef5; }
        QHeaderView::section { background-color: #101a28; color: white; padding: 6px; border: 1px solid #26384f; }
        QProgressBar { border: 1px solid #26384f; border-radius: 8px; text-align: center; background: #0b1320; }
        QProgressBar::chunk { background-color: #1793ff; border-radius: 8px; }
        QLabel#Logo { font-size: 58px; }
        QLabel#Title { font-size: 26px; font-weight: bold; }
        QLabel#Risk { font-size: 22px; font-weight: bold; color: #ffd400; }
        """)

        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        self.header = QGroupBox("Sistema detectado")
        h = QGridLayout(self.header)
        self.logo = QLabel("🐧")
        self.logo.setObjectName("Logo")
        self.title = QLabel(APP_NAME)
        self.title.setObjectName("Title")
        self.sysinfo_label = QLabel("")
        self.sysinfo_label.setWordWrap(True)
        self.risk_label = QLabel("Riesgo: sin escaneo")
        self.risk_label.setObjectName("Risk")
        self.risk_label.setWordWrap(True)

        h.addWidget(self.logo, 0, 0, 2, 1)
        h.addWidget(self.title, 0, 1)
        h.addWidget(self.sysinfo_label, 1, 1)
        h.addWidget(self.risk_label, 0, 2, 2, 1)
        h.setColumnStretch(1, 1)

        root.addWidget(self.header)

        controls = QGridLayout()
        controls.setSpacing(8)
        self.controls_layout = controls
        self.btn_quick = QPushButton("Escaneo rápido")
        self.btn_full = QPushButton("Escaneo completo")
        self.btn_tools = QPushButton("Ver herramientas")
        self.btn_sources = QPushButton("Fuentes del incidente")
        self.btn_update_db = QPushButton("Actualizar listas")
        self.btn_guard = QPushButton("Guardia AUR: ON")
        self.btn_safe_install = QPushButton("Instalar AUR seguro")
        self.btn_remove_pkg = QPushButton("Desinstalar paquete riesgoso")
        self.btn_report = QPushButton("Generar reporte HTML/PDF")
        self.btn_open_folder = QPushButton("Abrir carpeta reportes")
        self.btn_quick.clicked.connect(lambda: self.start_scan("quick"))
        self.btn_full.clicked.connect(lambda: self.start_scan("full"))
        self.btn_tools.clicked.connect(self.show_tools)
        self.btn_sources.clicked.connect(self.show_sources)
        self.btn_update_db.clicked.connect(self.update_lists_now)
        self.btn_guard.clicked.connect(self.toggle_guard)
        self.btn_safe_install.clicked.connect(self.safe_install_dialog)
        self.btn_remove_pkg.clicked.connect(self.remove_package_dialog)
        self.btn_report.clicked.connect(self.save_report)
        self.btn_open_folder.clicked.connect(self.open_reports_folder)
        buttons = [
            self.btn_quick,
            self.btn_full,
            self.btn_tools,
            self.btn_sources,
            self.btn_update_db,
            self.btn_guard,
            self.btn_safe_install,
            self.btn_remove_pkg,
            self.btn_report,
            self.btn_open_folder,
        ]
        self.control_buttons = buttons
        for index, button in enumerate(self.control_buttons):
            button.setMinimumHeight(40)
            button.setMaximumHeight(48)
            controls.addWidget(button, index // 5, index % 5)
        for col in range(5):
            controls.setColumnStretch(col, 1)
        root.addLayout(controls)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.status = QLabel("Listo.")
        root.addWidget(self.progress)
        root.addWidget(self.status)

        self.tabs = QTabWidget()
        self.table_aur = QTableWidget(0, 9)
        self.table_aur.setHorizontalHeaderLabels(["Estado", "Paquete", "Versión", "AUR", "Mantenedor", "Riesgo", "Puntaje", "Motivos", "Acción"])
        self.configure_table(self.table_aur)
        self.tabs.addTab(self.table_aur, "Paquetes AUR")

        self.txt_connections = QPlainTextEdit()
        self.txt_connections.setReadOnly(True)
        self.tabs.addTab(self.txt_connections, "Conexiones")

        self.table_iprep = QTableWidget(0, 10)
        self.table_iprep.setHorizontalHeaderLabels(["Estado", "IP", "Tipo", "Riesgo", "RDAP/ASN", "VirusTotal", "AbuseIPDB", "OTX", "Motivo", "Procesos"])
        self.configure_table(self.table_iprep)
        self.tabs.addTab(self.table_iprep, "Reputación IP")

        self.txt_services = QPlainTextEdit()
        self.txt_services.setReadOnly(True)
        self.tabs.addTab(self.txt_services, "Servicios")

        self.txt_audit = QPlainTextEdit()
        self.txt_audit.setReadOnly(True)
        self.tabs.addTab(self.txt_audit, "arch-audit / Integridad")

        self.txt_sources = QPlainTextEdit()
        self.txt_sources.setReadOnly(True)
        self.tabs.addTab(self.txt_sources, "Fuentes")

        self.txt_log = QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        self.tabs.addTab(self.txt_log, "Log")

        root.addWidget(self.tabs)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(central)
        self.setCentralWidget(scroll)

        self.refresh_system_header()
        self.txt_sources.setPlainText(self.render_sources_text())
        self.setup_tray_guard()
        self.reflow_controls()
        if self.start_minimized:
            if self.tray_icon and self.tray_icon.isVisible():
                QTimer.singleShot(0, self.hide)
            else:
                QTimer.singleShot(0, self.showMinimized)
            QTimer.singleShot(
                1200,
                lambda: self.show_guard_popup(
                    "Guardia AUR activa",
                    "AUR Sentinel quedó ejecutándose en segundo plano. Monitorea instalaciones y actualizaciones de paquetes.",
                    "info",
                    7000,
                ),
            )

    def configure_table(self, table):
        table.setAlternatingRowColors(True)
        table.setWordWrap(False)
        table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        table.horizontalHeader().setStretchLastSection(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        table.verticalHeader().setVisible(False)

    def reflow_controls(self):
        if not self.controls_layout or not self.control_buttons:
            return
        width = max(1, self.width())
        if width < 820:
            columns = 2
        elif width < 1120:
            columns = 3
        else:
            columns = 5
        while self.controls_layout.count():
            item = self.controls_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.setParent(None)
        for index, button in enumerate(self.control_buttons):
            self.controls_layout.addWidget(button, index // columns, index % columns)
        for col in range(5):
            self.controls_layout.setColumnStretch(col, 1 if col < columns else 0)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.reflow_controls()

    def refresh_system_header(self):
        info = system_info()
        self.logo.setText(info["logo"])
        self.sysinfo_label.setText(
            f"{info['distro']} | Kernel {info['kernel']} | Escritorio {info['desktop']} | AUR helper: {info['aur_helper']} | {info['usuario']}@{info['hostname']}"
        )

    def render_sources_text(self):
        sources = self.report.get("incident_sources") if self.report else incident_sources_status()
        lines = []
        lines.append("FUENTES DINÁMICAS Y DE SEGUIMIENTO DEL INCIDENTE AUR")
        lines.append("=" * 70)
        lines.append("")
        lines.append("Base de datos usada por el análisis:")
        lines.append("IMPORTANTE: se consulta el hilo oficial aur-general de Arch y la lista viva md.archlinux.org cuando hay Internet.")
        for url in sources.get("database_urls", []):
            lines.append(f"- {url}")
        lines.append("")
        lines.append(f"Cache local: {sources.get('local_cache')}")
        lines.append("")
        lines.append("Fuentes informativas:")
        for item in sources.get("links", []):
            lines.append(f"- {item.get('name')}")
            lines.append(f"  {item.get('url')}")
            lines.append(f"  {item.get('note')}")
            lines.append("")
        lines.append("Cómo actualizar la lista desde el programa:")
        lines.append("1) Presiona el botón 'Actualizar listas'.")
        lines.append("2) Luego ejecuta 'Escaneo completo' nuevamente.")
        lines.append("3) Si no hay Internet, el programa usará la cache local si existe.")
        lines.append("")
        lines.append("Recomendación:")
        lines.append(sources.get("recommendation", "Reejecuta el análisis periódicamente."))
        return "\n".join(lines)

    def show_guard_popup(self, title, message, level="info", timeout_ms=15000):
        """
        Popup visual persistente:
        - queda visible durante el análisis o resultado,
        - se cierra con click en "Cerrar",
        - o se cierra automáticamente luego de 15 segundos.
        """
        dialog = QDialog(None)
        dialog.setWindowTitle(title)
        dialog.setModal(False)
        dialog.setWindowFlags(
            dialog.windowFlags()
            | Qt.WindowStaysOnTopHint
            | Qt.Tool
        )
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)

        colors = {
            "ok": ("#003a1d", "#00d26a", "✅"),
            "warning": ("#4d4100", "#ffd400", "⚠️"),
            "error": ("#4d0000", "#ff3131", "❌"),
            "info": ("#0b1320", "#1793ff", "🛡️"),
        }
        bg, border, icon = colors.get(level, colors["info"])

        dialog.setStyleSheet(f"""
        QDialog {{
            background-color: {bg};
            color: #e8eef5;
            border: 2px solid {border};
            border-radius: 12px;
        }}
        QLabel {{
            color: #e8eef5;
            font-size: 14px;
        }}
        QLabel#PopupTitle {{
            font-size: 20px;
            font-weight: bold;
        }}
        QPushButton {{
            background-color: {border};
            color: #07101d;
            border: 0;
            border-radius: 8px;
            padding: 8px 16px;
            font-weight: bold;
        }}
        """)

        layout = QVBoxLayout(dialog)
        title_label = QLabel(f"{icon} {title}")
        title_label.setObjectName("PopupTitle")
        title_label.setWordWrap(True)

        msg_label = QLabel(message)
        msg_label.setWordWrap(True)
        msg_label.setTextInteractionFlags(Qt.TextSelectableByMouse)

        countdown = QLabel("Esta alerta se cerrará automáticamente en 15 segundos o al presionar Cerrar.")
        countdown.setWordWrap(True)

        btn = QPushButton("Cerrar")
        btn.clicked.connect(dialog.close)

        layout.addWidget(title_label)
        layout.addWidget(msg_label)
        layout.addWidget(countdown)
        layout.addWidget(btn, alignment=Qt.AlignRight)

        remaining = {"sec": max(1, timeout_ms // 1000)}
        timer = QTimer(dialog)

        def tick():
            remaining["sec"] -= 1
            if remaining["sec"] <= 0:
                timer.stop()
                dialog.close()
            else:
                countdown.setText(f"Esta alerta se cerrará automáticamente en {remaining['sec']} segundos o al presionar Cerrar.")

        timer.timeout.connect(tick)
        timer.start(1000)

        popup_w, popup_h = fit_size_to_screen(560, 280, min_w=320, min_h=220, width_ratio=0.86, height_ratio=0.42)
        dialog.resize(popup_w, popup_h)
        geo = available_screen_geometry()
        if geo:
            margin = 24
            dialog.move(
                geo.right() - dialog.width() - margin,
                geo.bottom() - dialog.height() - margin,
            )
        self.guard_popups.append(dialog)
        dialog.destroyed.connect(lambda *_: self.guard_popups.remove(dialog) if dialog in self.guard_popups else None)
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()
        QApplication.alert(self, timeout_ms)
        return dialog

    def setup_tray_guard(self):
        """
        Deja el programa en bandeja y monitorea pacman.log.
        Limitación: detecta instalaciones cuando quedan registradas en pacman.log.
        Para bloquear antes de instalar, usar wrappers aur-guard-yay / aur-guard-paru incluidos en tools/.
        """
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray_icon = QSystemTrayIcon(get_app_icon(), self)
            self.tray_icon.setToolTip("AUR Sentinel Audit - Guardia AUR activa")
            self.tray_icon.activated.connect(self.on_tray_activated)
            menu = QMenu()

            show_action = QAction("Mostrar AUR Sentinel", self)
            show_action.triggered.connect(self.showNormal)
            menu.addAction(show_action)

            scan_action = QAction("Escaneo rápido", self)
            scan_action.triggered.connect(lambda: self.start_scan("quick"))
            menu.addAction(scan_action)

            guard_action = QAction("Activar/Desactivar Guardia", self)
            guard_action.triggered.connect(self.toggle_guard)
            menu.addAction(guard_action)

            quit_action = QAction("Salir", self)
            quit_action.triggered.connect(QApplication.instance().quit)
            menu.addAction(quit_action)

            self.tray_icon.setContextMenu(menu)
            self.tray_icon.show()
        else:
            self.append_log("El entorno gráfico no expone bandeja del sistema. La Guardia AUR seguirá activa con popups/notificaciones.")

        try:
            if PACMAN_LOG.exists():
                self.pacman_log_position = PACMAN_LOG.stat().st_size
        except Exception:
            self.pacman_log_position = 0

        self.tray_timer = QTimer(self)
        self.tray_timer.timeout.connect(self.check_pacman_log_for_aur_events)
        self.tray_timer.start(10000)
        self.append_log("Guardia AUR activa en bandeja. Monitoreando /var/log/pacman.log cada 10 segundos.")

    def on_tray_activated(self, reason):
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.showNormal()
            self.raise_()
            self.activateWindow()

    def toggle_guard(self):
        self.guard_enabled = not self.guard_enabled
        self.btn_guard.setText("Guardia AUR: ON" if self.guard_enabled else "Guardia AUR: OFF")
        self.append_log("Guardia AUR activada." if self.guard_enabled else "Guardia AUR desactivada.")

    def check_pacman_log_for_aur_events(self):
        if not self.guard_enabled:
            return
        try:
            if not PACMAN_LOG.exists():
                return
            size = PACMAN_LOG.stat().st_size
            if size < self.pacman_log_position:
                self.pacman_log_position = 0
            if size == self.pacman_log_position:
                return
            with PACMAN_LOG.open("r", encoding="utf-8", errors="ignore") as f:
                f.seek(self.pacman_log_position)
                new_data = f.read()
                self.pacman_log_position = f.tell()

            interesting = []
            for line in new_data.splitlines():
                if " installed " in line or " upgraded " in line:
                    interesting.append(line)

            if interesting:
                paquetes = "\n".join(interesting[-5:])
                self.append_log("Guardia AUR detectó instalación/actualización de paquetes. Ejecutando escaneo rápido...")
                self.append_log(paquetes)
                popup_msg = (
                    "Se detectó una instalación o actualización registrada en pacman.log.\n\n"
                    "AUR Sentinel ejecutará controles de seguridad:\n"
                    "1) Base de paquetes reportados del incidente AUR\n"
                    "2) Firmas atomic-lockfile / js-digest / eBPF\n"
                    "3) Revisión de conexiones activas\n"
                    "4) Generación automática de reporte\n\n"
                    "Últimos eventos detectados:\n" + paquetes
                )
                self.show_guard_popup("Guardia AUR detectó cambios", popup_msg, "warning", 15000)

                if self.tray_icon:
                    self.tray_icon.showMessage(
                        "🛡️ Guardia AUR detectó cambios",
                        "Se detectó instalación/actualización. Ejecutando análisis de seguridad.",
                        QSystemTrayIcon.Warning,
                        15000
                    )
                if not self.worker or not self.worker.isRunning():
                    self.start_scan("quick")
        except Exception as e:
            self.append_log("Error en guardia AUR: " + str(e))

    def append_log(self, text):
        self.txt_log.appendPlainText(f"[{dt.datetime.now().strftime('%H:%M:%S')}] {text}")

    def set_busy(self, busy):
        self.btn_quick.setDisabled(busy)
        self.btn_full.setDisabled(busy)
        self.btn_tools.setDisabled(busy)
        self.btn_report.setDisabled(busy)
        self.btn_update_db.setDisabled(busy)
        self.btn_safe_install.setDisabled(busy)
        self.btn_remove_pkg.setDisabled(busy)

    def start_scan(self, mode):
        if not is_arch_like():
            QMessageBox.warning(self, "Advertencia", "No parece ser Arch Linux o una derivada con pacman. Algunas funciones pueden fallar.")
        self.set_busy(True)
        self.progress.setValue(0)
        self.status.setText("Iniciando escaneo...")
        self.txt_log.clear()
        self.append_log("Iniciando escaneo " + ("completo" if mode == "full" else "rápido"))
        self.worker = ScanWorker(mode)
        self.worker.progress.connect(self.on_progress)
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self.on_scan_done)
        self.worker.failed.connect(self.on_scan_failed)
        self.worker.start()

    def on_progress(self, value, text):
        self.progress.setValue(value)
        self.status.setText(text)
        self.append_log(text)

    def on_scan_done(self, report):
        self.report = report
        self.set_busy(False)
        self.status.setText("Escaneo finalizado.")
        self.populate_report()
        try:
            self.save_report(auto=True)
            riesgo = general_risk(self.report)
            criticos = [p for p in self.report.get("aur_analysis", []) if p.get("risk_level") in ["Crítico", "Alto"] or p.get("incident_reported")]
            ip_sospechosas = [x for x in self.report.get("ip_reputation", {}).get("results", []) if x.get("risk") in ["Alto", "Medio"]]
            if criticos or ip_sospechosas:
                titulo = "⚠️ Guardia AUR: revisar alertas"
                cuerpo = f"Controles finalizados con riesgo {riesgo}.\nPaquetes/firmas: {len(criticos)} | IPs a revisar: {len(ip_sospechosas)}"
                icono = QSystemTrayIcon.Warning
            else:
                titulo = "✅ Guardia AUR: controles aprobados"
                cuerpo = "No se detectaron firmas críticas ni paquetes reportados. Reporte HTML/PDF generado."
                icono = QSystemTrayIcon.Information

            nivel_popup = "warning" if (criticos or ip_sospechosas) else "ok"
            self.show_guard_popup(titulo, cuerpo + "\n\nSe generó reporte HTML y PDF automáticamente.", nivel_popup, 15000)

            if self.tray_icon:
                self.tray_icon.showMessage(titulo, cuerpo, icono, 15000)

            QMessageBox.information(self, "Finalizado", cuerpo + "\n\nSe generó reporte HTML y PDF automáticamente.")
        except Exception as e:
            self.append_log("ERROR generando reporte automático: " + str(e))
            QMessageBox.warning(self, "Escaneo finalizado", "El escaneo terminó, pero hubo un error generando el reporte automático. Revisa la pestaña Log.")

    def on_scan_failed(self, error):
        self.set_busy(False)
        QMessageBox.critical(self, "Error", error)
        self.append_log("ERROR: " + error)

    def populate_report(self):
        info = self.report.get("system", {})
        self.logo.setText(info.get("logo", "🐧"))
        self.sysinfo_label.setText(
            f"{info.get('distro')} | Kernel {info.get('kernel')} | Escritorio {info.get('desktop')} | AUR helper: {info.get('aur_helper')} | {info.get('usuario')}@{info.get('hostname')}"
        )
        self.risk_label.setText("Riesgo: " + general_risk(self.report))

        aur = self.report.get("aur_analysis", [])
        self.table_aur.setRowCount(len(aur))
        for row, p in enumerate(aur):
            hits = ", ".join([h["pattern"] for h in p.get("hits", [])]) or "-"
            status = p.get("incident_status") or ("❌ REPORTADO / INFECTADO" if p.get("incident_reported") else "✅ No figura en base del incidente")
            values = [status, p.get("name", ""), p.get("version", ""), p.get("aur_exists", ""), p.get("maintainer", ""), p.get("risk_level", ""), str(p.get("risk_score", "")), hits]
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                if col in [0, 5, 6]:
                    item.setTextAlignment(Qt.AlignCenter)
                if col == 0:
                    if "✅" in str(val):
                        item.setToolTip("No aparece en la base de paquetes reportados por el incidente AUR consultada.")
                    else:
                        item.setToolTip("Este paquete aparece en la base de paquetes reportados. Revisar urgente.")
                self.table_aur.setItem(row, col, item)
            pkg_name = str(p.get("name", "")).strip()
            removable = bool(p.get("incident_reported")) or p.get("risk_level") in ["Crítico", "Alto"]
            btn = QPushButton("Remover" if removable else "Seguro")
            btn.setToolTip(
                "Desinstalar este paquete y limpiar cache de yay/paru."
                if removable
                else "El paquete no está marcado como comprometido o crítico."
            )
            btn.setEnabled(removable and bool(pkg_name))
            btn.clicked.connect(lambda _checked=False, pkg=pkg_name, data=p: self.remove_package_dialog(pkg, data))
            self.table_aur.setCellWidget(row, 8, btn)
        self.table_aur.resizeColumnsToContents()
        self.table_aur.horizontalHeader().setSectionResizeMode(7, QHeaderView.Stretch)
        self.table_aur.setColumnWidth(8, max(96, self.table_aur.columnWidth(8)))

        self.txt_connections.setPlainText(self.report.get("connections", {}).get("raw_limited", ""))

        iprep = self.report.get("ip_reputation", {}).get("results", [])
        self.table_iprep.setRowCount(len(iprep))
        for row, r in enumerate(iprep):
            vt = r.get("vt", {})
            abuse = r.get("abuseipdb", {})
            otx = r.get("otx", {})
            vt_txt = vt.get("status", "")
            if vt.get("malicious") is not None:
                vt_txt = f"M:{vt.get('malicious')} S:{vt.get('suspicious')} H:{vt.get('harmless')}"
            abuse_txt = abuse.get("status", "")
            if abuse.get("abuse_score") is not None:
                abuse_txt = f"Score:{abuse.get('abuse_score')} Reports:{abuse.get('total_reports')}"
            otx_txt = otx.get("status", "")
            if otx.get("pulse_count") is not None:
                otx_txt = f"Pulses:{otx.get('pulse_count')} {otx.get('first_pulse', '')}"
            rdap = r.get("rdap", {})
            rdap_txt = rdap.get("name") or rdap.get("handle") or rdap.get("status", "")
            values = [
                r.get("status", ""),
                r.get("ip", ""),
                r.get("type", ""),
                r.get("risk", ""),
                rdap_txt,
                vt_txt,
                abuse_txt,
                otx_txt,
                r.get("reason", ""),
                ", ".join(r.get("related_processes", [])),
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                if col in [0, 3]:
                    item.setTextAlignment(Qt.AlignCenter)
                self.table_iprep.setItem(row, col, item)
        self.table_iprep.resizeColumnsToContents()
        self.table_iprep.horizontalHeader().setSectionResizeMode(8, QHeaderView.Stretch)

        services = self.report.get("services", {})
        self.txt_services.setPlainText("SERVICIOS EN EJECUCIÓN\n\n" + services.get("running", "") + "\n\nSERVICIOS HABILITADOS\n\n" + services.get("enabled", ""))
        audit = self.report.get("arch_audit", {}).get("output", "")
        integ = "\n".join(self.report.get("integrity", {}).get("warnings", [])) or self.report.get("integrity", {}).get("raw_limited", "")
        self.txt_audit.setPlainText("ARCH-AUDIT\n\n" + audit + "\n\nINTEGRIDAD PACMAN -QKK\n\n" + integ)
        self.txt_sources.setPlainText(self.render_sources_text())

    def update_lists_now(self):
        self.status.setText("Actualizando listas comunitarias...")
        self.append_log("Actualizando listas comunitarias del incidente...")
        result = force_update_malware_db_for_ui()
        self.txt_sources.setPlainText(self.render_sources_text())
        if result.get("ok"):
            QMessageBox.information(
                self,
                "Listas actualizadas",
                f"Base actualizada correctamente.\nEntradas detectadas: {result.get('count')}\nCache local:\n{result.get('cache')}"
            )
            self.append_log(f"Listas actualizadas: {result.get('count')} entradas")
        else:
            QMessageBox.warning(
                self,
                "No se pudo actualizar",
                "No se pudo descargar la base remota. Si existe cache local, se seguirá usando. Revisa la pestaña Fuentes."
            )
            self.append_log("No se pudo actualizar la base remota")
        self.status.setText("Listo.")

    def show_sources(self):
        self.tabs.setCurrentWidget(self.txt_sources)
        sources = self.report.get("incident_sources") if self.report else incident_sources_status()
        first_url = sources.get("links", [{}])[0].get("url")
        reply = QMessageBox.question(
            self,
            "Fuentes del incidente",
            "Se abrirá la pestaña Fuentes dentro del programa.\n\n¿Deseas abrir también el hilo principal de CachyOS en el navegador?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes and first_url:
            subprocess.Popen(["xdg-open", first_url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def show_tools(self):
        status = installed_tools_status()
        msg = "\n".join([f"{'✅' if ok else '❌'} {tool}" for tool, ok in status.items()])
        QMessageBox.information(self, "Herramientas detectadas", msg)

    def save_report(self, auto=False):
        if not self.report:
            if not auto:
                QMessageBox.warning(self, "Sin datos", "Primero ejecuta un escaneo.")
            return

        html_path, txt_path, json_path, pdf_path = generate_html(self.report)
        self.last_report_paths = {
            "html": html_path,
            "txt": txt_path,
            "json": json_path,
            "pdf": pdf_path,
        }
        self.append_log(f"Reporte HTML: {html_path}")
        self.append_log(f"Reporte PDF: {pdf_path}")

        if auto:
            return

        msg = QMessageBox(self)
        msg.setWindowTitle("Reporte generado")
        msg.setText("El reporte fue generado correctamente.")
        msg.setInformativeText(
            f"HTML:\n{html_path}\n\nPDF:\n{pdf_path}\n\nTXT:\n{txt_path}\n\nJSON:\n{json_path}\n\n¿Qué deseas abrir?"
        )
        btn_html = msg.addButton("Abrir HTML", QMessageBox.AcceptRole)
        btn_pdf = msg.addButton("Abrir PDF", QMessageBox.ActionRole)
        btn_folder = msg.addButton("Abrir carpeta", QMessageBox.ActionRole)
        msg.addButton("Cerrar", QMessageBox.RejectRole)
        msg.exec()

        clicked = msg.clickedButton()
        if clicked == btn_html:
            subprocess.Popen(["xdg-open", html_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif clicked == btn_pdf:
            subprocess.Popen(["xdg-open", pdf_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif clicked == btn_folder:
            subprocess.Popen(["xdg-open", str(REPORT_DIR)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def safe_install_dialog(self):
        pkg, ok = QInputDialog.getText(
            self,
            "Instalar paquete AUR seguro",
            "Nombre del paquete AUR a revisar antes de instalar:"
        )
        pkg = str(pkg).strip()
        if not ok or not pkg:
            return

        helper = detect_aur_helper()
        if helper == "solo pacman":
            helper = "yay" if which("yay") else ("paru" if which("paru") else "")

        if not helper:
            QMessageBox.warning(
                self,
                "AUR helper no detectado",
                "No se detectó yay ni paru. Instala uno o usa tools/aur-guard-yay manualmente."
            )
            return

        wrapper = Path("tools/aur-guard").resolve()
        if not wrapper.exists():
            QMessageBox.warning(self, "Wrapper no encontrado", "No se encontró tools/aur-guard.")
            return

        QMessageBox.information(
            self,
            "Guardia AUR interactiva",
            "Se abrirá el control interactivo.\\n\\n"
            "El paquete será revisado en este orden:\\n"
            "1) Lista de paquetes reportados\\n"
            "2) PKGBUILD completo\\n"
            "3) Firmas críticas atomic-lockfile/js-digest/eBPF\\n"
            "4) Confirmación manual\\n\\n"
            "Solo si pasa los controles se permitirá continuar."
        )
        subprocess.Popen([str(wrapper), pkg, helper], cwd=str(Path(".").resolve()))

    def remove_package_dialog(self, pkg=None, package_data=None):
        if not pkg:
            pkg, ok = QInputDialog.getText(self, "Desinstalar paquete riesgoso", "Nombre del paquete a remover completamente:")
            pkg = str(pkg).strip()
            if not ok or not pkg:
                return

        pkg = str(pkg).strip()
        if not re.fullmatch(r"[A-Za-z0-9@._+:-]{2,}", pkg):
            QMessageBox.warning(self, "Paquete inválido", "El nombre del paquete contiene caracteres no permitidos.")
            return

        risk = (package_data or {}).get("risk_level", "No especificado")
        status = (package_data or {}).get("incident_status", "")
        msg = (
            f"Se removerá el paquete: {pkg}\n\n"
            f"Estado: {status or 'seleccionado manualmente'}\n"
            f"Riesgo: {risk}\n\n"
            "Acciones:\n"
            f"1) pacman -Rns {pkg}\n"
            "2) limpiar cache local de yay/paru para ese paquete\n"
            "3) mostrar el proceso completo en pantalla\n\n"
            "¿Continuar?"
        )
        if QMessageBox.question(self, "Confirmar desinstalación", msg, QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return

        self.run_package_removal(pkg)

    def run_package_removal(self, pkg):
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Removiendo paquete: {pkg}")
        remove_w, remove_h = fit_size_to_screen(820, 520, min_w=520, min_h=360, width_ratio=0.9, height_ratio=0.82)
        dialog.resize(remove_w, remove_h)

        layout = QVBoxLayout(dialog)
        title = QLabel(f"Proceso de desinstalación: {pkg}")
        title.setObjectName("PopupTitle")
        log_box = QPlainTextEdit()
        log_box.setReadOnly(True)
        close_btn = QPushButton("Cerrar")
        close_btn.setEnabled(False)
        close_btn.clicked.connect(dialog.close)

        layout.addWidget(title)
        layout.addWidget(log_box)
        layout.addWidget(close_btn, alignment=Qt.AlignRight)

        pkg_q = shlex.quote(pkg)
        cache_yay = shlex.quote(str(Path.home() / ".cache" / "yay" / pkg))
        cache_paru = shlex.quote(str(Path.home() / ".cache" / "paru" / "clone" / pkg))
        script = f"""
set -u
echo "[1/4] Verificando si el paquete está instalado: {pkg_q}"
if ! pacman -Q {pkg_q} >/dev/null 2>&1; then
  echo "[AVISO] El paquete no aparece instalado con pacman -Q."
  exit 0
fi

echo "[2/4] Solicitando desinstalación con pacman -Rns..."
if command -v pkexec >/dev/null 2>&1; then
  pkexec pacman -Rns --noconfirm {pkg_q}
else
  sudo pacman -Rns --noconfirm {pkg_q}
fi
REMOVE_CODE=$?

echo "[3/4] Limpiando cache local del paquete en yay/paru..."
rm -rf -- {cache_yay} {cache_paru}

echo "[4/4] Verificación final..."
if pacman -Q {pkg_q} >/dev/null 2>&1; then
  echo "[ALERTA] El paquete todavía aparece instalado. Revisa dependencias o errores anteriores."
  exit 10
fi

if [ "$REMOVE_CODE" -eq 0 ]; then
  echo "[OK] Paquete removido correctamente: {pkg_q}"
else
  echo "[ERROR] pacman terminó con código $REMOVE_CODE"
fi
exit "$REMOVE_CODE"
"""

        process = QProcess(dialog)
        process.setProcessChannelMode(QProcess.MergedChannels)
        self.remove_processes.append(process)

        def append_output():
            data = bytes(process.readAllStandardOutput()).decode("utf-8", errors="ignore")
            if data:
                log_box.appendPlainText(data.rstrip())
                self.append_log(data.rstrip())

        def finished(exit_code, _status):
            append_output()
            close_btn.setEnabled(True)
            if process in self.remove_processes:
                self.remove_processes.remove(process)
            if exit_code == 0:
                log_box.appendPlainText("\n[FINALIZADO] Desinstalación completada.")
                self.show_guard_popup("Paquete removido", f"{pkg} fue removido correctamente.", "ok", 12000)
                if self.report:
                    QTimer.singleShot(500, lambda: self.start_scan("quick") if not self.worker or not self.worker.isRunning() else None)
            else:
                log_box.appendPlainText(f"\n[FINALIZADO] El proceso terminó con código {exit_code}.")
                self.show_guard_popup("Revisar desinstalación", f"La remoción de {pkg} terminó con código {exit_code}. Revisa el detalle.", "warning", 15000)

        process.readyReadStandardOutput.connect(append_output)
        process.finished.connect(finished)
        dialog.show()

        self.tabs.setCurrentWidget(self.txt_log)
        self.append_log(f"Iniciando desinstalación guiada de {pkg}")
        log_box.appendPlainText(f"Iniciando desinstalación guiada de {pkg}...\n")
        process.start("bash", ["-lc", script])
        if not process.waitForStarted(3000):
            close_btn.setEnabled(True)
            log_box.appendPlainText("[ERROR] No se pudo iniciar el proceso de desinstalación.")
            if process in self.remove_processes:
                self.remove_processes.remove(process)

    def open_reports_folder(self):
        REPORT_DIR.mkdir(exist_ok=True)
        subprocess.Popen(["xdg-open", str(REPORT_DIR)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def closeEvent(self, event):
        if self.tray_icon and self.tray_icon.isVisible():
            self.hide()
            self.tray_icon.showMessage(
                "AUR Sentinel Audit",
                "El programa sigue ejecutándose en la bandeja.",
                QSystemTrayIcon.Information,
                3000
            )
            event.ignore()
        else:
            event.accept()
            QApplication.instance().quit()


def main():
    start_minimized = any(arg in ("--tray", "--minimized", "--background") for arg in sys.argv[1:])
    qt_argv = [sys.argv[0]] + [arg for arg in sys.argv[1:] if arg not in ("--tray", "--minimized", "--background")]
    app = QApplication(qt_argv)
    app.setApplicationName(APP_NAME)
    app.setQuitOnLastWindowClosed(False)
    win = MainWindow(start_minimized=start_minimized)
    if start_minimized:
        if win.tray_icon and win.tray_icon.isVisible():
            win.hide()
        else:
            win.showMinimized()
    else:
        win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
