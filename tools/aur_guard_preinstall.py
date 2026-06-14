#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import argparse, json, re, tarfile, tempfile
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.parse import quote

MALWARE_DB_URLS = [
    "https://md.archlinux.org/s/SxbqukK6IA/download",
    "https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/FGXPCB3ZVCJIV7FX323SBAX2JHYB7ZS4/",
    "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/package_list.txt",
    "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/malicious_npm_packages.txt",
    "https://paste.cachyos.org/73a714d",
]

CRITICAL_SIGNATURES = {
    "INCIDENTE_AUR_atomic_lockfile": [
        r"\bnpm\s+install\s+atomic-lockfile\b", r"\bpnpm\s+(install|add)\s+atomic-lockfile\b",
        r"\byarn\s+add\s+atomic-lockfile\b", r"\bbun\s+add\s+atomic-lockfile\b", r"\batomic-lockfile\b"],
    "INCIDENTE_AUR_js_digest_gsdigest": [
        r"\bnpm\s+install\s+js-digest\b", r"\bpnpm\s+(install|add)\s+js-digest\b",
        r"\bbun\s+add\s+js-digest\b", r"\bjs-digest\b", r"@gsdigest/gsdigest", r"\bgsdigest\b"],
    "BPF_rootkit_indicators": [r"/sys/fs/bpf/hidden_", r"\bbpftool\b", r"\bbpftrace\b", r"\bebpf\b", r"\brootkit\b"],
    "hooks_deps_suspicious": [r"src/hooks/deps", r"\.install\b"],
    "dangerous_shell_patterns": [
        r"curl\s+.*\|\s*(bash|sh)", r"wget\s+.*\|\s*(bash|sh)", r"base64\s+(-d|--decode)",
        r"\beval\b", r"bash\s+-c", r"python[0-9.]*\s+-c", r"\bcrontab\b", r"systemctl\s+enable"],
}

def fetch_url(url, binary=False, timeout=25):
    req = Request(url, headers={"User-Agent": "AUR-Sentinel-Guard/2.6"})
    with urlopen(req, timeout=timeout) as r:
        data = r.read()
    return data if binary else data.decode("utf-8", errors="ignore")

def parse_pkg_names(txt):
    names=set()
    for pat in [
        r"aur\.archlinux\.org/packages/([A-Za-z0-9@._+:-]+)",
        r"aur\.archlinux\.org/cgit/aur\.git/commit/\?h=([A-Za-z0-9@._+:-]+)",
        r"aur\.archlinux\.org/([A-Za-z0-9@._+:-]+)\.git",
        r"activity\?ref=([A-Za-z0-9@._+:-]+)",
    ]:
        for m in re.findall(pat, txt, flags=re.I):
            names.add(m.strip().lower())
    for raw in txt.splitlines():
        token = re.split(r"[\s,;]+", raw.strip().strip("'\"`"))[0]
        if re.fullmatch(r"[A-Za-z0-9@._+:-]{2,}", token) and token.lower() not in {"html","head","body","title","href"}:
            names.add(token.lower())
    return names

def update_db(cache):
    cache.parent.mkdir(parents=True, exist_ok=True)
    alln=set(); raw=[]
    for url in MALWARE_DB_URLS:
        try:
            txt=fetch_url(url)
            names=parse_pkg_names(txt)
            alln |= names
            raw.append(f"# Fuente: {url}\n# Extraidos: {len(names)}\n" + "\n".join(sorted(names)) + "\n")
        except Exception:
            pass
    if alln:
        cache.write_text("\n".join(raw), encoding="utf-8")
        return alln
    if cache.exists():
        return parse_pkg_names(cache.read_text(encoding="utf-8", errors="ignore"))
    return set()

def aur_rpc(pkg):
    data=json.loads(fetch_url(f"https://aur.archlinux.org/rpc/v5/info/{quote(pkg)}"))
    if data.get("resultcount",0)<1:
        raise RuntimeError(f"El paquete '{pkg}' no existe en AUR.")
    return data["results"][0]

def download_snapshot(pkg, tmp):
    info=aur_rpc(pkg)
    url="https://aur.archlinux.org"+info.get("URLPath", f"/cgit/aur.git/snapshot/{quote(pkg)}.tar.gz")
    tar_path=tmp/f"{pkg}.tar.gz"
    tar_path.write_bytes(fetch_url(url, binary=True, timeout=35))
    out=tmp/"src"; out.mkdir()
    with tarfile.open(tar_path, "r:gz") as tar:
        tar.extractall(out)
    return out

def scan(root):
    findings=[]
    for p in root.rglob("*"):
        if p.is_file() and p.stat().st_size <= 2_000_000:
            txt=p.read_text(encoding="utf-8", errors="ignore")
            rel=str(p.relative_to(root))
            for sig, pats in CRITICAL_SIGNATURES.items():
                for pat in pats:
                    if re.search(pat, txt, flags=re.I|re.M|re.S):
                        findings.append({"signature":sig,"pattern":pat,"file":rel})
    return findings

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("package")
    ap.add_argument("--cache", default="data/aur_malware_package_list.txt")
    ap.add_argument("--json", action="store_true")
    args=ap.parse_args()
    pkg=args.package.strip()
    res={"package":pkg,"blocked":False,"passed":False,"reasons":[],"findings":[]}
    try:
        reported=update_db(Path(args.cache))
        if pkg.lower() in reported:
            res.update(blocked=True, reasons=["El paquete aparece en listas reportadas del incidente AUR."])
            print(json.dumps(res, indent=2, ensure_ascii=False) if args.json else "❌ BLOQUEADO: aparece en listas reportadas.")
            return 20
        with tempfile.TemporaryDirectory() as td:
            findings=scan(download_snapshot(pkg, Path(td)))
        if findings:
            res.update(blocked=True, reasons=["Firmas críticas detectadas en snapshot/PKGBUILD."], findings=findings)
            if args.json:
                print(json.dumps(res, indent=2, ensure_ascii=False))
            else:
                print("❌ BLOQUEADO: firmas críticas detectadas.")
                for f in findings: print(f"- {f['signature']} | {f['file']} | {f['pattern']}")
            return 30
        res.update(passed=True, reasons=["No figura reportado y no se detectaron firmas críticas."])
        print(json.dumps(res, indent=2, ensure_ascii=False) if args.json else "✅ APROBADO: sin reportes ni firmas críticas conocidas.")
        return 0
    except Exception as e:
        res.update(blocked=True, reasons=[f"Error durante revisión previa: {e}"])
        print(json.dumps(res, indent=2, ensure_ascii=False) if args.json else f"❌ BLOQUEADO por seguridad: {e}")
        return 40
if __name__=="__main__":
    raise SystemExit(main())
