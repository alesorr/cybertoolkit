"""
Network discovery & validation
MITRE: T1046, T1016, T1021, T1570, T1071, T1041
"""
import subprocess
from datetime import datetime
from tqdm import tqdm
import time

def extract_live_hosts(nmap_output: str) -> list:
    hosts = []
    for line in nmap_output.splitlines():
        if line.startswith("Nmap scan report for"):
            hosts.append(line.split()[-1])
    return hosts

def run_with_progress(command: str, description: str):
    """
    Esegue un comando mostrando una barra di progresso simulata.
    """
    with tqdm(
        total=100,
        desc=description,
        bar_format="{l_bar}{bar}| {elapsed}"
    ) as pbar:

        proc = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Simulazione avanzamento (realistica)
        while proc.poll() is None:
            time.sleep(0.3)
            if pbar.n < 95:
                pbar.update(5)

        stdout, stderr = proc.communicate()
        pbar.update(100 - pbar.n)

    return proc.returncode, stdout, stderr

def discovery(context):
    """
    network.discovery
    Iterative network discovery with progress visualization
    """
    from datetime import datetime

    network_ranges = context.network_ranges()
    if not network_ranges:
        return {
            "status": "error",
            "raw": "",
            "summary": "Nessun network range configurato"
        }

    target = network_ranges[0]
    results = {}
    overall_status = "success"

    # =========================
    # PHASE 1 – HOST DISCOVERY
    # =========================
    cmd = f"nmap -sn {target}"
    rc, out, err = run_with_progress(
        cmd, "🔍 Host discovery"
    )

    live_hosts = extract_live_hosts(out)

    results["host_discovery"] = {
        "command": cmd,
        "live_hosts": live_hosts,
        "count": len(live_hosts),
        "output": out
    }

    if not live_hosts:
        return {
            "status": "success",
            "raw": results,
            "summary": f"Nessun host attivo su {target}"
        }

    # Limite professionale
    live_hosts = live_hosts[:20]
    targets = " ".join(live_hosts)

    # =========================
    # PHASE 2 – KEY PORTS
    # =========================
    cmd = (
        f"nmap -Pn -p 21,22,23,80,443,445,3389,3306,5432,8080 "
        f"--open {targets}"
    )
    rc, out, err = run_with_progress(
        cmd, "🚪 Scansione porte chiave"
    )

    results["key_ports"] = {
        "command": cmd,
        "output": out
    }

    # =========================
    # PHASE 3 – ADVANCED SCANS
    # =========================
    advanced_scans = {
        "service_detection": (
            "🧬 Service detection",
            f"nmap -Pn -sV --version-light {targets}"
        ),
        "os_fingerprint": (
            "🖥 OS fingerprinting",
            f"nmap -Pn -O --osscan-guess {targets}"
        )
    }

    if context.is_dos_testing_allowed():
        advanced_scans["safe_scripts"] = (
            "📜 NSE safe scripts",
            f"nmap -Pn -sC --script safe {targets}"
        )

    for key, (desc, cmd) in advanced_scans.items():
        rc, out, err = run_with_progress(cmd, desc)
        results[key] = {
            "command": cmd,
            "output": out
        }

    # =========================
    # FINAL RESPONSE
    # =========================
    return {
        "status": overall_status,
        "raw": results,
        "summary": (
            f"Discovery iterativa completata: "
            f"{len(live_hosts)} host analizzati su {target}"
        ),
        "metadata": {
            "target": target,
            "hosts_analyzed": live_hosts,
            "timestamp": datetime.utcnow().isoformat(),
            "strategy": "iterative_with_progress"
        }
    }

def _discovery(context):
    """
    network.discovery
    Iterative network discovery (senior pentester approach)
    """
    import subprocess
    from datetime import datetime

    network_ranges = context.network_ranges()
    if not network_ranges:
        return {
            "status": "error",
            "raw": "",
            "summary": "Nessun network range configurato"
        }

    target = network_ranges[0]
    results = {}
    overall_status = "success"

    # =========================
    # PHASE 1 – HOST DISCOVERY
    # =========================
    host_cmd = f"nmap -sn {target}"
    host_proc = subprocess.run(
        host_cmd, shell=True, capture_output=True, text=True
    )

    live_hosts = extract_live_hosts(host_proc.stdout)
    results["host_discovery"] = {
        "command": host_cmd,
        "live_hosts": live_hosts,
        "count": len(live_hosts),
        "output": host_proc.stdout
    }

    if not live_hosts:
        return {
            "status": "success",
            "raw": results,
            "summary": f"Nessun host attivo trovato su {target}"
        }

    # Limite professionale
    live_hosts = live_hosts[:20]
    targets = " ".join(live_hosts)

    # =========================
    # PHASE 2 – KEY PORTS
    # =========================
    key_ports_cmd = (
        f"nmap -Pn -p 21,22,23,80,443,445,3389,3306,5432,8080 "
        f"--open {targets}"
    )

    key_ports_proc = subprocess.run(
        key_ports_cmd, shell=True, capture_output=True, text=True
    )

    results["key_ports_scan"] = {
        "command": key_ports_cmd,
        "output": key_ports_proc.stdout
    }

    # =========================
    # PHASE 3 – ADVANCED SCANS (CONDITIONAL)
    # =========================
    advanced_profiles = {
        "service_detection": f"nmap -Pn -sV --version-light {targets}",
        "os_fingerprint": f"nmap -Pn -O --osscan-guess {targets}"
    }

    if context.is_dos_testing_allowed():
        advanced_profiles["safe_scripts"] = (
            f"nmap -Pn -sC --script safe {targets}"
        )

    for name, cmd in advanced_profiles.items():
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True
        )
        results[name] = {
            "command": cmd,
            "output": proc.stdout
        }

    # =========================
    # FINAL RESPONSE
    # =========================
    return {
        "status": overall_status,
        "raw": results,
        "summary": (
            f"Discovery iterativa completata: "
            f"{len(live_hosts)} host analizzati su {target}"
        ),
        "metadata": {
            "target": target,
            "hosts_analyzed": live_hosts,
            "timestamp": datetime.utcnow().isoformat(),
            "strategy": "iterative_host_based_scan"
        }
    }



def portscan(context):
   """
   network.portscan
   Scansione porte TCP principali
   """
   target_ip = context.assets.get("endpoint", "192.168.1.1")
   cmd = f"nmap -sT -Pn --top-ports 1000 {target_ip}"
   result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
   return {
       "status": "success" if result.returncode == 0 else "error",
       "raw": result.stdout,
       "summary": f"Port scan TCP su {target_ip}"
   }

def segmentation(context):
   """
   network.segmentation
   Verifica segmentazione / percorsi di rete
   """
   target_ip = context.assets.get("gateway_ip", "192.168.1.1")
   cmd = f"tracert -d {target_ip}"
   result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
   return {
       "status": "success" if result.returncode == 0 else "error",
       "raw": result.stdout,
       "summary": "Verifica segmentazione e routing di rete"
   }

def egress(context):
   """
   network.egress
   Verifica comunicazioni in uscita (C2 / data exfiltration)
   """
   cmd = "powershell -Command \"Test-NetConnection 8.8.8.8 -Port 443\""
   result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
   return {
       "status": "success",
       "raw": result.stdout,
       "summary": "Test egress traffic verso Internet"
   }