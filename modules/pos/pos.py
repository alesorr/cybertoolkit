import subprocess
"""
Verifica POS (rete / configurazioni) senza exploit distruttivi.
"""

def pos_enum(context):
    """
    Enumerazione POS sulla rete:
    - Effettua ping dei terminali POS
    - Raccoglie stato reachability + metadata
    """
    pos_list = context.pos_list()

    if not pos_list:
        return {
            "status": "success",
            "raw": [],
            "summary": "Nessun POS configurato"
        }

    findings = []

    for pos in pos_list:
        ip = pos.get("ip")
        if not ip:
            continue

        cmd = f"ping -c 1 {ip}"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        findings.append({
            "ip": ip,
            "reachable": res.returncode == 0,
            "vendor": pos.get("vendor", "unknown"),
            "model": pos.get("model", "unknown"),
            "pci_scope": pos.get("pci_scope", False),
            "stdout": res.stdout.strip()
        })

    return {
        "status": "success",
        "raw": findings,
        "summary": f"Enumerati {len(findings)} POS"
    }

def pos_validation(context):
    """
    Validazione sicurezza POS.
    
    Cosa fa:
    - Controlla servizi sensibili sui POS (es: SMB su 445)
    - Raccoglie output Nmap
    - Indica host sicuro / potenzialmente rischioso
    
    Output strutturato per report engine.
    """
    
    pos_list = context.pos_list()

    if not pos_list:
        return {
            "status": "success",
            "raw": [],
            "summary": "Nessun POS configurato"
        }

    report = []

    for pos in pos_list:
        ip = pos.get("ip")
        if not ip:
            continue

        cmd = f"nmap -Pn -p 445 {ip}"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        smb_open = "open" in res.stdout.lower()

        report.append({
            "ip": ip,
            "vendor": pos.get("vendor", "unknown"),
            "model": pos.get("model", "unknown"),
            "pci_scope": pos.get("pci_scope", False),
            "command": cmd,
            "returncode": res.returncode,
            "smb_port_open": smb_open,
            "stdout": res.stdout.strip(),
            "stderr": res.stderr.strip()
        })

    return {
        "status": "success",
        "raw": report,
        "summary": f"Validazione sicurezza POS completata. Analizzati {len(report)} host."
    }