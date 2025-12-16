import sys
import yaml
#print("YAML version:", yaml.__version__)
import argparse
from core.context import Context
from core.orchestrator import Orchestrator
import os
from datetime import datetime

def load_yaml(path):
   with open(path, "r") as f:
       return yaml.safe_load(f)

def write_log(filename, results, mitre_hits, risk):
    with open(filename, "w", encoding="utf-8") as f:
        f.write("[+] Assessment completato\n\n")

        for step, data in results.items():
            f.write(f"[STEP] {step}\n")
            f.write(f"Status : {data.get('status')}\n")
            f.write(f"Summary: {data.get('summary')}\n")
            raw = data.get("raw", "").strip()
            if raw:
                f.write("Raw output:\n")
                f.write(raw + "\n")
            f.write("-" * 50 + "\n")

        f.write("\n=== MITRE TECHNIQUES ===\n")
        for t in mitre_hits:
            f.write(f"- {t}\n")

        f.write("\n=== RISK SUMMARY ===\n")
        f.write(f"Score: {risk['score']}\n")
        f.write(f"Level: {risk['level']}\n")

def print_client_assets(data: dict) -> None:
    client = data.get("client", {})
    assets = data.get("assets", {})

    network = assets.get("network", {})
    web = assets.get("web", {})
    endpoints = assets.get("endpoints", {})
    pos = assets.get("pos_systems", {})

    print("=" * 60)
    print("CLIENT ASSET OVERVIEW")
    print("=" * 60)

    print("\n[ Client Information ]")
    print(f"Name     : {client.get('name', 'N/A')}")
    print(f"Category : {client.get('category', 'N/A')}")

    print("\n[ Network ]")
    for r in network.get("ranges", []):
        print(f" - Range: {r}")

    print("\n[ Web Domains ]")
    for d in web.get("domains", []):
        print(f" - {d}")

    print("\n[ Endpoints ]")
    for ws in endpoints.get("workstations", []):
        print(f" - {ws.get('ip')}")

    print("\n[ POS Systems ]")
    for p in pos.get("list", []):
        print(f" - {p.get('ip')}")

    print("\n" + "=" * 60)

    
def build_context(args):
    """
    Costruisce il contesto cliente combinando:
    - file input YAML (master template)
    - parametri CLI (che hanno precedenza)
    """

    raw = {}
    if args.input_file:
        raw = load_yaml(args.input_file)

    # Sezioni principali (sicure anche se mancanti)
    assessment = raw.get("assessment", {})
    client = raw.get("client", {})
    assets = raw.get("assets", {})
    #print(f"ASSET {assets}")
    constraints = raw.get("security_constraints", {})
    metadata = raw.get("notes", {})

    # === Override CLI ===
    if args.client:
        client["name"] = args.client

    if args.category:
        client["category"] = args.category

    if args.network_range:
        assets.setdefault("network", {})
        assets["network"]["ranges"] = [args.network_range]

    if args.web_domain:
        assets.setdefault("web", {})
        assets["web"]["domains"] = [args.web_domain]

    if args.endpoints:
        assets.setdefault("endpoints", {})
        assets["endpoints"]["workstations"] = [
            {"ip": ip.strip()} for ip in args.endpoints.split(",")
        ]

    if args.pos:
        assets.setdefault("pos_systems", {})
        assets["pos_systems"]["list"] = [
            {"ip": ip.strip()} for ip in args.pos.split(",")
        ]

    # Stampa riepilogo (opzionale ma utile)
    print_client_assets({
        "client": client,
        "assets": assets
    })

    return Context(
        name=client.get("name", "UNKNOWN"),
        category=client.get("category", "generic"),
        assets=assets,
        extra={
            "assessment": assessment,
            "constraints": constraints,
            "notes": metadata
        }
    )


def main():
    parser = argparse.ArgumentParser(
        description="CyberToolkit - MITRE-based Security Assessment"
    )
    parser.add_argument("--workflow", required=True, help="Path del workflow YAML")
    parser.add_argument("--input-file", help="File YAML con parametri cliente")
    parser.add_argument("--client", help="Nome cliente")
    parser.add_argument(
        "--category",
        choices=["pmi", "negozio", "hotel", "ristorante"],
        help="Categoria cliente"
    )
    parser.add_argument("--network_range", help="Network target (CIDR)")
    parser.add_argument("--web_domain", help="Sito web target")
    parser.add_argument("--endpoints", help="IP endpoint separati da virgola")
    parser.add_argument("--pos", help="IP POS separati da virgola")
    args = parser.parse_args()

    # Carica workflow e contesto
    workflow = load_yaml(args.workflow)
    context = build_context(args)

    print(f"\n[*] Avvio assessment per {context}")
    print(f"[*] Workflow: {workflow.get('name')}\n")

    # Passa direttamente l'oggetto Context
    orchestrator = Orchestrator(context)
    output = orchestrator.run(workflow)

    results = output["results"]
    mitre_hits = output["mitre_observed"]
    risk = output["risk_score"]
    report = output["report"]
    
    # Output CLI
    print("[+] Assessment completato\n")
    print("=== RISULTATI ===")
    for step_name, step_result in results.items():
        print(f"- {step_name}: {step_result.get('status', 'unknown')}")

    print("\n=== MITRE TECHNIQUES ===")
    for t in mitre_hits:
        print(f"- {t}")

    print("\n=== RISK SUMMARY ===")
    print(f"Score: {risk['score']}")
    print(f"Level: {risk['level']}")

if __name__ == "__main__":
   main()