import sys
import yaml
print("YAML version:", yaml.__version__)
import argparse
from core.context import Context
from core.orchestrator import Orchestrator
import os
from datetime import datetime

def ensure_logs_folder():
    os.makedirs("logs", exist_ok=True)

def get_log_filename():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"logs/log_{timestamp}.log"

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

def build_context(args):
   """
   Costruisce il contesto cliente combinando:
   - file input (se presente)
   - parametri CLI (che hanno precedenza)
   """
   data = {}
   if args.input_file:
       data = load_yaml(args.input_file)
   client_data = data.get("client", {})
   assets = data.get("assets", {})
   metadata = data.get("metadata", {})
# Override da CLI
   if args.client:
       client_data["name"] = args.client
   if args.category:
       client_data["category"] = args.category
   if args.network_range:
       assets["network_range"] = args.network_range
   if args.web_domain:
       assets["web_domain"] = args.web_domain
   if args.endpoints:
       assets["endpoints"] = args.endpoints.split(",")
   if args.pos:
       assets["pos_list"] = args.pos.split(",")
   print(client_data)
   return Context(
       name=client_data["name"],
       category=client_data["category"],
       assets=assets,
       extra=metadata
   )

def main():
   parser = argparse.ArgumentParser(
       description="CyberToolkit - MITRE-based Security Assessment"
   )
   parser.add_argument(
       "--workflow",
       required=True,
       help="Path del workflow YAML"
   )
   parser.add_argument(
       "--input-file",
       help="File YAML con parametri cliente"
   )
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
   workflow = load_yaml(args.workflow)
   context = build_context(args)
   category = "" if args.category is None else args.category
   orchestrator = Orchestrator(context, category)
   print(f"\n[*] Avvio assessment per {context}")
   print(f"[*] Workflow: {workflow.get('name')}\n")
   output = orchestrator.run(workflow)
   results = output["results"]
   print(results)
   mitre_hits = output["mitre_observed"]
   risk = output["risk_score"]
   report = output["report"]  # opzionale se ti serve
   
   ensure_logs_folder()
   log_file = get_log_filename()
   write_log(log_file, results, mitre_hits, risk)

   print("[+] Assessment completato\n")
   print("=== RISULTATI ===")
   for step_name, step_result in results.items():
    status = step_result.get("status", "unknown")
    print(f"- {step_name}: {status}")

   print("\n=== MITRE TECHNIQUES ===")
   for t in mitre_hits:
       print(f"- {t}")
   print("\n=== RISK SUMMARY ===")
   print(f"Score: {risk['score']}")
   print(f"Level: {risk['level']}")

if __name__ == "__main__":
   main()