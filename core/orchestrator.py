import importlib
from core.mitre_engine import get_mitre_for_step
from core.risk_engine import calculate_risk
from core.report_engine import generate_report
from core.context import Context
import os
import yaml
import json
from datetime import datetime

class Orchestrator:
    """
    Orchestrator workflow MITRE-aligned.
    Esegue un workflow passo-passo usando il Context del cliente.
    """

    def __init__(self, context: Context, log_folder="logs"):
        """
        :param context: oggetto Context con assets, client, extra
        :param log_folder: cartella dove salvare i log passo-passo
        """
        self.context = context
        self.log_folder = log_folder
        os.makedirs(self.log_folder, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = os.path.join(self.log_folder, f"log_{timestamp}.txt")

    def _write_step_log(self, step_name, step_result):
        """Scrive il risultato di uno step direttamente a log file"""
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"[STEP] {step_name}\n")
            f.write(f"Status : {step_result.get('status', 'unknown')}\n")
            f.write(f"Summary: {step_result.get('summary', '')}\n")
            raw = step_result.get("raw", None)
            if raw:
                f.write("Raw output:\n")
                # ============================
                # 1️⃣ Caso: RAW = Dizionario
                # ============================
                if isinstance(raw, dict):
                    for key, value in raw.items():
                        f.write(f"\n- {key}:\n")
                        try:
                            f.write(yaml.dump(value, sort_keys=False, allow_unicode=True))
                        except:
                            f.write(str(value) + "\n")
                # ============================
                # 2️⃣ Caso: RAW = Lista
                # ============================
                elif isinstance(raw, list):
                    for i, item in enumerate(raw, 1):
                        f.write(f"\n[{i}] ")
                        if isinstance(item, dict):
                            f.write("\n")
                            f.write(yaml.dump(item, sort_keys=False, allow_unicode=True))
                        else:
                            f.write(str(item) + "\n")
                # ============================
                # 3️⃣ Qualsiasi altra cosa
                # ============================
                else:
                    f.write(str(raw) + "\n")
            f.write("-" * 50 + "\n")

    def run(self, workflow: dict) -> dict:
        """
        Esegue il workflow passo-passo e scrive i log live.

        :param workflow: dict YAML con chiave "steps"
        :return: dict con risultati, MITRE osservato, risk score e report
        """
        results = {}
        mitre_observed = []

        for step in workflow.get("steps", []):
            try:
                # Import dinamico del modulo e funzione
                module_name, func_name = step.rsplit(".", 1)
                module = importlib.import_module(f"modules.{module_name}")
                func = getattr(module, func_name)

                # Esecuzione step
                step_result = func(self.context)

                # Standardizza output
                if not isinstance(step_result, dict):
                    step_result = {
                        "status": "success",
                        "raw": str(step_result),
                        "summary": ""
                    }

                results[step] = step_result

                # Log immediato
                self._write_step_log(step, step_result)

                # MITRE mapping
                mitre = get_mitre_for_step(step)
                if mitre:
                    for t in mitre:
                        if t not in mitre_observed:
                            mitre_observed.append(t)

            except Exception as e:
                step_result = {
                    "status": "error",
                    "raw": "",
                    "summary": f"Step fallito: {str(e)}"
                }
                results[step] = step_result
                # Log errore subito
                self._write_step_log(step, step_result)

        # Calcolo rischio
        risk_score = calculate_risk(mitre_observed, results)

        # Generazione report
        report = generate_report(self.context, results, mitre_observed, risk_score)

        # Informazioni extra dai metodi helper del Context
        summary_info = {
            "network_ranges": self.context.network_ranges(),
            "workstations": self.context.workstations(),
            "servers": self.context.servers(),
            "web_domains": self.context.web_domains(),
            "pos_list": self.context.pos_list()
        }

        return {
            "results": results,
            "mitre_observed": mitre_observed,
            "risk_score": risk_score,
            "report": report,
            "summary_info": summary_info
        }
