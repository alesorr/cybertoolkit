import importlib
from core.context import Context
from core.mitre_engine import get_mitre_for_step
from core.risk_engine import calculate_risk
from core.report_engine import generate_report

class Orchestrator:
   """
   Orchestrator workflow MITRE-aligned.
   """
   def __init__(self, context_data, category):
       """
       :param context_data: dict con assets, client, metadata
       """
       self.context = Context(context_data,category)
       
   def run(self, workflow):
       """
       Esegue il workflow passo-passo
       :param workflow: dict caricato da YAML con key "steps"
       :return: dict con risultati, MITRE osservato, risk score e report
       """
       results = {}
       mitre_observed = []
       for step in workflow.get("steps", []):
           try:
               # import dinamico del modulo
               module_name, func_name = step.rsplit(".", 1)
               module = importlib.import_module(f"modules.{module_name}")
               func = getattr(module, func_name)
               func = getattr(module, func_name)
               # esecuzione step
               step_result = func(self.context)
               # standardizza output
               if not isinstance(step_result, dict):
                   step_result = {
                       "status": "success",
                       "raw": str(step_result),
                       "summary": ""
                   }
               results[step] = step_result
               # MITRE mapping
               mitre = get_mitre_for_step(step)
               if mitre:
                   for t in mitre:
                       if t not in mitre_observed:
                           mitre_observed.append(t)
           except Exception as e:
               results[step] = {
                   "status": "error",
                   "raw": "",
                   "summary": f"Step fallito: {str(e)}"
               }
       # calcolo rischio
       risk_score = calculate_risk(mitre_observed, results)
       # generazione report
       report = generate_report(self.context, results, mitre_observed, risk_score)
       return {
           "results": results,
           "mitre_observed": mitre_observed,
           "risk_score": risk_score,
           "report": report
       }