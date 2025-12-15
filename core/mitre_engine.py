from core.mitre_mapping import MITRE_MAPPING
def get_mitre_for_step(step_id):
   """
   Restituisce tecniche MITRE associate a uno step
   """
   entry = MITRE_MAPPING.get(step_id, {})
   return entry.get("techniques", [])
def get_tactics_for_step(step_id):
   """
   Restituisce tattiche MITRE associate a uno step
   """
   entry = MITRE_MAPPING.get(step_id, {})
   return entry.get("tactics", [])