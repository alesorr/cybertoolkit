"""
Compliance checks
MITRE: T1490, T1078
"""
def backup_check(context):
   """
   compliance.backup_check
   """
   raw = f"""
Backup enabled: {context.assets.get('backup_enabled')}
Last backup: {context.assets.get('last_backup')}
"""
   return {
       "status": "success",
       "raw": raw,
       "summary": "Verifica backup e resilienza"
   }

def pci_dss_light(context):
   """
   compliance.pci_dss_light
   """
   issues = []
   if not context.assets.get("card_data_encrypted"):
       issues.append("Dati carta non cifrati")
   if context.assets.get("shared_accounts"):
       issues.append("Account POS condivisi")
   raw = "\n".join(issues) if issues else "Controlli PCI-DSS base OK"
   return {
       "status": "success",
       "raw": raw,
       "summary": "Valutazione PCI-DSS light"
   }

def gdpr_light(context):
   """
   compliance.gdpr_light
   """
   raw = f"""
Privacy policy: {context.assets.get('privacy_policy')}
Data retention: {context.assets.get('data_retention')}
"""
   return {
       "status": "success",
       "raw": raw,
       "summary": "Valutazione GDPR light"
   }