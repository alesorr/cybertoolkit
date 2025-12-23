"""
MITRE Mapping centralizzato
Ogni step di workflow è mappato alle tattiche e tecniche MITRE ATT&CK
"""
MITRE_MAPPING = {
# NETWORK
   "network.network.discovery": {
       "tactics": ["Discovery"],
       "techniques": ["T1046", "T1016"]
   },
   "network.network.portscan": {
       "tactics": ["Discovery"],
       "techniques": ["T1046"]
   },
   "network.network.segmentation": {
       "tactics": ["Defense Evasion", "Lateral Movement"],
       "techniques": ["T1021", "T1570"]
   },
   "network.egress": {
       "tactics": ["Command and Control"],
       "techniques": ["T1071", "T1041"]
   },
# WEB
   "web.web.web_enum": {
       "tactics": ["Discovery"],
       "techniques": ["T1190"]
   },
   "web.web.tls_enum": {
       "tactics": ["Defense Evasion"],
       "techniques": ["T1557"]
   },
# POS
   "pos.pos.pos_enum": {
       "tactics": ["Discovery"],
       "techniques": ["T1082"]
   },
   "pos.pos.pos_validation": {
       "tactics": ["Execution", "Credential Access"],
       "techniques": ["T1021", "T1078"]
   },
# ENDPOINT
   "endpoint.endpoint.os_check": {
       "tactics": ["Discovery"],
       "techniques": ["T1082"]
   },
# EXPLOITS / VALIDATION
   "exploits.exploits.metasploit_check": {
       "tactics": ["Execution"],
       "techniques": ["T1203"]
   },
# COMPLIANCE
   "compliance.compliance.backup_check": {
       "tactics": ["Impact"],
       "techniques": ["T1490"]
   },
   "compliance.compliance.pci_dss_light": {
       "tactics": ["Credential Access"],
       "techniques": ["T1078"]
   },
   "compliance.compliance.gdpr_light": {
       "tactics": ["Impact"],
       "techniques": []
   }
}