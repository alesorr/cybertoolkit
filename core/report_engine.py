def generate_report(client, results, mitre_techniques, risk_score):
   report = f"Cybersecurity Assessment Report - {client.name}\n"
   report += f"Category: {client.category}\n\n"
   report += "Findings:\n"
   for step, output in results.items():
       report += f"{step}:\n{output}\n\n"
   report += "MITRE Techniques Observed:\n"
   report += ", ".join(mitre_techniques) + "\n\n"
   report += f"Risk Score: {risk_score['score']}\n"
   report += f"Risk Level: {risk_score['level']}\n"
   return report