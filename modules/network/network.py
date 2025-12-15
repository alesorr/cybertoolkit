"""
Network discovery & validation
MITRE: T1046, T1016, T1021, T1570, T1071, T1041
"""
import subprocess

def discovery(context):
   """
   network.discovery
   Host discovery sulla rete interna
   """
   network_range = context.assets.get("network_range")
   cmd = f"nmap -sn {network_range}"
   result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
   return {
       "status": "success" if result.returncode == 0 else "error",
       "raw": result.stdout,
       "summary": f"Host discovery eseguita su {network_range}"
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