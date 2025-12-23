"""
Web enumeration & TLS validation
MITRE: T1190, T1557
"""
import subprocess

def web_enum(context):
   """
   web.web_enum
   Enumerazione base servizi web
   """
   domain = context.web_domains()
   if not domain:
       return {
           "status": "error",
           "raw": "",
           "summary": "Nessun dominio web fornito"
       }
   cmd = f"nmap -p 80,443 --script=http-title,http-headers {domain}"
   result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
   return {
       "status": "success",
       "raw": result.stdout,
       "summary": f"Enumerazione web su {domain}"
   }

def tls_enum(context):
   """
   web.tls_enum
   Enumerazione TLS / SSL
   """
   domain = context.web_domains()
   if not domain:
       return {
           "status": "error",
           "raw": "",
           "summary": "Nessun dominio per TLS enum"
       }
   cmd = f"nmap --script ssl-enum-ciphers -p 443 {domain}"
   result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
   return {
       "status": "success",
       "raw": result.stdout,
       "summary": "Enumerazione TLS / cifrari"
   }