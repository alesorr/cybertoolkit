"""
Verifica sistemi obsoleti o endpoint critici.
"""
import platform

def os_check(context):
   """
   Esegue una scansione OS info sugli endpoint
   """
   raw = f"""
    OS: {platform.system()}
    Version: {platform.version()}
    Arch: {platform.machine()}
    """
   return {
       "status": "success",
       "raw": raw,
       "summary": "Identificazione sistema operativo endpoint"
   }