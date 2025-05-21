# imunify360-webshield-1.21
Desarrollado por m10sec - m10sec@proton.me
CVE: Path Traversal Custom Bypass Vulnerability

# PoC para Bypass en Imunify360 Webshield 1.21 - Imunify360 WebShield 1.21 Bypass Tester

Este repositorio contiene un **Proof of Concept (PoC)** para un bypass de reglas de filtrado en **Imunify360 Webshield** versión **1.21**. El PoC explora una vulnerabilidad que permite evadir el filtrado de URL mediante el uso de caracteres codificados.

> **Nota**: Este código es únicamente para fines educativos y de investigación en ciberseguridad. Solo debe ejecutarse en entornos de prueba controlados y con el debido permiso.

## Descripción

El PoC explota una vulnerabilidad en Imunify360 Webshield 1.21 que permite el acceso a archivos restringidos del sistema, como `/etc/passwd`, mediante el uso de caracteres codificados en la URL. Este tipo de vulnerabilidad podría ser utilizada por un atacante para evadir los controles de seguridad y acceder a información confidencial.

## Requisitos

- **Python 3**.
- Librería `requests` (puedes instalarla usando `pip install requests`).
- Acceso a un servidor web con Imunify360 Webshield versión 1.21.

## Instalación

Clona este repositorio y navega al directorio del proyecto:

```bash[
git clone https://github.com/moften/imunify360-webshield-1.21.git
cd imunify360-bypass-poc
