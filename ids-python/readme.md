# IDS - Intrusion Detection System 

Sistema de detección de intrusos casero construido en Python usando Scapy.
Captura y analiza tráfico de red en tiempo real, detectando comportamiento sospechoso.

## ¿Qué detecta?

- **ARP Spoofing** — suplantación de identidad en la red local
- **ICMP sospechoso** — paquetes de ping con payload inusualmente grande (posible túnel)
- **Escaneos de puertos** — conexiones SYN hacia múltiples puertos
- **Puertos asociados a malware** — conexiones a puertos conocidos como 4444, 31337, etc.

## Requisitos

- Python 3.x
- Npcap (Windows) — descargar en [npcap.com](https://npcap.com)
- Scapy

## Instalación

```bash
pip install -r requirements.txt
```

## Uso

Ejecutar como administrador (requerido para capturar tráfico):

**Windows — PowerShell como administrador:**
```powershell
py ids.py
```

**Linux:**
```bash
sudo python3 ids.py
```
## Tecnologías

- Python 3
- Scapy 2.x

## Contexto

Proyecto desarrollado como parte de mi aprendizaje en ciberseguridad con orientación en ciberdefensa.
Forma parte de mi portafolio en [cybersecurity-journey](../README.md).

## Próximas mejoras

- [ ] Logging de alertas en archivo JSON
- [ ] Reporte automático en HTML
- [ ] Contador de SYN para detección más precisa de escaneos
- [ ] Soporte para especificar interfaz de red por argumento
