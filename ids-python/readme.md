# Sistema de Detección de Intrusos en Red (IDS)

Un monitor de seguridad de red (NSM) y Sistema de Detección de Intrusos pasivo y ligero escrito en Python utilizando Scapy. Diseñado para entornos locales con el fin de auditar el tráfico de red, inspeccionar paquetes en tiempo real a través de múltiples protocolos (TCP/UDP/ARP/ICMP) y registrar alertas estructuradas cuando se superan los umbrales de actividad maliciosa.

## Características Principales

*   **Detección de Escaneo de Puertos Stateful**: Rastrea los puertos de destino únicos apuntados por un solo host dentro de una ventana de tiempo dinámica para minimizar eficazmente los falsos positivos.
*   **Monitoreo de Inundación UDP (UDP Flood)**: Mide la velocidad y el volumen de los paquetes para identificar posibles patrones de ataques de Denegación de Servicio (DoS).
*   **Inspección Multi-Protocolo**: Seguimiento nativo de protocolos para respuestas maliciosas de ARP Spoofing, cargas útiles de ICMP (Ping) de tamaño sospechoso e Indicadores de Compromiso (IOC) en puertos de malware conocidos.
*   **Registro Estructurado Listo para SIEM**: Canaliza todos los eventos de seguridad en un archivo de log JSON limpio y legible por máquinas para facilitar su posterior análisis o integración.

## Constantes del Motor Principal

El motor de evaluación de firmas utiliza variables calibradas para analizar amenazas de comportamiento:

*   `PORT_SCAN_THRESHOLD = 10` (Puertos de destino únicos atacados por un host origen)
*   `UDP_FLOOD_THRESHOLD = 50` (Máximo de paquetes UDP tolerados desde un solo origen)
*   `DETECTION_WINDOW_SECS = 5` (Intervalo de ventana dinámica para el rastreo de estados)
*   `SUSPICIOUS_PORTS_IOC = [4444, 5555, 6666, 31337, 12345]` (Puertos de comandos y control de malware monitoreados)

## Prerrequisitos y Configuración

1.  **Privilegios de Administrador**: Es obligatorio ejecutar la consola como Administrador para que Scapy pueda enlazarse a las interfaces de red locales.
2.  **Controlador de Captura de Paquetes**: Instalar [Npcap](https://npcap.com) en sistemas Windows (asegúrese de marcar la casilla *WinPcap API-compatible mode* durante la instalación).
3.  **Dependencias**:
    ```bash
    pip install scapy
    ```

## Ejecución del IDS

Ejecute el script principal desde una consola con permisos elevados:

```bash
python ids.py
```

## 📁 Ejemplo de Esquema de Alerta JSON (`ids_alerts.json`)

```json
{"timestamp": "2026-06-26 23:30:12", "event": "Port Scan", "source_ip": "192.168.1.105", "details": "Attempted connections to 11 unique ports."}
{"timestamp": "2026-06-26 23:31:45", "event": "UDP Flood", "source_ip": "10.0.0.42", "details": "Sent 56 UDP packets."}
```


## Próximas mejoras
- [ ] Reporte automático en HTML

