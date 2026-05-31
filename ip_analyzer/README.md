# IP Analyzer

Herramienta simple para detectar IPs sospechosas en archivos de log.

## ¿Qué hace?
Lee un archivo de log línea por línea y cuenta cuántas veces
aparece cada IP. Si supera el límite configurado, la marca como sospechosa.

## Uso
```bash
py analyzer.py
```

## Configuración
Cambiá `LIMITE_CONTEO` en el código para ajustar el umbral de detección.

## Tecnologías
- Python 3
