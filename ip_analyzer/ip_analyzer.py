
archivo = open("sample.log", "r")
lineas = archivo.readlines()
archivo.close()

conteo = {}
LIMITE_CONTEO = 3  

for linea in lineas:
    ip = linea.strip()
    if ip in conteo:
        conteo[ip] += 1
    else:
        conteo[ip] = 1

print("=== REPORTE DE IPs ===")
for ip, cantidad in conteo.items():
    if cantidad > LIMITE_CONTEO:
        print(f"SOSPECHOSA - {ip} apareció {cantidad} veces")
    else:
        print(f"Normal     - {ip} apareció {cantidad} veces")
