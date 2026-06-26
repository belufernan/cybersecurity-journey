from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP, Raw

known_malware_ports = [4444, 5555, 6666, 31337, 12345]

def procesar_packet(pkt):
    # 1. Detección de ARP Spoofing
    if ARP in pkt and pkt[ARP].op == 2:
        print(f"ARP SPOOFING: {pkt[ARP].hwsrc} dice ser {pkt[ARP].psrc}")

    if IP not in pkt:
        return

    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst
    
    # 2. Detección de ICMP Sospechoso
    if ICMP in pkt and Raw in pkt:
        if len(pkt[Raw].load) > 100:
            print(f"ICMP SOSPECHOSO: Paquete grande ({len(pkt[Raw].load)} bytes) de {ip_src}")

    # Lógica para TCP/UDP
    if TCP in pkt:
        port_dst = pkt[TCP].dport
        flags = pkt[TCP].flags
        
        # 3. Detección de Escaneo de Puertos
        if flags == "S":
            print(f"ESCANEO POSIBLE: SYN de {ip_src} al puerto {port_dst}")
        
        if port_dst in known_malware_ports:
            print(f"ALERTA CRÍTICA: Conexión a puerto malicioso ({port_dst}) desde {ip_src}")
            
        print(f"[TCP] {ip_src}:{pkt[TCP].sport} -> {ip_dst}:{port_dst}")

    elif UDP in pkt:
        port_dst = pkt[UDP].dport
        # Ejemplo: Alertar si hay DNS (puerto 53) hacia una IP que no es tu router
        
        print(f"[UDP] {ip_src} -> {ip_dst}:{port_dst}")   

def main():
    print("Iniciando sniffing (Ctrl+C para detener)...")
    try:
        sniff(prn=procesar_packet, store=False)
    except KeyboardInterrupt:
        print("\nSniffing detenido por el usuario.")

if __name__ == "__main__":
    main()
