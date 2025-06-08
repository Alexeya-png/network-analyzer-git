from scapy.all import IP, TCP, send
import random
import time

target_ip = "192.168.1.1"
target_port = 80
iface = "wlan0"

while True:
    src_port = random.randint(1024, 65535)
    src_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))

    ip = IP(src=src_ip, dst=target_ip)
    tcp = TCP(sport=src_port, dport=target_port, flags="S", seq=random.randint(0, 4294967295))
    pkt = ip / tcp

    send(pkt, iface=iface, verbose=False)
    print(f"Sent SYN from {src_ip}:{src_port} -> {target_ip}:{target_port}")

    time.sleep(5)
