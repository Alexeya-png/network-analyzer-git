import scapy.all as scapy
import pandas as pd


def process_pcap(file_path):
    packets = scapy.rdpcap(file_path)
    data = []

    for packet in packets:
        is_malicious = 0
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == "S":
            is_malicious = 1
            print(f"Позначений пакет як шкідливий: {packet.summary()}")

        features = {
            'src_ip': packet[scapy.IP].src if packet.haslayer(scapy.IP) else None,
            'dst_ip': packet[scapy.IP].dst if packet.haslayer(scapy.IP) else None,
            'src_port': packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else None,
            'dst_port': packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else None,
            'protocol': packet[scapy.IP].proto if packet.haslayer(scapy.IP) else None,
            'packet_size': len(packet),
            'is_malicious': is_malicious
        }
        data.append(features)

    return pd.DataFrame(data)


df = process_pcap('capture.pcap')
df.to_csv('network_traffic_dataset.csv', index=False)

print("Конвертація в CSV завершена.")
