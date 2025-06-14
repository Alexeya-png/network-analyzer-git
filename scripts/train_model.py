#!/usr/bin/env python3
import os
import glob
import struct
import socket
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from scapy.all import rdpcap, IP

def ip_to_int(ip: str) -> int:
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except Exception:
        return 0

def extract_features_from_pcap(path: str) -> pd.DataFrame:
    pkts = rdpcap(path)
    rows = []
    for pkt in pkts:
        if IP in pkt:
            ip = pkt[IP]
            rows.append({
                "src_ip": ip_to_int(ip.src),
                "dst_ip": ip_to_int(ip.dst),
                "proto":  ip.proto,
                "length": len(ip),
            })
    return pd.DataFrame(rows)

def load_dataset(normal_pcap: str, malicious_pcap: str) -> pd.DataFrame:
    """Читает два pcap-файла и возвращает DataFrame с метками."""
    dfs = []
    # normal traffic
    df_norm = extract_features_from_pcap(normal_pcap)
    df_norm["label"] = 0
    dfs.append(df_norm)
    # malicious traffic
    df_mal = extract_features_from_pcap(malicious_pcap)
    df_mal["label"] = 1
    dfs.append(df_mal)

    combined = pd.concat(dfs, ignore_index=True)
    if combined.empty:
        raise RuntimeError("Данные не загружены: убедитесь, что файлы существуют и не пусты")
    return combined

def main():
    # Определяем путь до папки scripts и до папки с pcap'ами
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pcaps_dir  = os.path.join(script_dir, "pcaps")

    normal_pcap    = os.path.join(pcaps_dir, "http-normal.pcap")
    malicious_pcap = os.path.join(pcaps_dir, "http-flood.pcap")

    print("Loading PCAPs:")
    print(" - normal   :", normal_pcap)
    print(" - malicious:", malicious_pcap)

    df = load_dataset(normal_pcap, malicious_pcap)
    print(f"Total packets: {len(df)} (normal={sum(df.label==0)}, malicious={sum(df.label==1)})")

    df.fillna(0, inplace=True)
    X = df[["src_ip", "dst_ip", "proto", "length"]]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.3,
        random_state=42,
        stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        random_state=42
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\n=== Classification Report ===")
    print(classification_report(y_test, y_pred, digits=4))

    out_path = os.path.join(script_dir, "random_forest_model.joblib")
    joblib.dump(model, out_path, compress=3)
    print(f"\nModel saved to {out_path}")

if __name__ == "__main__":
    main()
