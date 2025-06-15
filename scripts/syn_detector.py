#!/usr/bin/env python3
import sys
import json
import argparse
import warnings
from scapy.all import rdpcap, TCP, IP
import ipaddress
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# Подавляем предупреждения sklearn о несовпадении feature names
warnings.filterwarnings('ignore', category=UserWarning)

def classify_features(features, model_path='rf_model.pkl', true_labels=None):

    clf = joblib.load(model_path)
    preds = clf.predict(features).tolist()
    confidences = []
    if hasattr(clf, 'predict_proba'):
        probs = clf.predict_proba(features)
        confidences = [max(p) for p in probs.tolist()]
    else:
        confidences = [None] * len(preds)

    total = len(preds)
    malicious = sum(preds)
    benign = total - malicious

    accuracy = None
    if true_labels is not None:
        matches = sum(1 for p, t in zip(preds, true_labels) if p == t)
        accuracy = matches / total if total > 0 else None

    return {
        'predictions': preds,
        'confidence': confidences,
        'summary': {
            'total': total,
            'malicious': malicious,
            'benign': benign,
            'accuracy': accuracy
        }
    }

# Вспомогательные функции для CLI-режима

def ip_i(x):
    return int(ipaddress.ip_address(x))


def df_from_pcap(path, label=True):
    rows = []
    pkts = rdpcap(path)
    for p in pkts:
        if p.haslayer(IP):
            proto = 6 if p.haslayer(TCP) else 17
            src   = ip_i(p[IP].src)
            dst   = ip_i(p[IP].dst)
            sport = p[TCP].sport if p.haslayer(TCP) else 0
            dport = p[TCP].dport if p.haslayer(TCP) else 0
            length= len(p)
            syn   = 1 if p.haslayer(TCP) and (p[TCP].flags & 0x02) else 0
            if label:
                rows.append([src, dst, sport, dport, proto, length, syn])
            else:
                rows.append([src, dst, sport, dport, proto, length])
    cols = ['src','dst','sport','dport','proto','length']
    if label:
        cols.append('danger')
    return pd.DataFrame(rows, columns=cols)


def train(pcap, model_out, csv_out):
    df = df_from_pcap(pcap, label=True)
    df.to_csv(csv_out, index=False)
    X, y = df.drop('danger', axis=1), df['danger']
    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    clf = RandomForestClassifier(
        n_estimators=200, n_jobs=-1, random_state=42, class_weight='balanced'
    )
    clf.fit(Xtr, ytr)
    print(classification_report(yte, clf.predict(Xte)))
    joblib.dump(clf, model_out)


def detect(pcap, model_in, min_run=10):
    clf  = joblib.load(model_in)
    pkts = rdpcap(pcap)
    rows = []
    for p in pkts:
        if p.haslayer(IP):
            proto = 6 if p.haslayer(TCP) else 17
            rows.append([
                ip_i(p[IP].src), ip_i(p[IP].dst),
                p[TCP].sport if p.haslayer(TCP) else 0,
                p[TCP].dport if p.haslayer(TCP) else 0,
                proto, len(p)
            ])
    df    = pd.DataFrame(rows, columns=['src','dst','sport','dport','proto','length'])
    preds = clf.predict(df.values.tolist())
    runs  = []
    start = None
    for i, lab in enumerate(preds):
        if lab == 1 and start is None:
            start = i
        if lab == 0 and start is not None:
            if i - start >= min_run:
                runs.append((start, i))
            start = None
    if start is not None and len(preds) - start >= min_run:
        runs.append((start, len(preds)))
    for s, e in runs:
        for pkt in pkts[s:e]:
            print(pkt.summary())


if __name__ == '__main__':
    if len(sys.argv) == 1:
        raw = sys.stdin.read()
        try:
            payload = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            payload = {}

        if 'features' in payload:
            features    = payload.get('features', [])
            true_labels = payload.get('true_labels')
            model_path  = payload.get('model', 'rf_model.pkl')
            result = classify_features(features, model_path, true_labels)
            print(json.dumps(result))
            sys.exit(0)
        else:
            print('No features provided', file=sys.stderr)
            sys.exit(1)

    parser = argparse.ArgumentParser(
        description='train or detect SYN packet attacks'
    )
    parser.add_argument('mode', choices=['train', 'detect'], help='режим работы')
    parser.add_argument('pcap', help='путь к pcap-файлу')
    parser.add_argument('--model', default='rf_model.pkl', help='путь к модели')
    parser.add_argument('--csv',   default='dataset.csv', help='CSV для train')
    parser.add_argument(
        '--minrun', type=int, default=10,
        help='длина последовательности для пометки как опасной'
    )
    args = parser.parse_args()
    if args.mode == 'train':
        train(args.pcap, args.model, args.csv)
    else:
        detect(args.pcap, args.model, args.minrun)
