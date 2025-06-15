import argparse, ipaddress, pandas as pd, joblib
from scapy.all import rdpcap, TCP, IP
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

def ip_i(x):               # IPv4/6 ➜ int
    return int(ipaddress.ip_address(x))

def df_from_pcap(path, label=True):
    rows = []
    for p in rdpcap(path):
        if p.haslayer(IP):
            proto = 6 if p.haslayer(TCP) else 17
            src = ip_i(p[IP].src)
            dst = ip_i(p[IP].dst)
            ln  = len(p)
            sport = dport = syn = 0
            if p.haslayer(TCP):
                sport = p[TCP].sport
                dport = p[TCP].dport
                syn   = 1 if p[TCP].flags & 0x02 else 0
            rows.append([src, dst, sport, dport, proto, ln, syn if label else None])
    cols = ['src', 'dst', 'sport', 'dport', 'proto', 'length']
    if label:
        cols.append('danger')
    return pd.DataFrame(rows, columns=cols)

def train(pcap, model_out, csv_out):
    df = df_from_pcap(pcap)
    df.to_csv(csv_out, index=False)
    X, y = df.drop('danger', axis=1), df['danger']
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2,
                                          random_state=42, stratify=y)
    clf = RandomForestClassifier(n_estimators=200, n_jobs=-1,
                                 random_state=42, class_weight='balanced')
    clf.fit(Xtr, ytr)
    print(classification_report(yte, clf.predict(Xte)))
    joblib.dump(clf, model_out)

def detect(pcap, model_in, min_run=10):
    clf   = joblib.load(model_in)
    pkts  = rdpcap(pcap)
    rows  = []
    for p in pkts:
        if p.haslayer(IP):
            proto = 6 if p.haslayer(TCP) else 17
            rows.append([
                ip_i(p[IP].src),
                ip_i(p[IP].dst),
                p[TCP].sport if p.haslayer(TCP) else 0,
                p[TCP].dport if p.haslayer(TCP) else 0,
                proto,
                len(p)
            ])
    df    = pd.DataFrame(rows, columns=['src', 'dst', 'sport', 'dport',
                                        'proto', 'length'])
    preds = clf.predict(df)

    # определить последовательности подряд идущих «1»
    runs = []
    start = None
    for i, lab in enumerate(preds):
        if lab == 1:
            if start is None:
                start = i
        else:
            if start is not None and i - start >= min_run:
                runs.append((start, i))      # конец не включён
            start = None
    if start is not None and len(preds) - start >= min_run:
        runs.append((start, len(preds)))

    # выводим пакеты, входящие только в длинные последовательности
    for s, e in runs:
        for pkt in pkts[s:e]:
            print(pkt.summary())

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('mode',  choices=['train', 'detect'])
    ap.add_argument('pcap')
    ap.add_argument('--model', default='rf_model.pkl')
    ap.add_argument('--csv',   default='dataset.csv')
    ap.add_argument('--minrun', type=int, default=10,
                    help='длина последовательности для отметки как опасной')
    args = ap.parse_args()
    if args.mode == 'train':
        train(args.pcap, args.model, args.csv)
    else:
        detect(args.pcap, args.model, args.minrun)

