import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import socket
import struct
import joblib

def ip_to_int(ip):
    if isinstance(ip, str):
        try:
            return struct.unpack("!I", socket.inet_aton(ip))[0]
        except socket.error:
            return 0
    else:
        return 0

df = pd.read_csv('network_traffic_dataset.csv')

df['src_ip'] = df['src_ip'].apply(ip_to_int)
df['dst_ip'] = df['dst_ip'].apply(ip_to_int)

df.fillna(0, inplace=True)

X = df.drop(columns=['is_malicious'])
y = df['is_malicious']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

model = RandomForestClassifier()
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

joblib.dump(model, 'random_forest_model.joblib')
