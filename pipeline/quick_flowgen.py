#!/usr/bin/env python3
# quick_flowgen.py
# Usage: python quick_flowgen.py /app/pcaps/seg_0_...pcap /app/flow_csvs/quick_fallback.csv

import sys, csv, os
from collections import defaultdict

try:
    from scapy.all import rdpcap, IP
except Exception as e:
    print("scapy missing:", e)
    sys.exit(2)

if len(sys.argv) < 3:
    print("usage: quick_flowgen.py <pcap> <out_csv>")
    sys.exit(1)

pcap_path = sys.argv[1]
out_csv = sys.argv[2]

print(f"[quick_flowgen] reading {pcap_path}")
pkts = rdpcap(pcap_path)
flows = defaultdict(lambda: {'pkts':0,'bytes':0,'start':None,'end':None})
for p in pkts:
    if not p.haslayer(IP):
        continue
    ip = p[IP]
    sport = getattr(p.payload, 'sport', 0)
    dport = getattr(p.payload, 'dport', 0)
    proto = ip.proto
    key = (ip.src, ip.dst, sport, dport, proto)
    ent = flows[key]
    ent['pkts'] += 1
    ent['bytes'] += len(p)
    ts = float(getattr(p, 'time', 0))
    ent['start'] = ts if (ent['start'] is None or ts < ent['start']) else ent['start']
    ent['end'] = ts if (ent['end'] is None or ts > ent['end']) else ent['end']

os.makedirs(os.path.dirname(out_csv) or '.', exist_ok=True)
with open(out_csv, 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['src','dst','sport','dport','proto','pkts','bytes','start','end'])
    for k,v in flows.items():
        w.writerow(list(k) + [v['pkts'], v['bytes'], v['start'], v['end']])

print("[quick_flowgen] WROTE", out_csv)
# End of quick_flowgen.py