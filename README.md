# OS-Fingerprinting
# Without touching HTTP, only by using TCP stack values, brand/model prediction.

    from scapy.all import *

    target = "<IP>"
    port ="ports ex. 80,443,22,23"

    ip = IP(dst=target)
    syn = TCP(dport=port, flags="S")
    pkt = ip/syn
    resp = sr1(pkt, timeout=2)

    if resp and resp.haslayer(TCP):
        ttl = resp[IP].ttl
        window = resp[TCP].window
        options = resp[TCP].options
         print(f"TTL: {ttl}")
         print(f"Window Size: {window}")
         print(f"TCP Options: {options}")

    # Simple brand prediction
    if ttl == 64 and window == 5840:
        print("Most likely a Linux (Zyxel / Huawei).")
    elif ttl == 128:
        print("Most likely a Windows-based device (very unlikely).")
    else:
        print("Add to knowledge base, manual analysis required.")
    else:
        print("No Answer.")
