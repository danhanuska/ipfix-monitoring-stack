#!/usr/bin/env python3
"""
Synthetic IPFIX generator for the network-monitoring-stack demo.

Sends realistic-looking flow records (IPFIX over UDP) to the ipfixcol2 collector.
Uses only private and documentation address ranges (RFC 1918, RFC 4193, RFC 5737,
RFC 3849), so it contains no real addresses.

The exported fields match the columns in configs/ipfixcol2/startup.xml(.tpl):
vlanId, sourceMacAddress, src/dst IPv4|IPv6, src/dst port, tcpControlBits,
octetDeltaCount, packetDeltaCount, flowStart/EndMilliseconds,
ipClassOfService, protocolIdentifier.

Configuration via environment variables:
  TARGET_HOST          collector host (default: ipfixcol2)
  TARGET_PORT          collector port (default: 4739)
  SESSIONS_PER_SEC     average sessions per second at peak (default: 5)
                       each session = typically 2 flows (request + response)
  IPV6_RATIO           share of IPv6 for sessions that support it, 0..1 (default: 0.15)
  DIURNAL              1 = daily and weekly traffic pattern, 0 = constant (default: 1)
  PEAK_HOUR_UTC        peak hour in UTC (default: 13, i.e. 15:00 CEST)
  OBSERVATION_DOMAIN   ODID in the IPFIX message header (default: 1)
  INCIDENT_INTERVAL_MIN  average minutes between simulated security incidents
                       (SYN/ACK flood, SSH brute force, port scan, network sweep,
                       exfiltration, ARP spoofing) that trip the dashboard detections (default: 20,
                       0 = off)
  SEED                 random seed (optional, for reproducible output)
"""

import ipaddress
import math
import os
import random
import signal
import socket
import struct
import sys
import time

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TARGET_HOST = os.environ.get("TARGET_HOST", "ipfixcol2")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "4739"))
SESSIONS_PER_SEC = float(os.environ.get("SESSIONS_PER_SEC", "5"))
IPV6_RATIO = float(os.environ.get("IPV6_RATIO", "0.15"))
DIURNAL = os.environ.get("DIURNAL", "1") == "1"
PEAK_HOUR_UTC = float(os.environ.get("PEAK_HOUR_UTC", "13"))
ODID = int(os.environ.get("OBSERVATION_DOMAIN", "1"))
INCIDENT_INTERVAL_MIN = float(os.environ.get("INCIDENT_INTERVAL_MIN", "20"))

if os.environ.get("SEED"):
    random.seed(int(os.environ["SEED"]))

MAX_MSG_SIZE = 1400          # stay below MTU, no IP fragmentation
TEMPLATE_REFRESH_SECS = 10   # UDP is stateless - resend templates periodically
STATS_EVERY_SECS = 60

# ---------------------------------------------------------------------------
# IPFIX encoding
# ---------------------------------------------------------------------------

TID_V4, TID_V6 = 256, 257


def template_fields(v6):
    return [
        (58, 2),                     # vlanId
        (56, 6),                     # sourceMacAddress
        (27, 16) if v6 else (8, 4),  # sourceIPv6Address / sourceIPv4Address
        (28, 16) if v6 else (12, 4), # destinationIPv6Address / destinationIPv4Address
        (7, 2),                      # sourceTransportPort
        (11, 2),                     # destinationTransportPort
        (6, 2),                      # tcpControlBits
        (1, 8),                      # octetDeltaCount
        (2, 8),                      # packetDeltaCount
        (152, 8),                    # flowStartMilliseconds
        (153, 8),                    # flowEndMilliseconds
        (5, 1),                      # ipClassOfService
        (4, 1),                      # protocolIdentifier
    ]


def build_template_set():
    body = b""
    for tid, v6 in ((TID_V4, False), (TID_V6, True)):
        fields = template_fields(v6)
        body += struct.pack("!HH", tid, len(fields))
        body += b"".join(struct.pack("!HH", ie, ln) for ie, ln in fields)
    return struct.pack("!HH", 2, 4 + len(body)) + body


TEMPLATE_SET = build_template_set()
REC_V4 = struct.Struct("!H6s4s4sHHHQQQQBB")
REC_V6 = struct.Struct("!H6s16s16sHHHQQQQBB")
HEADER = struct.Struct("!HHIII")


class Exporter:
    def __init__(self, host, port, odid):
        self.host, self.port, self.odid = host, port, odid
        self.sock = None
        self.addr = None
        self.seq = 0
        self.last_template = 0.0
        self.sent_flows = 0
        self.sent_msgs = 0

    def _connect(self):
        if self.sock is not None:
            return True
        try:
            family, _, _, _, addr = socket.getaddrinfo(
                self.host, self.port, type=socket.SOCK_DGRAM)[0]
        except socket.gaierror as exc:
            print(f"[generator] cannot resolve {self.host}: {exc} - will retry",
                  file=sys.stderr, flush=True)
            return False
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.addr = addr
        self.last_template = 0.0  # new target -> send templates immediately
        print(f"[generator] sending IPFIX to {addr[0]}:{addr[1]} (ODID {self.odid})",
              flush=True)
        return True

    def send(self, flows):
        if not self._connect():
            return
        v4 = [f for f in flows if not f[0]]
        v6 = [f for f in flows if f[0]]
        for tid, rec, group in ((TID_V4, REC_V4, v4), (TID_V6, REC_V6, v6)):
            per_msg = (MAX_MSG_SIZE - HEADER.size - len(TEMPLATE_SET) - 4) // rec.size
            for i in range(0, len(group), per_msg):
                chunk = group[i:i + per_msg]
                data = b"".join(rec.pack(*f[1:]) for f in chunk)
                self._send_message(tid, data, len(chunk))
                if self.sock is None:
                    # send failed and the socket was dropped: skip the rest of
                    # this batch, the next send() reconnects
                    return

    def _send_message(self, tid, data, count):
        now = time.time()
        with_template = now - self.last_template >= TEMPLATE_REFRESH_SECS
        body = (TEMPLATE_SET if with_template else b"")
        body += struct.pack("!HH", tid, 4 + len(data)) + data
        msg = HEADER.pack(10, HEADER.size + len(body), int(now), self.seq, self.odid) + body
        try:
            self.sock.sendto(msg, self.addr)
        except OSError as exc:
            # collector restarting / container IP changed -> resolve again
            print(f"[generator] send error: {exc}", file=sys.stderr, flush=True)
            self.sock.close()
            self.sock = None
            return
        if with_template:
            self.last_template = now
        # sequence number = number of data records sent BEFORE this message
        self.seq = (self.seq + count) & 0xFFFFFFFF
        self.sent_flows += count
        self.sent_msgs += 1


# ---------------------------------------------------------------------------
# Model network
# ---------------------------------------------------------------------------

ip = ipaddress.ip_address
VLANS = [
    (ipaddress.ip_network("192.168.10.0/24"), 10),  # office / clients
    (ipaddress.ip_network("192.168.20.0/24"), 20),  # internal servers
    (ipaddress.ip_network("192.168.30.0/24"), 30),  # IoT
    (ipaddress.ip_network("192.168.50.0/24"), 50),  # DMZ
    (ipaddress.ip_network("fd00:10::/64"), 10),
    (ipaddress.ip_network("fd00:50::/64"), 50),
]
GATEWAY_MAC = bytes.fromhex("020000000001")

CLIENTS_V4 = [ip(f"192.168.10.{i}") for i in range(10, 90)]
CLIENTS_V6 = [ip(f"fd00:10::{i:x}") for i in range(10, 90)]   # dual-stack counterparts
IOT = [ip(f"192.168.30.{i}") for i in range(10, 30)]
ADMINS = CLIENTS_V4[:3]

DNS_SERVER = ip("192.168.20.2")
FILE_SERVER = ip("192.168.20.10")
MAIL_SERVER = ip("192.168.20.25")
INTERNAL_SERVERS = [DNS_SERVER, FILE_SERVER, MAIL_SERVER, ip("192.168.20.30")]
WEB_V4 = ip("192.168.50.10")
WEB_V6 = ip("fd00:50::10")
DMZ_HOSTS = [ip(f"192.168.50.{i}") for i in range(2, 30)]

UPSTREAM_DNS = [ip("192.0.2.53"), ip("198.51.100.53")]
NTP_SERVERS = [ip("203.0.113.123"), ip("192.0.2.123")]
SIP_PROVIDER = ip("198.51.100.60")
IOT_CLOUD = [ip("203.0.113.200"), ip("203.0.113.201")]
SCANNERS = [ip(f"203.0.113.{i}") for i in (66, 77, 99, 150)] + [ip("198.51.100.250")]


def _pool(nets, size):
    hosts = []
    for _ in range(size):
        net = ipaddress.ip_network(random.choice(nets))
        offset = random.randint(1, min(net.num_addresses - 2, 2 ** 32))
        hosts.append(net.network_address + offset)
    return hosts


EXT_V4 = _pool(["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"], 300)
EXT_V6 = _pool(["2001:db8:1::/48", "2001:db8:2::/48", "2001:db8:3::/48"], 150)
# Zipf distribution -> a few "popular" servers get most traffic (nice top-N charts)
EXT_V4_W = [1 / (i + 1) for i in range(len(EXT_V4))]
EXT_V6_W = [1 / (i + 1) for i in range(len(EXT_V6))]
CLIENT_W = [1 / (i + 1) ** 0.6 for i in range(len(CLIENTS_V4))]


def pick(pool, weights=None):
    return random.choices(pool, weights=weights)[0]


def client(v6=False):
    idx = random.choices(range(len(CLIENTS_V4)), weights=CLIENT_W)[0]
    return CLIENTS_V6[idx] if v6 else CLIENTS_V4[idx]


def external(v6=False):
    return pick(EXT_V6, EXT_V6_W) if v6 else pick(EXT_V4, EXT_V4_W)


def vlan_of(*addrs):
    for a in addrs:
        for net, vlan in VLANS:
            if a.version == net.version and a in net:
                return vlan
    return 0


def mac_of(addr):
    if addr.is_private and vlan_of(addr):
        h = (int(addr) * 2654435761) & 0xFFFFFFFFFF
        return b"\x02" + h.to_bytes(5, "big")
    return GATEWAY_MAC  # traffic from outside is seen with the router MAC


def ephemeral():
    return random.randint(49152, 65535)


def lognorm(median, sigma):
    return max(1, int(random.lognormvariate(math.log(median), sigma)))


# ---------------------------------------------------------------------------
# Flow construction
# ---------------------------------------------------------------------------

TCP_FULL = 0x1B          # FIN|SYN|PSH|ACK - a normal completed session
TCP_SYN = 0x02
TCP_ACK = 0x10
TCP_RST_ACK = 0x14
DSCP_EF = 46 << 2        # VoIP media
DSCP_CS3 = 24 << 2       # VoIP signalling


def flow(src, dst, sport, dport, proto, nbytes, pkts, flags, start_ms, end_ms, tos=0):
    # (je_v6, vlan, mac, src, dst, sport, dport, flags, bytes, pkts, start, end, tos, proto)
    start_ms = min(start_ms, end_ms)   # reply of a very short flow must not start after it ends
    return (src.version == 6, vlan_of(src, dst), mac_of(src), src.packed, dst.packed,
            sport, dport, flags, nbytes, pkts, start_ms, end_ms, tos, proto)


def timing(dur_s):
    end = int(time.time() * 1000) - random.randint(0, 1000)
    return end - int(dur_s * 1000), end


def tcp_session(src, dst, dport, req, resp, dur, tos=0):
    sport = ephemeral()
    start, end = timing(dur)
    resp_p = max(2, resp // 1400 + 1)
    req_p = max(3, req // 500 + resp_p // 2)       # requests + ACKs
    req = max(req, req_p * 52)
    resp = max(resp, resp_p * 52)
    return [
        flow(src, dst, sport, dport, 6, req, req_p, TCP_FULL, start, end, tos),
        flow(dst, src, dport, sport, 6, resp, resp_p, TCP_FULL, start + 1, end, tos),
    ]


def udp_session(src, dst, dport, req, resp, dur, tos=0, sport=None, pkt_size=1200):
    sport = sport or ephemeral()
    start, end = timing(dur)
    req_p = max(1, req // pkt_size + 1)
    resp_p = max(1, resp // pkt_size + 1)
    return [
        flow(src, dst, sport, dport, 17, max(req, req_p * 28), req_p, 0, start, end, tos),
        flow(dst, src, dport, sport, 17, max(resp, resp_p * 28), resp_p, 0, start + 1, end, tos),
    ]


def v6_roll():
    return random.random() < IPV6_RATIO


# ---------------------------------------------------------------------------
# Traffic scenarios
# ---------------------------------------------------------------------------

def sc_https():
    v6 = v6_roll()
    return tcp_session(client(v6), external(v6), 443, lognorm(3000, 1.0),
                       lognorm(60000, 1.8), min(120, lognorm(3, 1.2)))


def sc_quic():
    v6 = v6_roll()
    return udp_session(client(v6), external(v6), 443, lognorm(8000, 1.0),
                       lognorm(200000, 1.6), min(120, lognorm(8, 1.2)))


def sc_http():
    return tcp_session(client(), external(), 80, lognorm(800, 0.5),
                       lognorm(20000, 1.5), min(30, lognorm(1, 1.0)))


def sc_dns_internal():
    src = client() if random.random() < 0.8 else pick(IOT)
    return udp_session(src, DNS_SERVER, 53, random.randint(60, 90),
                       random.randint(100, 400), random.uniform(0.005, 0.08), pkt_size=512)


def sc_dns_upstream():
    return udp_session(DNS_SERVER, pick(UPSTREAM_DNS), 53, random.randint(60, 90),
                       random.randint(100, 500), random.uniform(0.01, 0.15), pkt_size=512)


def sc_ntp():
    src = pick(IOT + INTERNAL_SERVERS)
    return udp_session(src, pick(NTP_SERVERS), 123, 76, 76, random.uniform(0.01, 0.05),
                       sport=123, pkt_size=76)


def sc_smb():
    return tcp_session(client(), FILE_SERVER, 445, lognorm(20000, 1.2),
                       lognorm(2_000_000, 1.5), min(120, lognorm(20, 1.0)))


def sc_ssh():
    dst = pick(INTERNAL_SERVERS + DMZ_HOSTS[:3])
    return tcp_session(pick(ADMINS), dst, 22, lognorm(40000, 1.0),
                       lognorm(150000, 1.2), min(120, lognorm(60, 0.8)))


def sc_mail_out():
    return tcp_session(MAIL_SERVER, external(), 25, lognorm(40000, 1.3),
                       random.randint(800, 2000), min(30, lognorm(2, 0.8)))


def sc_mail_in():
    return tcp_session(external(), MAIL_SERVER, 25, lognorm(50000, 1.3),
                       random.randint(800, 2000), min(30, lognorm(2, 0.8)))


def sc_web_inbound():
    v6 = v6_roll()
    return tcp_session(external(v6), WEB_V6 if v6 else WEB_V4, 443, lognorm(2000, 0.8),
                       lognorm(80000, 1.4), min(60, lognorm(2, 1.0)))


def sc_voip():
    c = client()
    dur = min(120, lognorm(90, 0.7))
    pkts = int(dur * 50)                      # 20ms paketizace
    start, end = timing(dur)
    port = random.randrange(10000, 20000, 2)
    flows = udp_session(c, SIP_PROVIDER, 5060, random.randint(1500, 4000),
                        random.randint(1500, 4000), random.uniform(0.2, 2), tos=DSCP_CS3,
                        sport=5060, pkt_size=800)
    flows.append(flow(c, SIP_PROVIDER, port, port, 17, pkts * 214, pkts, 0, start, end, DSCP_EF))
    flows.append(flow(SIP_PROVIDER, c, port, port, 17, pkts * 214, pkts, 0, start, end, DSCP_EF))
    return flows


SCAN_PORTS = [22, 23, 80, 443, 445, 1433, 3306, 3389, 5900, 8080, 8443]


def sc_scan():
    scanner = pick(SCANNERS)
    dst = WEB_V4 if random.random() < 0.5 else pick(DMZ_HOSTS)
    dport = random.choice(SCAN_PORTS) if random.random() < 0.8 else random.randint(1, 65535)
    sport = ephemeral()
    start, end = timing(random.uniform(0, 0.01))
    flows = [flow(scanner, dst, sport, dport, 6, 44, 1, TCP_SYN, start, end)]
    if random.random() < 0.5:   # the rest is filtered - no reply
        flows.append(flow(dst, scanner, dport, sport, 6, 40, 1, TCP_RST_ACK, start + 1, end))
    return flows


def sc_icmp():
    v6 = v6_roll()
    src, dst = client(v6), external(v6)
    n = random.choice([1, 4, 4, 10])
    start, end = timing(n - 1 + random.uniform(0.01, 0.2))
    proto, req, rep = (58, 128 << 8, 129 << 8) if v6 else (1, 8 << 8, 0)
    size = 104 if v6 else 84
    return [flow(src, dst, 0, req, proto, n * size, n, 0, start, end),
            flow(dst, src, 0, rep, proto, n * size, n, 0, start + 1, end)]


def sc_iot_cloud():
    return tcp_session(pick(IOT), pick(IOT_CLOUD), 8883, lognorm(1500, 0.8),
                       lognorm(800, 0.8), min(120, lognorm(30, 1.0)))


SCENARIOS = [
    (sc_https, 35), (sc_quic, 10), (sc_http, 4),
    (sc_dns_internal, 15), (sc_dns_upstream, 5), (sc_ntp, 2),
    (sc_smb, 5), (sc_ssh, 1.5), (sc_mail_out, 1), (sc_mail_in, 1),
    (sc_web_inbound, 5), (sc_voip, 1), (sc_scan, 4), (sc_icmp, 2), (sc_iot_cloud, 3),
]
SC_FUNCS = [s[0] for s in SCENARIOS]
SC_WEIGHTS = [s[1] for s in SCENARIOS]


# ---------------------------------------------------------------------------
# Simulated incidents
# ---------------------------------------------------------------------------
# Rare bursts that clearly exceed the dashboard thresholds (flood > 50 flows / 30 s,
# brute force > 10 attempts / 30 s, port scan > 200 ports / min, sweep > 100 targets
# / min, exfiltration > 50 MB / 5 min, ARP spoofing: one IP with more than one MAC
# in 5 min), so the detection panels have something to
# show in demo mode. Each burst fits into 20 s, so even when it is split across two
# time buckets, the larger part is still above the threshold.

BURST_SECS = 20


def burst(n, make):
    """n flows from make(i, start_ms), with start times spread over the last BURST_SECS."""
    now = int(time.time() * 1000)
    return [make(i, now - random.randint(0, BURST_SECS * 1000)) for i in range(n)]


def inc_syn_flood():
    src = pick(SCANNERS)
    flows = burst(random.randint(120, 250), lambda i, t: flow(
        src, WEB_V4, ephemeral(), 443, 6, 44, 1, TCP_SYN, t, t))
    return f"syn_flood {src} -> {WEB_V4}:443", flows


def inc_ack_flood():
    src = pick(SCANNERS)
    flows = burst(random.randint(120, 250), lambda i, t: flow(
        src, WEB_V4, ephemeral(), 443, 6, 40, 1, TCP_ACK, t, t))
    return f"ack_flood {src} -> {WEB_V4}:443", flows


def inc_ssh_bruteforce():
    src, dst = pick(SCANNERS), pick(DMZ_HOSTS[:3])

    def attempt(i, t):
        sport, end = ephemeral(), t + random.randint(300, 1500)
        return [flow(src, dst, sport, 22, 6, random.randint(1500, 3000), 12, TCP_FULL, t, end),
                flow(dst, src, 22, sport, 6, random.randint(2000, 4000), 10, TCP_FULL, t + 1, end)]

    flows = [f for pair in burst(random.randint(30, 60), attempt) for f in pair]
    return f"ssh_bruteforce {src} -> {dst}:22", flows


def inc_port_scan():
    src, dst = pick(SCANNERS), pick(DMZ_HOSTS)
    ports = random.sample(range(1, 65536), random.randint(450, 900))
    flows = burst(len(ports), lambda i, t: flow(
        src, dst, ephemeral(), ports[i], 6, 44, 1, TCP_SYN, t, t))
    return f"port_scan {src} -> {dst} ({len(ports)} ports)", flows


def inc_network_sweep():
    src = pick(SCANNERS)
    targets = [ip(f"192.168.50.{i}") for i in range(1, 255)]
    random.shuffle(targets)
    flows = []
    for dst, f in zip(targets, burst(len(targets), lambda i, t: flow(
            src, targets[i], 0, 8 << 8, 1, 84, 1, 0, t, t))):
        flows.append(f)
        if random.random() < 0.15:   # a few hosts answer the ping
            flows.append(flow(dst, src, 0, 0, 1, 84, 1, 0, f[10] + 1, f[10] + 1))
    return f"network_sweep {src} -> 192.168.50.0/24 ({len(targets)} hosts)", flows


def inc_exfiltration():
    src, dst = client(), external()
    size = random.randint(60, 200) * 1_000_000
    flows = tcp_session(src, dst, 443, size, random.randint(20000, 80000),
                        random.uniform(60, 240))
    return f"exfiltration {src} -> {dst}:443 ({size // 1_000_000} MB)", flows


ATTACKER_MAC = bytes.fromhex("020000006666")


def inc_arp_spoof():
    # A second device claims the server's IP: the same source IP shows up with two
    # MAC addresses. Each step emits the genuine and the spoofed flow at the same
    # time, so every time bucket the burst touches contains both MACs.
    server = pick([DNS_SERVER, FILE_SERVER, MAIL_SERVER])

    def step(i, t):
        dst, dport, sport = client(), ephemeral(), random.choice([53, 445, 25])
        genuine = flow(server, dst, sport, dport, 6, random.randint(500, 5000), 4, TCP_FULL, t, t + 200)
        spoofed = flow(server, dst, sport, dport, 6, random.randint(500, 5000), 4, TCP_FULL, t + 1, t + 200)
        return [genuine, spoofed[:2] + (ATTACKER_MAC,) + spoofed[3:]]

    flows = [f for pair in burst(random.randint(10, 20), step) for f in pair]
    return f"arp_spoof {server} claimed by {ATTACKER_MAC.hex(':')}", flows


INCIDENTS = [inc_syn_flood, inc_ack_flood, inc_ssh_bruteforce, inc_port_scan,
             inc_network_sweep, inc_exfiltration, inc_arp_spoof]


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def load_factor(now):
    """0.2 at night ... 1.0 at peak, half on weekends."""
    if not DIURNAL:
        return 1.0
    t = time.gmtime(now)
    hour = t.tm_hour + t.tm_min / 60
    daily = 0.2 + 0.8 * (1 + math.cos(2 * math.pi * (hour - PEAK_HOUR_UTC) / 24)) / 2
    weekend = 0.5 if t.tm_wday >= 5 else 1.0
    return daily * weekend


def poisson(lam):
    if lam <= 0:
        return 0
    if lam > 30:
        return max(0, round(random.gauss(lam, math.sqrt(lam))))
    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= random.random()
        if p <= limit:
            return k
        k += 1


running = True


def stop(*_):
    global running
    running = False


def main():
    signal.signal(signal.SIGTERM, stop)   # PID 1 in a container ignores SIGTERM otherwise
    signal.signal(signal.SIGINT, stop)
    exp = Exporter(TARGET_HOST, TARGET_PORT, ODID)
    print(f"[generator] start: {SESSIONS_PER_SEC} sessions/s at peak, "
          f"IPv6 {IPV6_RATIO:.0%}, diurnal pattern {'on' if DIURNAL else 'off'}, "
          f"incidents {'every ~%g min' % INCIDENT_INTERVAL_MIN if INCIDENT_INTERVAL_MIN > 0 else 'off'}",
          flush=True)

    next_tick = time.time()
    last_stats, last_flows = time.time(), 0
    while running:
        now = time.time()
        n = poisson(SESSIONS_PER_SEC * load_factor(now))
        flows = []
        for _ in range(n):
            flows.extend(random.choices(SC_FUNCS, weights=SC_WEIGHTS)[0]())
        if INCIDENT_INTERVAL_MIN > 0 and random.random() < 1 / (INCIDENT_INTERVAL_MIN * 60):
            desc, inc_flows = random.choice(INCIDENTS)()
            flows.extend(inc_flows)
            print(f"[generator] incident: {desc}, {len(inc_flows)} flows", flush=True)
        if flows:
            exp.send(flows)

        if now - last_stats >= STATS_EVERY_SECS:
            rate = (exp.sent_flows - last_flows) / (now - last_stats)
            print(f"[generator] sent {exp.sent_flows} flows / {exp.sent_msgs} messages total, "
                  f"current rate {rate:.1f} flows/s (load {load_factor(now):.0%})", flush=True)
            last_stats, last_flows = now, exp.sent_flows

        next_tick += 1
        delay = next_tick - time.time()
        if delay > 0:
            time.sleep(delay)
        else:
            next_tick = time.time()   # falling behind -> do not catch up
    print("[generator] shutting down", flush=True)


if __name__ == "__main__":
    main()