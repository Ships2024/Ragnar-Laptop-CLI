#!/usr/bin/env python3
"""arp_guard.py — layered ARP poisoning / spoofing detector (Ragnar).

Detection only: it never sends a corrective ARP, blocks traffic, or intervenes —
it watches and alerts. Passive: Scapy is used only as the live-capture front end;
field extraction is a hand-rolled raw-byte parser (no library dissector), so the
self-test drives the exact production parse path with no Scapy and no NIC.

A fixed pipeline of four independent, stateful layers scores each observed ARP
frame; findings about one packet from multiple layers are merged into a single
alert (highest severity, combined evidence) to avoid alert fatigue during a
sustained attack.

  1 binding      IP->MAC conflict / rapid flap (arpspoof/ettercap in progress)
  2 gratuitous   gratuitous-ARP rate to one IP + breadth (subnet-wide poison)
  3 structural   per-packet field/opcode/consistency sanity (sloppy tooling)
  4 gateway      trusted IP->MAC pins set out-of-band (gateway impersonation)

Unlike the snapshot-based ARP check in network_diagnostics (which reads the
resolved neighbour table), this watches the live packet stream, so it sees the
attack *in progress*. See docs/arp_guard.md.
"""

import argparse
import json
import os
import struct
import sys
import time
from collections import defaultdict, deque

MODULE = 'arp_guard'
SEV_RANK = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
ETH_P_ARP = 0x0806
ETH_P_8021Q = 0x8100
BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
ZERO_IP = '0.0.0.0'

DEFAULTS = {
    'garp_window_s': 10.0,
    'garp_rate_threshold': 5,        # gratuitous ARPs to ONE ip in the window
    'garp_breadth_threshold': 4,     # distinct ips one mac gratuitously claims
    'flap_window_s': 30.0,
    'flap_count': 3,                 # binding changes for one ip in the window
    'stable_threshold_s': 300.0,     # an old binding this stable -> high on change
    'trusted_bindings': {},          # ip -> mac, pinned OUT OF BAND
}


# ===========================================================================
# Raw-byte Ethernet + ARP parser
# ===========================================================================
def _mac(b, i):
    return ':'.join('%02x' % x for x in b[i:i + 6])


def _ip(b, i):
    return '%d.%d.%d.%d' % (b[i], b[i + 1], b[i + 2], b[i + 3])


def _u16(b, i):
    return (b[i] << 8) | b[i + 1]


def parse_arp(raw):
    """Parse an Ethernet(/802.1Q) ARP frame into a dict, or None if not ARP.
    Never raises: a truncated/odd frame is returned with truncated/malformed set
    so the structural layer can flag it instead of the sniffer dying."""
    if len(raw) < 14:
        return None
    off = 12
    etype = _u16(raw, 12)
    if etype == ETH_P_8021Q:
        if len(raw) < 18:
            return None
        off = 16
        etype = _u16(raw, 16)
    if etype != ETH_P_ARP:
        return None
    a = off + 2
    d = {'eth_src': _mac(raw, 6), 'eth_dst': _mac(raw, 0),
         'hwtype': None, 'ptype': None, 'hwlen': None, 'plen': None,
         'opcode': None, 'sender_mac': None, 'sender_ip': None,
         'target_mac': None, 'target_ip': None, 'truncated': False,
         'malformed': None}
    if len(raw) < a + 8:
        d['truncated'] = True
        d['malformed'] = 'ARP header truncated'
        return d
    d['hwtype'] = _u16(raw, a)
    d['ptype'] = _u16(raw, a + 2)
    d['hwlen'] = raw[a + 4]
    d['plen'] = raw[a + 5]
    d['opcode'] = _u16(raw, a + 6)
    p = a + 8
    need = p + 2 * d['hwlen'] + 2 * d['plen']
    if len(raw) < need:
        d['truncated'] = True
        d['malformed'] = 'frame shorter than its declared hwlen/plen'
        return d
    if d['hwlen'] == 6 and d['plen'] == 4:
        d['sender_mac'] = _mac(raw, p)
        d['sender_ip'] = _ip(raw, p + 6)
        d['target_mac'] = _mac(raw, p + 10)
        d['target_ip'] = _ip(raw, p + 16)
    return d


def _is_mcast_or_bcast_ip(ip):
    try:
        first = int(ip.split('.')[0])
        return ip == '255.255.255.255' or 224 <= first <= 239
    except (ValueError, IndexError, AttributeError):
        return False


# ===========================================================================
# Pipeline
# ===========================================================================
class ArpGuard:
    def __init__(self, config=None, emit=None):
        c = dict(DEFAULTS)
        c.update(config or {})
        self.cfg = c
        self.emit = emit or (lambda a: None)
        self.trusted = {k.lower(): v.lower() for k, v in (c.get('trusted_bindings') or {}).items()}
        # layer 1
        self._bind = {}                          # ip -> {'mac', 'since', 'flaps': deque}
        # layer 2
        self._garp = defaultdict(lambda: deque())    # mac -> deque[(ts, ip)]
        self.frames = 0
        self.stats = defaultdict(int)

    @staticmethod
    def _trim(dq, ts, window, keyed=True):
        while dq and ts - (dq[0][0] if keyed else dq[0]) > window:
            dq.popleft()

    def process_packet(self, raw, ts=None):
        pkt = parse_arp(raw)
        if pkt is None:
            return None
        if ts is None:
            ts = time.time()
        self.frames += 1
        findings = []
        findings += self._layer3_structural(pkt)
        # A truncated/malformed frame has no trustworthy addresses; stop after
        # the structural finding rather than feed junk into the stateful layers.
        if not pkt.get('malformed'):
            findings += self._layer4_gateway_trust(pkt, ts)
            findings += self._layer1_binding(pkt, ts)
            findings += self._layer2_gratuitous(pkt, ts)
        if findings:
            return self._merge_and_emit(pkt, findings, ts)
        return None

    # -- layer 1: binding conflict / flap ------------------------------------
    def _layer1_binding(self, pkt, ts):
        ip, mac = pkt.get('sender_ip'), pkt.get('sender_mac')
        if not ip or not mac or ip == ZERO_IP:   # 0.0.0.0 = ARP probe, not a claim
            return []
        b = self._bind.get(ip)
        if b is None:
            self._bind[ip] = {'mac': mac, 'since': ts, 'flaps': deque()}
            return []
        if b['mac'] == mac:
            return []
        # binding changed
        stable_for = ts - b['since']
        b['flaps'].append((ts, mac))
        self._trim(b['flaps'], ts, self.cfg['flap_window_s'])
        macs_in_window = {m for _t, m in b['flaps']} | {b['mac']}
        prev = b['mac']
        b['mac'], b['since'] = mac, ts
        if len(b['flaps']) >= self.cfg['flap_count'] and len(macs_in_window) >= 2:
            return [{'layer': 'binding', 'code': 'binding_flap', 'severity': 'critical',
                     'detail': '%s is flapping between %d MACs (%d changes/%.0fs) — two '
                     'hosts racing to answer (active ARP spoofing)'
                     % (ip, len(macs_in_window), len(b['flaps']), self.cfg['flap_window_s'])}]
        sev = 'high' if stable_for >= self.cfg['stable_threshold_s'] else 'medium'
        return [{'layer': 'binding', 'code': 'binding_conflict', 'severity': sev,
                 'detail': '%s moved from %s to %s (old binding stable %.0fs) — ARP '
                 'cache poisoning' % (ip, prev, mac, stable_for)}]

    # -- layer 2: gratuitous ARP rate + breadth ------------------------------
    def _layer2_gratuitous(self, pkt, ts):
        ip, mac = pkt.get('sender_ip'), pkt.get('sender_mac')
        # Gratuitous ARP: sender IP == target IP (an unsolicited binding assert).
        if not ip or not mac or ip == ZERO_IP or pkt.get('target_ip') != ip:
            return []
        dq = self._garp[mac]
        dq.append((ts, ip))
        self._trim(dq, ts, self.cfg['garp_window_s'])
        same_ip = sum(1 for _t, i in dq if i == ip)
        distinct = {i for _t, i in dq}
        out = []
        if len(distinct) >= self.cfg['garp_breadth_threshold']:
            out.append({'layer': 'gratuitous', 'code': 'garp_subnet_poison', 'severity': 'high',
                        'detail': '%s sent gratuitous ARP for %d distinct IPs in %.0fs — '
                        'subnet-wide poisoning' % (mac, len(distinct), self.cfg['garp_window_s'])})
        elif same_ip >= self.cfg['garp_rate_threshold']:
            out.append({'layer': 'gratuitous', 'code': 'garp_rate_flood', 'severity': 'medium',
                        'detail': '%s sent %d gratuitous ARPs for %s in %.0fs — targeted '
                        'poisoning/flood' % (mac, same_ip, ip, self.cfg['garp_window_s'])})
        return out

    # -- layer 3: structural integrity ---------------------------------------
    def _layer3_structural(self, pkt):
        out = []

        def add(sev, code, detail):
            out.append({'layer': 'structural', 'code': code, 'severity': sev, 'detail': detail})

        if pkt.get('malformed'):
            add('medium', 'malformed', pkt['malformed'])
            return out
        op = pkt.get('opcode')
        if op not in (1, 2):
            add('medium', 'bad_opcode', 'invalid ARP opcode %s' % op)
        if pkt.get('hwtype') != 1:
            add('low', 'bad_hwtype', 'non-Ethernet hwtype %s' % pkt.get('hwtype'))
        if pkt.get('ptype') != 0x0800:
            add('low', 'bad_ptype', 'non-IPv4 ptype 0x%04x' % (pkt.get('ptype') or 0))
        smac, emac = pkt.get('sender_mac'), pkt.get('eth_src')
        if smac and emac and smac != emac:
            add('high', 'src_mismatch',
                'Ethernet source %s != ARP sender hardware address %s — forged' % (emac, smac))
        sip = pkt.get('sender_ip')
        if sip and _is_mcast_or_bcast_ip(sip):
            add('medium', 'bcast_sender_ip', 'sender IP %s is multicast/broadcast' % sip)
        if op == 2:                              # reply
            # A *gratuitous* announcement (sender IP == target IP) is legitimately
            # broadcast; only a solicited reply to broadcast is anomalous (real
            # replies are unicast to the requester). Gratuitous-ARP abuse is
            # caught by the rate/breadth layer, not here.
            if pkt.get('eth_dst') == BROADCAST_MAC and sip != pkt.get('target_ip'):
                add('medium', 'broadcast_reply',
                    'solicited ARP reply sent to broadcast (real replies are unicast)')
            if sip == ZERO_IP:
                add('medium', 'zero_reply', 'ARP reply with sender IP 0.0.0.0 (invalid)')
        # NOTE: opcode 1 (request) with sender 0.0.0.0 is a legitimate ARP probe
        # (RFC 5227) and is intentionally NOT flagged.
        return out

    # -- layer 4: trusted-binding pins ---------------------------------------
    def _layer4_gateway_trust(self, pkt, ts):
        ip, mac = pkt.get('sender_ip'), pkt.get('sender_mac')
        if not ip or not mac or ip == ZERO_IP:
            return []
        pinned = self.trusted.get(ip.lower())
        if pinned and mac.lower() != pinned:
            return [{'layer': 'gateway', 'code': 'trusted_impersonation', 'severity': 'critical',
                     'detail': 'pinned host %s (trusted %s) is being claimed by %s — '
                     'gateway/host impersonation' % (ip, pinned, mac)}]
        return []

    # -- merge ---------------------------------------------------------------
    def _merge_and_emit(self, pkt, findings, ts):
        worst = max(findings, key=lambda f: SEV_RANK[f['severity']])
        alert = {
            'ts': ts, 'module': MODULE, 'severity': worst['severity'],
            'sender_ip': pkt.get('sender_ip'), 'sender_mac': pkt.get('sender_mac'),
            'eth_src': pkt.get('eth_src'), 'opcode': pkt.get('opcode'),
            'codes': [f['code'] for f in findings],
            'summary': worst['detail'],
            'evidence': [{'layer': f['layer'], 'code': f['code'],
                          'severity': f['severity'], 'detail': f['detail']}
                         for f in sorted(findings, key=lambda f: -SEV_RANK[f['severity']])],
        }
        self.stats[worst['severity']] += 1
        self.emit(alert)
        return alert


# ===========================================================================
# Passive gateway learning (reads the kernel neighbour table — no packet sent)
# ===========================================================================
def learn_gateway(gateway_ip):
    """Return the gateway's MAC from /proc/net/arp (already-resolved by the
    kernel). Passive: sends nothing. Ping the gateway once if there's no entry."""
    try:
        with open('/proc/net/arp') as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == gateway_ip and parts[3] != '00:00:00:00:00:00':
                    return parts[3]
    except OSError:
        pass
    return None


# ===========================================================================
# Live capture / replay (scapy, lazy)
# ===========================================================================
def run_live(iface, guard):
    from scapy.all import sniff
    sys.stderr.write('arp_guard: passive on %s (arp) — Ctrl-C to stop\n' % iface)
    sniff(iface=iface, filter='arp or vlan', store=False,
          prn=lambda p: guard.process_packet(bytes(p), float(getattr(p, 'time', 0)) or time.time()))


def run_replay(path, guard):
    from scapy.all import PcapReader
    with PcapReader(path) as pr:
        for p in pr:
            guard.process_packet(bytes(p), float(getattr(p, 'time', 0)) or time.time())


# ===========================================================================
# CLI
# ===========================================================================
def make_emitter(out_fh, echo):
    def emit(a):
        line = json.dumps(a)
        if out_fh:
            out_fh.write(line + '\n')
            out_fh.flush()
        if echo:
            sys.stderr.write('  !! [%s] %s %s :: %s\n' % (
                a['severity'], a.get('sender_ip') or '?', ','.join(a['codes']), a['summary']))
    return emit


def main(argv=None):
    ap = argparse.ArgumentParser(prog='arp_guard',
                                 description='Passive layered ARP poisoning detector (detection-only).')
    ap.add_argument('-i', '--iface', help='live capture interface')
    ap.add_argument('--replay', help='replay a pcap instead of live capture')
    ap.add_argument('-c', '--config', help='JSON config (thresholds + trusted_bindings)')
    ap.add_argument('--jsonl', '-o', help="JSON-lines output path ('-' = stdout)")
    ap.add_argument('--echo', action='store_true', help='echo alerts to stderr')
    ap.add_argument('--learn-gateway', action='store_true',
                    help='print the gateway MAC from the kernel neighbour table (passive)')
    ap.add_argument('--gateway-ip', help='gateway IP for --learn-gateway')
    ap.add_argument('--self-test', action='store_true')
    args = ap.parse_args(argv)

    if args.self_test:
        import arp_guard_selftest
        return arp_guard_selftest.run(verbose=True)
    if args.learn_gateway:
        if not args.gateway_ip:
            ap.error('--learn-gateway needs --gateway-ip')
        mac = learn_gateway(args.gateway_ip)
        if mac:
            print('%s is at %s  (copy into trusted_bindings)' % (args.gateway_ip, mac))
            return 0
        sys.stderr.write('no neighbour entry for %s — ping it once, then retry\n' % args.gateway_ip)
        return 1

    cfg = {}
    if args.config:
        with open(args.config) as f:
            cfg = json.load(f)
    out_fh = sys.stdout if args.jsonl == '-' else (
        open(args.jsonl, 'a') if args.jsonl else None)
    guard = ArpGuard(cfg, emit=make_emitter(out_fh, args.echo or not args.jsonl))

    if args.replay:
        run_replay(args.replay, guard)
    elif args.iface:
        if os.geteuid() != 0:
            sys.stderr.write('error: live capture needs root / CAP_NET_RAW.\n')
            return 2
        try:
            run_live(args.iface, guard)
        except KeyboardInterrupt:
            pass
    else:
        ap.error('one of --iface, --replay, --learn-gateway or --self-test is required')
    sys.stderr.write('arp_guard: %d frames, alerts %s\n' % (guard.frames, dict(guard.stats)))
    if out_fh and out_fh is not sys.stdout:
        out_fh.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
