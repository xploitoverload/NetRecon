#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║              N E T R E C O N  v2.0                           ║
║         Autonomous Local Network Scanner                     ║
║         github.com/xploitoverload  |  Hack.The.Planet        ║
╚═══════════════════════════════════════════════════════════════╝

Full-featured ARP-based network discovery tool.
Active/passive scanning, interactive TUI, parsable output,
live monitor, port scan, JSON/CSV export.

Developer  : Kalpesh Solanki (xploitoverload)

"""

import sys
import os
import json
import csv
import time
import curses
import socket
import struct
import signal
import argparse
import threading
import ipaddress
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Dependency guard ──────────────────────────────────────────────────────────
MISSING = []
try:
    from scapy.all import (
        ARP, Ether, srp, sniff, sendp, conf as scapy_conf,
        get_if_hwaddr,
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    MISSING.append("scapy")

try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False
    MISSING.append("netifaces")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import (Progress, SpinnerColumn, BarColumn,
                               TextColumn, TimeElapsedColumn)
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    MISSING.append("rich")

# ── Import OUI table ──────────────────────────────────────────────────────────
try:
    from oui_table import OUI_TABLE
except ImportError:
    OUI_TABLE = {}   # fallback: empty, scapy manuf db used instead

# ── Console (used only outside curses TUI) ────────────────────────────────────
console = Console(highlight=False) if HAS_RICH else None

C = {
    "purple": "\033[95m", "cyan": "\033[96m", "green": "\033[92m",
    "yellow": "\033[93m", "red":    "\033[91m", "bold":  "\033[1m",
    "dim":    "\033[2m",  "reset":  "\033[0m",
}

VERSION = "2.0"

# ── Common networks — netdiscover default auto-scan list ──────────────────────
COMMON_NETWORKS = [
    "192.168.0.0/16",
    "169.254.0.0/16",
    "172.16.0.0/16", "172.17.0.0/16", "172.18.0.0/16", "172.19.0.0/16",
    "172.20.0.0/16", "172.21.0.0/16", "172.22.0.0/16", "172.23.0.0/16",
    "172.24.0.0/16", "172.25.0.0/16", "172.26.0.0/16", "172.27.0.0/16",
    "172.28.0.0/16", "172.29.0.0/16", "172.30.0.0/16", "172.31.0.0/16",
    "10.0.0.0/8",
]

# ── Fast mode last octets ─────────────────────────────────────────────────────
FAST_IPS = ["1", "2", "100", "200", "254"]

# ── Common ports for optional port scan ───────────────────────────────────────
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                443, 445, 3306, 3389, 5900, 8080, 8443, 9100]

# ── Virtual interface prefixes to skip ───────────────────────────────────────
_SKIP_PREFIXES = (
    "lo", "virbr", "docker", "veth", "br-", "vmnet",
    "dummy", "tunl", "sit", "ip6tnl", "gre", "tun",
)

# ── Screen view modes (same as netdiscover) ───────────────────────────────────
SMODE_REPLY   = 0
SMODE_REQUEST = 1
SMODE_HELP    = 2
SMODE_HOST    = 3

# =============================================================================
# DATA LAYER
# Three independent registries mirroring netdiscover's data_reply,
# data_request, data_unique.
# =============================================================================

class DataRegistry:
    """Single host entry — mirrors struct data_registry."""
    __slots__ = ("ip", "mac", "vendor", "hostname", "arp_type",
                 "count", "tlength", "focused")

    def __init__(self, ip, mac, vendor, hostname, arp_type, length):
        self.ip       = ip
        self.mac      = mac
        self.vendor   = vendor
        self.hostname = hostname
        self.arp_type = arp_type   # "reply" | "request"
        self.count    = 1
        self.tlength  = length
        self.focused  = False      # True = known host (from -m file)


class DataLayer:
    """
    Thread-safe list of DataRegistry entries.
    Mirrors netdiscover's data_al abstraction layer.
    """
    def __init__(self, name: str):
        self.name    = name
        self._list: list[DataRegistry] = []
        self._lock   = threading.Lock()
        self.packets = 0
        self.total_length = 0

    def add(self, entry: DataRegistry, dedup_key=None):
        """
        Add or update. dedup_key is a callable(existing, new) -> bool
        returning True if they are duplicates.
        """
        with self._lock:
            self.packets     += 1
            self.total_length += entry.tlength
            if dedup_key:
                for existing in self._list:
                    if dedup_key(existing, entry):
                        existing.count   += 1
                        existing.tlength += entry.tlength
                        return False   # duplicate — not added
            self._list.append(entry)
            return True   # new entry

    def hosts_count(self) -> int:
        with self._lock:
            return len(self._list)

    def snapshot(self) -> list[DataRegistry]:
        with self._lock:
            return list(self._list)

    def clear(self):
        with self._lock:
            self._list.clear()
            self.packets = 0
            self.total_length = 0


# Global data layers — same role as _data_reply, _data_request, _data_unique
data_reply   = DataLayer("ARP Reply")
data_request = DataLayer("ARP Request")
data_unique  = DataLayer("Unique Hosts")

# Dedup functions
def _dedup_reply(a: DataRegistry, b: DataRegistry) -> bool:
    return a.ip == b.ip and a.mac == b.mac

def _dedup_request(a: DataRegistry, b: DataRegistry) -> bool:
    return a.ip == b.ip and a.mac == b.mac

def _dedup_unique(a: DataRegistry, b: DataRegistry) -> bool:
    return a.ip == b.ip and a.mac == b.mac

# =============================================================================
# INTERFACE DETECTION
# =============================================================================

def _is_virtual(name: str) -> bool:
    return any(name.startswith(p) for p in _SKIP_PREFIXES)


def _active_ip_via_socket() -> "str | None":
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip if ip and not ip.startswith("127.") else None
    except Exception:
        return None


def _active_ip_via_ip_route() -> "tuple[str,str] | tuple[None,None]":
    try:
        out = subprocess.check_output(
            ["ip", "route", "get", "8.8.8.8"],
            text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            parts = line.split()
            ip  = parts[parts.index("src") + 1] if "src" in parts else None
            dev = parts[parts.index("dev") + 1] if "dev" in parts else None
            if ip and dev and not ip.startswith("127."):
                return ip, dev
    except Exception:
        pass
    return None, None


def _iface_details_from_ip_addr(iface: str, local_ip: str):
    netmask = "255.255.255.0"
    mac = "??:??:??:??:??:??"
    try:
        out = subprocess.check_output(
            ["ip", "addr", "show", iface],
            text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("link/ether"):
                mac = line.split()[1]
            if line.startswith("inet ") and local_ip in line:
                prefix = int(line.split()[1].split("/")[1])
                netmask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
    except Exception:
        pass
    return netmask, mac


def _iface_for_ip_proc(local_ip: str) -> "str | None":
    try:
        out = subprocess.check_output(
            ["ip", "-o", "-4", "addr"],
            text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            iface = parts[1]
            if _is_virtual(iface):
                continue
            if parts[3].split("/")[0] == local_ip:
                return iface
    except Exception:
        pass
    return None


def _full_record_netifaces(iface: str, local_ip: str):
    if not HAS_NETIFACES:
        return None
    try:
        addrs = netifaces.ifaddresses(iface)
        for entry in addrs.get(netifaces.AF_INET, []):
            if entry.get("addr") == local_ip:
                nm  = entry.get("netmask", "255.255.255.0")
                mac = ""
                if netifaces.AF_LINK in addrs:
                    mac = addrs[netifaces.AF_LINK][0].get("addr", "??:??:??:??:??:??")
                return (iface, local_ip, nm, mac)
    except Exception:
        pass
    return None


def detect_active_interface():
    local_ip = _active_ip_via_socket()
    iface_name = None
    iproute_ip, iproute_iface = _active_ip_via_ip_route()

    if iproute_iface and not _is_virtual(iproute_iface):
        iface_name = iproute_iface
        if not local_ip:
            local_ip = iproute_ip

    if not local_ip:
        return None

    if not iface_name:
        if HAS_NETIFACES:
            for iface in netifaces.interfaces():
                if _is_virtual(iface):
                    continue
                addrs = netifaces.ifaddresses(iface)
                for e in addrs.get(netifaces.AF_INET, []):
                    if e.get("addr") == local_ip:
                        iface_name = iface
                        break
        if not iface_name:
            iface_name = _iface_for_ip_proc(local_ip)

    if not iface_name:
        return None

    rec = _full_record_netifaces(iface_name, local_ip)
    if rec:
        return rec

    netmask, mac = _iface_details_from_ip_addr(iface_name, local_ip)
    return (iface_name, local_ip, netmask, mac)


def detect_all_interfaces():
    results = []
    if HAS_NETIFACES:
        for iface in netifaces.interfaces():
            if _is_virtual(iface):
                continue
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET not in addrs:
                continue
            for entry in addrs[netifaces.AF_INET]:
                ip  = entry.get("addr", "")
                nm  = entry.get("netmask", "255.255.255.0")
                mac = ""
                if netifaces.AF_LINK in addrs:
                    mac = addrs[netifaces.AF_LINK][0].get("addr", "??:??:??:??:??:??")
                if ip and not ip.startswith("127."):
                    results.append((iface, ip, nm, mac))
    else:
        try:
            out = subprocess.check_output(
                ["ip", "-o", "-4", "addr"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) < 4:
                    continue
                iface = parts[1]
                if _is_virtual(iface):
                    continue
                addr_cidr = parts[3]
                ip = addr_cidr.split("/")[0]
                prefix = int(addr_cidr.split("/")[1])
                nm = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
                mac = _get_mac_ip_link(iface)
                if not ip.startswith("127."):
                    results.append((iface, ip, nm, mac))
        except Exception:
            pass
    return results


def _get_mac_ip_link(iface: str) -> str:
    try:
        out = subprocess.check_output(
            ["ip", "link", "show", iface], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("link/ether"):
                return line.split()[1]
    except Exception:
        pass
    return "??:??:??:??:??:??"


def iface_to_cidr(ip: str, netmask: str) -> str:
    return str(ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False))


def detect_gateway() -> "str | None":
    if HAS_NETIFACES:
        try:
            gws = netifaces.gateways()
            gw  = gws.get("default", {}).get(netifaces.AF_INET, [None])[0]
            if gw:
                return gw
        except Exception:
            pass
    for cmd in (["ip", "route", "show", "default"],
                ["ip", "route", "get", "8.8.8.8"]):
        try:
            out = subprocess.check_output(
                cmd, text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                parts = line.split()
                if "via" in parts:
                    return parts[parts.index("via") + 1]
        except Exception:
            pass
    return None


def resolve_forced_iface(iface_name: str):
    for rec in detect_all_interfaces():
        if rec[0] == iface_name:
            return rec
    _print_err(f"Interface '{iface_name}' not found or has no IPv4.")
    sys.exit(1)

# =============================================================================
# VENDOR / HOSTNAME LOOKUP
# =============================================================================

def lookup_vendor(mac: str) -> str:
    if not mac or mac in ("??:??:??:??:??:??", "N/A", ""):
        return "Unknown vendor"
    mac_upper = mac.upper()
    oui = mac_upper[:8]
    # Try full OUI table first (37k+ entries)
    if oui in OUI_TABLE:
        return OUI_TABLE[oui]
    # Fallback: scapy manuf db
    if HAS_SCAPY:
        try:
            from scapy.libs.manuf import ManufDB
            db     = ManufDB()
            result = db.get(mac)
            if result:
                return result[1] or result[0] or "Unknown vendor"
        except Exception:
            pass
    return "Unknown vendor"


def resolve_hostname(ip: str, timeout: float = 0.3) -> str:
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        hostname = socket.gethostbyaddr(ip)[0]
        socket.setdefaulttimeout(old)
        return hostname
    except Exception:
        return ""

# =============================================================================
# KNOWN MAC TABLE  (netdiscover -m flag)
# =============================================================================

known_mac_table: dict[str, str] = {}   # MAC_UPPER_NOCOLON -> hostname


def load_known_mac_table(filepath: str) -> bool:
    """
    Load known MACs file.  Format per line:
        AA:BB:CC:DD:EE:FF  hostname
    Returns True on success.
    """
    global known_mac_table
    try:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) < 2:
                    continue
                mac  = parts[0].upper().replace(":", "").replace("-", "")
                host = parts[1].strip()
                if len(mac) == 12:
                    known_mac_table[mac] = host
        return True
    except Exception:
        return False


def search_known_mac(mac: str) -> "str | None":
    key = mac.upper().replace(":", "").replace("-", "")
    return known_mac_table.get(key)

# =============================================================================
# OWN MAC CACHE — ignore our own injected packets
# =============================================================================

_OWN_MAC: str = ""


def inject_init(iface: str):
    global _OWN_MAC
    try:
        if HAS_SCAPY:
            _OWN_MAC = get_if_hwaddr(iface).upper()
        else:
            _OWN_MAC = _get_mac_ip_link(iface).upper()
    except Exception:
        _OWN_MAC = ""

# =============================================================================
# PACKET PROCESSING  (mirrors process_packet + process_arp_header)
# =============================================================================

def _process_packet(pkt):
    """Called for every captured packet by scapy sniff()."""
    if not pkt.haslayer(ARP):
        return

    arp = pkt[ARP]
    eth = pkt[Ether]

    src_mac = eth.src.upper()
    src_ip  = arp.psrc
    dst_ip  = arp.pdst
    length  = len(pkt)
    op      = arp.op   # 1=request  2=reply

    # Ignore our own packets
    if _OWN_MAC and src_mac == _OWN_MAC:
        return
    if not src_ip or src_ip == "0.0.0.0":
        return

    arp_type = "reply" if op == 2 else "request"

    # Vendor + hostname
    known_host = search_known_mac(src_mac)
    if known_host:
        vendor   = known_host
        focused  = True
    else:
        vendor  = lookup_vendor(src_mac)
        focused = False

    hostname = resolve_hostname(src_ip)

    entry = DataRegistry(src_ip, src_mac, vendor, hostname, arp_type, length)
    entry.focused = focused

    # unique hosts (mirrors data_unique — dedup by IP+MAC)
    data_unique.add(entry, dedup_key=_dedup_unique)

    # per-type lists
    if op == 2:
        data_reply.add(entry, dedup_key=_dedup_reply)
    else:
        data_request.add(entry, dedup_key=_dedup_request)

    # parsable output — printed immediately if enabled
    if _parsable_output:
        _parsable_print(entry)

# =============================================================================
# ARP INJECTION  (mirrors forge_arp + scan_range + scan_net)
# =============================================================================

def forge_arp(src_ip: str, dst_ip: str, iface: str):
    if not HAS_SCAPY:
        return
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=dst_ip, psrc=src_ip)
    sendp(pkt, iface=iface, verbose=0)


def _get_fast_hosts(cidr: str) -> list:
    net  = ipaddress.IPv4Network(cidr, strict=False)
    base = str(net.network_address).rsplit(".", 1)[0]
    hosts = []
    for last in FAST_IPS:
        ip = f"{base}.{last}"
        try:
            if ipaddress.IPv4Address(ip) in net:
                hosts.append(ip)
        except Exception:
            pass
    return hosts


def inject_range(cidr: str, iface: str, src_node: int,
                 repeat: int, sleep_ms: int, suppress_sleep: bool,
                 fast_mode: bool, stop_event: threading.Event,
                 current_network_ref: list):
    """
    Inject ARP requests over a CIDR — mirrors inject_arp + scan_range.
    current_network_ref[0] is updated with current CIDR for display.
    """
    net = ipaddress.IPv4Network(cidr, strict=False)
    current_network_ref[0] = cidr

    if fast_mode:
        hosts = _get_fast_hosts(cidr)
    else:
        hosts = [str(h) for h in net.hosts()]

    # Source IP: first host with last octet replaced by src_node
    base   = str(net.network_address).rsplit(".", 1)[0]
    src_ip = f"{base}.{src_node}"
    if not hosts:
        return

    for _ in range(repeat):
        if stop_event.is_set():
            break
        for ip in hosts:
            if stop_event.is_set():
                break
            forge_arp(src_ip, ip, iface)
            if not suppress_sleep:
                delay = (sleep_ms / 1000.0) if sleep_ms else 0.001
                time.sleep(delay)
        if suppress_sleep:
            delay = (sleep_ms / 1000.0) if sleep_ms else 0.001
            time.sleep(delay)

# =============================================================================
# SNIFFER THREAD  (mirrors start_sniffer)
# =============================================================================

def start_sniffer(iface: str, pcap_filter: str, stop_event: threading.Event):
    def _stop_fn(_):
        return stop_event.is_set()

    sniff(
        iface=iface,
        filter=pcap_filter,
        prn=_process_packet,
        stop_filter=_stop_fn,
        store=False,
    )

# =============================================================================
# FAST ACTIVE SCAN (NetRecon original — parallel srp chunks)
# Used when passive=False to supplement injection-based scan
# =============================================================================

_ARP_CHUNK   = 32
_ARP_TIMEOUT = 0.8
_ARP_WORKERS = 16


def _arp_chunk_worker(args_tuple):
    ip_list, iface = args_tuple
    results = []
    try:
        pkts = [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
                for ip in ip_list]
        answered, _ = srp(pkts, iface=iface, timeout=_ARP_TIMEOUT,
                          verbose=0, inter=0, retry=1)
        for _, rcv in answered:
            results.append((rcv[ARP].psrc, rcv[Ether].src.upper(), len(rcv)))
    except Exception:
        pass
    return results


def fast_arp_scan(cidr: str, iface: str):
    """Parallel chunk-based ARP scan — feeds results into data layers."""
    scapy_conf.verb = 0
    net   = ipaddress.IPv4Network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()]
    chunks = [hosts[i:i + _ARP_CHUNK]
              for i in range(0, len(hosts), _ARP_CHUNK)]
    work = [(c, iface) for c in chunks]

    with ThreadPoolExecutor(max_workers=_ARP_WORKERS) as ex:
        for batch in ex.map(_arp_chunk_worker, work):
            for ip, mac, length in batch:
                known_host = search_known_mac(mac)
                vendor   = known_host if known_host else lookup_vendor(mac)
                focused  = bool(known_host)
                hostname = resolve_hostname(ip)
                entry    = DataRegistry(ip, mac, vendor, hostname,
                                        "reply", length)
                entry.focused = focused
                data_unique.add(entry, dedup_key=_dedup_unique)
                data_reply.add(entry,  dedup_key=_dedup_reply)

# =============================================================================
# PARSABLE OUTPUT  (mirrors netdiscover -P / -L)
# =============================================================================

_parsable_output   = False
_continue_listening = False
_no_header         = False


def _parsable_print(entry: DataRegistry):
    print(f"  {entry.ip:<16}  {entry.mac:<18}  "
          f"{entry.count:<5}  {entry.tlength:<7}  {entry.vendor}")
    sys.stdout.flush()


def print_parsable_header():
    print(" _____________________________________________________________________________")
    print("   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      ")
    print(" -----------------------------------------------------------------------------")

# =============================================================================
# PORT SCAN  (NetRecon feature)
# =============================================================================

def tcp_scan_host(ip: str, ports=COMMON_PORTS, timeout=0.5) -> list:
    def check(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                return port
            s.close()
        except Exception:
            pass
        return None
    with ThreadPoolExecutor(max_workers=len(ports)) as ex:
        return sorted(r for r in ex.map(check, ports) if r)

# =============================================================================
# EXPORT  (NetRecon feature)
# =============================================================================

def export_json(devices: list, path: str):
    data = {
        "scan_time": datetime.now().isoformat(),
        "total":     len(devices),
        "devices":   [
            {"ip": d.ip, "mac": d.mac, "vendor": d.vendor,
             "hostname": d.hostname, "count": d.count}
            for d in devices
        ],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    _print_ok(f"JSON saved → {path}")


def export_csv(devices: list, path: str):
    fields = ["ip", "mac", "vendor", "hostname", "count"]
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(fields)
        for d in devices:
            w.writerow([d.ip, d.mac, d.vendor, d.hostname, d.count])
    _print_ok(f"CSV saved → {path}")

# =============================================================================
# CURSES TUI  (mirrors screen.c — interactive terminal UI)
# =============================================================================

_tui_smode      = SMODE_HOST
_tui_scroll     = 0
_tui_oldmode    = SMODE_HOST
_current_net    = ["Starting."]   # mutable ref updated by injection thread
_scan_finished  = [False]

_COLOR_HEADER  = 1
_COLOR_TITLE   = 2
_COLOR_KNOWN   = 3
_COLOR_NORMAL  = 4
_COLOR_DIM     = 5


def _init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(_COLOR_HEADER, curses.COLOR_CYAN,    -1)
    curses.init_pair(_COLOR_TITLE,  curses.COLOR_MAGENTA, -1)
    curses.init_pair(_COLOR_KNOWN,  curses.COLOR_GREEN,   -1)
    curses.init_pair(_COLOR_NORMAL, -1,                   -1)
    curses.init_pair(_COLOR_DIM,    curses.COLOR_WHITE,   -1)


def _current_data() -> DataLayer:
    if _tui_smode == SMODE_REPLY:
        return data_reply
    if _tui_smode == SMODE_REQUEST:
        return data_request
    return data_unique


def _smode_name() -> str:
    return {
        SMODE_REPLY:   "ARP Reply",
        SMODE_REQUEST: "ARP Request",
        SMODE_HELP:    "Help",
        SMODE_HOST:    "Unique Hosts",
    }.get(_tui_smode, "?")


def _draw_status_header(win, rows, cols):
    status = f" Currently scanning: {_current_net[0]}   |   Screen View: {_smode_name()}"
    win.addnstr(0, 0, status.ljust(cols - 1),
                cols - 1, curses.color_pair(_COLOR_TITLE) | curses.A_BOLD)
    win.addnstr(1, 0, " " * (cols - 1), cols - 1)


def _draw_reply_header(win, row, cols):
    layer = data_reply
    summary = (f" {layer.packets} Captured ARP Reply packets, "
               f"from {layer.hosts_count()} hosts.   "
               f"Total size: {layer.total_length}")
    win.addnstr(row,     0, summary.ljust(cols - 1),
                cols - 1, curses.color_pair(_COLOR_HEADER))
    win.addnstr(row + 1, 0,
                " _____________________________________________________________________________"[:cols - 1],
                cols - 1, curses.color_pair(_COLOR_DIM))
    win.addnstr(row + 2, 0,
                "   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      "[:cols - 1],
                cols - 1, curses.color_pair(_COLOR_HEADER) | curses.A_BOLD)
    win.addnstr(row + 3, 0,
                " -----------------------------------------------------------------------------"[:cols - 1],
                cols - 1, curses.color_pair(_COLOR_DIM))
    return row + 4


def _draw_request_header(win, row, cols):
    layer = data_request
    summary = (f" {layer.packets} Captured ARP Request packets, "
               f"from {layer.hosts_count()} hosts.   "
               f"Total size: {layer.total_length}")
    win.addnstr(row,     0, summary.ljust(cols - 1),
                cols - 1, curses.color_pair(_COLOR_HEADER))
    win.addnstr(row + 1, 0,
                " _____________________________________________________________________________"[:cols - 1],
                cols - 1, curses.color_pair(_COLOR_DIM))
    win.addnstr(row + 2, 0,
                "   IP            At MAC Address      Requests IP      Count                   "[:cols - 1],
                cols - 1, curses.color_pair(_COLOR_HEADER) | curses.A_BOLD)
    win.addnstr(row + 3, 0,
                " -----------------------------------------------------------------------------"[:cols - 1],
                cols - 1, curses.color_pair(_COLOR_DIM))
    return row + 4


def _draw_unique_header(win, row, cols):
    layer = data_unique
    summary = (f" {layer.packets} Captured ARP Req/Rep packets, "
               f"from {layer.hosts_count()} hosts.   "
               f"Total size: {layer.total_length}")
    win.addnstr(row,     0, summary.ljust(cols - 1),
                cols - 1, curses.color_pair(_COLOR_HEADER))
    win.addnstr(row + 1, 0,
                " _____________________________________________________________________________"[:cols - 1],
                cols - 1, curses.color_pair(_COLOR_DIM))
    win.addnstr(row + 2, 0,
                "   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      "[:cols - 1],
                cols - 1, curses.color_pair(_COLOR_HEADER) | curses.A_BOLD)
    win.addnstr(row + 3, 0,
                " -----------------------------------------------------------------------------"[:cols - 1],
                cols - 1, curses.color_pair(_COLOR_DIM))
    return row + 4


def _fmt_reply_line(e: DataRegistry, cols: int) -> str:
    line = (f" {e.ip:<15} {e.mac:<18} {e.count:>5} {e.tlength:>7}  {e.vendor}")
    return line[:cols - 1].ljust(cols - 1)


def _fmt_request_line(e: DataRegistry, cols: int) -> str:
    line = (f" {e.ip:<15} {e.mac:<18}  {e.hostname or e.ip:<16} {e.count:>5}")
    return line[:cols - 1].ljust(cols - 1)


def _fmt_unique_line(e: DataRegistry, cols: int) -> str:
    line = (f" {e.ip:<15} {e.mac:<18} {e.count:>5} {e.tlength:>7}  {e.vendor}")
    return line[:cols - 1].ljust(cols - 1)


def _draw_help(win, start_row, rows, cols):
    help_lines = [
        "",
        "   ______________________________________________  ",
        "  |                                              | ",
        "  |    Usage Keys                                | ",
        "  |     h: show this help screen                 | ",
        "  |     j: scroll down  (or down arrow)          | ",
        "  |     k: scroll up    (or up arrow)            | ",
        "  |     .: scroll page down                      | ",
        "  |     ,: scroll page up                        | ",
        "  |     q: exit this screen or end               | ",
        "  |                                              | ",
        "  |    Screen views                              | ",
        "  |     a: show arp replies list                 | ",
        "  |     r: show arp requests list                | ",
        "  |     u: show unique hosts detected            | ",
        "  |                                              | ",
        "   ----------------------------------------------  ",
        "",
    ]
    for i, line in enumerate(help_lines):
        r = start_row + i
        if r >= rows - 1:
            break
        win.addnstr(r, 0, line[:cols - 1].ljust(cols - 1),
                    cols - 1, curses.color_pair(_COLOR_DIM))


def tui_draw(win):
    global _tui_scroll
    win.erase()
    rows, cols = win.getmaxyx()

    _draw_status_header(win, rows, cols)

    if _tui_smode == SMODE_REPLY:
        data_row = _draw_reply_header(win, 2, cols)
        entries  = data_reply.snapshot()
        fmt_fn   = _fmt_reply_line
    elif _tui_smode == SMODE_REQUEST:
        data_row = _draw_request_header(win, 2, cols)
        entries  = data_request.snapshot()
        fmt_fn   = _fmt_request_line
    elif _tui_smode == SMODE_HELP:
        data_row = _draw_unique_header(win, 2, cols)
        _draw_help(win, data_row, rows, cols)
        win.noutrefresh()
        curses.doupdate()
        return
    else:  # SMODE_HOST
        data_row = _draw_unique_header(win, 2, cols)
        entries  = data_unique.snapshot()
        fmt_fn   = _fmt_unique_line

    # Clamp scroll
    max_scroll = max(0, len(entries) - (rows - data_row - 1))
    _tui_scroll = max(0, min(_tui_scroll, max_scroll))

    visible = entries[_tui_scroll:]
    for i, entry in enumerate(visible):
        r = data_row + i
        if r >= rows - 1:
            break
        line = fmt_fn(entry, cols)
        attr = (curses.color_pair(_COLOR_KNOWN) | curses.A_BOLD
                if entry.focused
                else curses.color_pair(_COLOR_NORMAL))
        win.addnstr(r, 0, line, cols - 1, attr)

    win.noutrefresh()
    curses.doupdate()


def tui_read_key(win) -> str:
    """Read one keypress, return action string."""
    try:
        ch = win.getch()
    except Exception:
        return ""
    if ch == 27:            # ESC sequence (arrow keys)
        win.nodelay(True)
        ch2 = win.getch()
        win.nodelay(False)
        if ch2 == 91:
            ch3 = win.getch()
            if ch3 == 66:
                return "down"
            if ch3 == 65:
                return "up"
        return ""
    mapping = {
        ord("k"): "up",    ord("j"): "down",
        ord(","): "pgup",  ord("."): "pgdn",
        ord("r"): "req",   ord("a"): "rep",
        ord("u"): "host",  ord("h"): "help",
        ord("q"): "quit",
        curses.KEY_UP:   "up",
        curses.KEY_DOWN: "down",
    }
    return mapping.get(ch, "")


def run_tui(stdscr, stop_event: threading.Event):
    global _tui_smode, _tui_scroll, _tui_oldmode

    curses.curs_set(0)
    stdscr.nodelay(False)
    stdscr.timeout(1000)   # 1s refresh
    _init_colors()

    while not stop_event.is_set():
        tui_draw(stdscr)
        action = tui_read_key(stdscr)
        rows, _ = stdscr.getmaxyx()
        page    = max(1, rows - 7)

        if action == "up":
            if _tui_scroll > 0:
                _tui_scroll -= 1
        elif action == "down":
            _tui_scroll += 1
        elif action == "pgup":
            _tui_scroll = max(0, _tui_scroll - page)
        elif action == "pgdn":
            _tui_scroll += page
        elif action == "req":
            _tui_smode  = SMODE_REQUEST
            _tui_scroll = 0
        elif action == "rep":
            _tui_smode  = SMODE_REPLY
            _tui_scroll = 0
        elif action == "host":
            _tui_smode  = SMODE_HOST
            _tui_scroll = 0
        elif action == "help":
            if _tui_smode != SMODE_HELP:
                _tui_oldmode = _tui_smode
                _tui_smode   = SMODE_HELP
                _tui_scroll  = 0
        elif action == "quit":
            if _tui_smode == SMODE_HELP:
                _tui_smode  = _tui_oldmode
                _tui_scroll = 0
            else:
                stop_event.set()
                break

# =============================================================================
# RICH TABLE OUTPUT  (NetRecon feature — used in parsable/non-TUI mode)
# =============================================================================

def _print_err(msg):
    if HAS_RICH:
        console.print(f"[bold red][!][/bold red] {msg}")
    else:
        print(f"{C['red']}[!]{C['reset']} {msg}")


def _print_ok(msg):
    if HAS_RICH:
        console.print(f"[bold green][✓][/bold green] {msg}")
    else:
        print(f"{C['green']}[✓]{C['reset']} {msg}")


def _vprint(verbose, msg):
    if not verbose:
        return
    if HAS_RICH:
        console.print(f"[dim]{msg}[/dim]")
    else:
        print(f"{C['dim']}{msg}{C['reset']}")


def print_banner():
    banner = f"""
[bold purple]
  ███╗   ██╗███████╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██╔██╗ ██║█████╗     ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║ ╚████║███████╗   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝[/bold purple]
[dim purple]            Local Network Recon  •  v{VERSION}  •  Hack.The.Planet[/dim purple]
"""
    if HAS_RICH:
        console.print(banner)
    else:
        print(f"{C['purple']}[NETRECON v{VERSION}]{C['reset']} Local Network Recon")


def print_local_info(ifaces, gateway):
    if HAS_RICH:
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        t.add_column(style="dim purple")
        t.add_column(style="cyan")
        for (iface, ip, nm, mac) in ifaces:
            cidr = iface_to_cidr(ip, nm)
            t.add_row("Interface",
                      f"[bold]{iface}[/bold]  IP: {ip}  CIDR: {cidr}  MAC: {mac}")
        if gateway:
            t.add_row("Gateway", f"[bold]{gateway}[/bold]")
        console.print(Panel(t, title="[bold purple]Local Network[/bold purple]",
                            border_style="purple", padding=(0, 1)))
    else:
        for (iface, ip, nm, mac) in ifaces:
            cidr = iface_to_cidr(ip, nm)
            print(f"{C['purple']}Interface:{C['reset']} {iface}  "
                  f"IP: {ip}  CIDR: {cidr}  MAC: {mac}")
        if gateway:
            print(f"{C['purple']}Gateway:{C['reset']} {gateway}")


def build_rich_table(entries: list, do_ports=False) -> "Table":
    t = Table(
        title=f"[bold purple]Discovered Devices — "
              f"{datetime.now().strftime('%H:%M:%S')}[/bold purple]",
        box=box.HEAVY_HEAD, border_style="purple",
        header_style="bold magenta", show_lines=True, padding=(0, 1),
    )
    t.add_column("#",           style="dim",       width=4,  justify="right")
    t.add_column("IP Address",  style="bold cyan", width=16)
    t.add_column("MAC Address", style="yellow",    width=19)
    t.add_column("Vendor",      style="green",     width=24)
    t.add_column("Hostname",    style="white",     width=26)
    t.add_column("Count",       style="dim",       width=6,  justify="right")
    if do_ports:
        t.add_column("Open Ports", style="red",    width=28)
    for idx, e in enumerate(entries, 1):
        row = [str(idx), e.ip, e.mac,
               e.vendor or "Unknown vendor",
               e.hostname or "—",
               str(e.count)]
        if do_ports:
            ports = tcp_scan_host(e.ip)
            row.append(", ".join(map(str, ports)) or "—")
        t.add_row(*row)
    return t


def print_rich_results(entries: list, do_ports=False):
    if not entries:
        _print_err("No devices found.")
        return
    if HAS_RICH:
        console.print(build_rich_table(entries, do_ports))
        console.print(
            f"[dim purple]  Total: [bold]{len(entries)}[/bold] "
            f"device(s) found[/dim purple]\n")
    else:
        print(f"\n{'#':>3}  {'IP':<16}  {'MAC':<18}  {'Vendor':<24}  Hostname")
        print("-" * 80)
        for i, e in enumerate(entries, 1):
            print(f"{i:>3}  {e.ip:<16}  {e.mac:<18}  "
                  f"{e.vendor:<24}  {e.hostname}")
        print(f"\nTotal: {len(entries)} device(s)")

# =============================================================================
# LIVE MONITOR  (NetRecon feature)
# =============================================================================

def live_monitor(cidr: str, iface: str, interval: int, do_ports: bool):
    if HAS_RICH:
        console.print(
            f"\n[bold purple][~][/bold purple] Live monitor  "
            f"(interval={interval}s) — Ctrl+C to stop\n")
    else:
        print(f"[~] Live monitor — {interval}s interval. Ctrl+C to stop.")

    known: dict = {}
    try:
        while True:
            fast_arp_scan(cidr, iface)
            current = {e.ip: e for e in data_unique.snapshot()}

            for ip, dev in current.items():
                if ip not in known:
                    ts = datetime.now().strftime("%H:%M:%S")
                    ports_str = ""
                    if do_ports:
                        p = tcp_scan_host(ip)
                        ports_str = f"  ports: {p}" if p else ""
                    if HAS_RICH:
                        console.print(
                            f"[bold green][+][/bold green] [{ts}] NEW   "
                            f"{ip:<16}  {dev.mac}  {dev.vendor}{ports_str}")
                    else:
                        print(f"[+] [{ts}] NEW   {ip}  {dev.mac}{ports_str}")
                    known[ip] = dev

            for ip in list(known):
                if ip not in current:
                    ts = datetime.now().strftime("%H:%M:%S")
                    if HAS_RICH:
                        console.print(
                            f"[bold red][-][/bold red] [{ts}] LEFT  "
                            f"{ip:<16}  {known[ip].mac}  {known[ip].vendor}")
                    else:
                        print(f"[-] [{ts}] LEFT  {ip}  {known[ip].mac}")
                    del known[ip]

            data_unique.clear()
            data_reply.clear()
            data_request.clear()
            time.sleep(interval)
    except KeyboardInterrupt:
        if HAS_RICH:
            console.print("\n[dim purple]Live monitor stopped.[/dim purple]")

# =============================================================================
# CLI ARGUMENT PARSER
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netrecon",
        description=f"NetRecon v{VERSION} — Autonomous local network scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 netrecon.py                          # auto-scan + TUI
  sudo python3 netrecon.py -r 192.168.1.0/24        # specific range + TUI
  sudo python3 netrecon.py -p                        # passive mode + TUI
  sudo python3 netrecon.py -r 192.168.1.0/24 -P     # parsable output
  sudo python3 netrecon.py -L                        # parsable + keep listening
  sudo python3 netrecon.py --live                    # live monitor (rich)
  sudo python3 netrecon.py --ports --json out.json   # port scan + export
  sudo python3 netrecon.py -f                        # fast mode
  sudo python3 netrecon.py -m known_hosts.txt        # highlight known MACs
        """
    )
    # netdiscover-compatible flags
    p.add_argument("-i", "--iface",    metavar="IFACE",
                   help="Network interface (auto-detect if not set)")
    p.add_argument("-r", "--range",    metavar="CIDR",
                   help="Scan a specific CIDR range")
    p.add_argument("-l", "--list",     metavar="FILE",
                   help="File with CIDRs to scan (one per line)")
    p.add_argument("-p", "--passive",  action="store_true",
                   help="Passive mode — sniff only, no injection")
    p.add_argument("-m", "--macs",     metavar="FILE",
                   help="Known MACs file for host labeling")
    p.add_argument("-F", "--filter",   default="arp", metavar="EXPR",
                   help="Custom pcap filter (default: 'arp')")
    p.add_argument("-f", "--fast",     action="store_true",
                   help="Fast mode — probe only common last octets")
    p.add_argument("-c", "--count",    type=int, default=1, metavar="N",
                   help="Repeat each ARP request N times (default: 1)")
    p.add_argument("-s", "--sleep",    type=int, default=0, metavar="MS",
                   help="Sleep between ARP requests in ms")
    p.add_argument("-S", "--suppress", action="store_true",
                   help="Suppress per-packet sleep (hardcore mode)")
    p.add_argument("-n", "--node",     type=int, default=67, metavar="OCTET",
                   help="Source IP last octet (2-253, default: 67)")
    p.add_argument("-P", "--parsable", action="store_true",
                   help="Parsable output, stop after active scan")
    p.add_argument("-L", "--listen",   action="store_true",
                   help="Parsable output, keep listening after scan")
    p.add_argument("-N", "--no-header",action="store_true",
                   help="No header in parsable output")
    p.add_argument("-R", "--no-root",  action="store_true",
                   help="Skip root check")
    # NetRecon extras
    p.add_argument("--live",     action="store_true",
                   help="Live monitor — detect devices joining/leaving")
    p.add_argument("--interval", type=int, default=15, metavar="SEC",
                   help="Live mode rescan interval (default: 15s)")
    p.add_argument("--ports",    action="store_true",
                   help="TCP port scan on discovered hosts")
    p.add_argument("--json",     metavar="FILE", help="Export to JSON")
    p.add_argument("--csv",      metavar="FILE", help="Export to CSV")
    p.add_argument("--verbose",  action="store_true", help="Verbose output")
    p.add_argument("--timeout",  type=float, default=2.0, metavar="SEC",
                   help="ARP scan timeout (default: 2.0s)")
    return p

# =============================================================================
# MAIN
# =============================================================================

def check_root(skip=False):
    if skip:
        return
    if os.geteuid() != 0:
        _print_err("netrecon requires root. Run: sudo python3 netrecon.py")
        sys.exit(1)


def check_deps():
    if MISSING:
        for dep in MISSING:
            _print_err(f"Missing: {dep}  →  pip install {dep}")
        if not HAS_SCAPY:
            _print_err("Scapy is required for ARP scanning.")
            sys.exit(1)


def main():
    global _parsable_output, _continue_listening, _no_header

    parser = build_parser()
    args   = parser.parse_args()

    _parsable_output    = args.parsable or args.listen
    _continue_listening = args.listen
    _no_header          = args.no_header

    if not _parsable_output:
        print_banner()

    check_root(skip=args.no_root)
    check_deps()

    # Load known MACs
    if args.macs:
        if not load_known_mac_table(args.macs):
            _print_err(f"Cannot read MACs file: {args.macs}")

    # Resolve interface
    if args.iface:
        chosen = resolve_forced_iface(args.iface)
    else:
        chosen = detect_active_interface()
        if not chosen:
            _print_err("Could not auto-detect interface. Use: -i eth0")
            sys.exit(1)

    iface_name, ip, nm, mac = chosen
    cidr    = iface_to_cidr(ip, nm)
    gateway = detect_gateway()

    inject_init(iface_name)

    if not _parsable_output:
        print_local_info([chosen], gateway)

    # Parsable header
    if _parsable_output and not _no_header:
        print_parsable_header()

    stop_event = threading.Event()

    # ── Signal handler ────────────────────────────────────────────────────────
    def _sigint(sig, frame):
        stop_event.set()
    signal.signal(signal.SIGINT, _sigint)

    # ── Determine ranges to scan ──────────────────────────────────────────────
    if args.list:
        try:
            with open(args.list) as f:
                scan_ranges = [l.strip() for l in f if l.strip()]
        except Exception:
            _print_err(f"Cannot read list file: {args.list}")
            sys.exit(1)
    elif args.range:
        scan_ranges = [args.range]
    elif args.passive:
        scan_ranges = []
    elif args.live:
        scan_ranges = [cidr]
    else:
        scan_ranges = COMMON_NETWORKS   # auto-scan

    # ── LIVE MONITOR MODE ─────────────────────────────────────────────────────
    if args.live:
        live_monitor(cidr, iface_name, args.interval, args.ports)
        return

    # ── PASSIVE MODE ──────────────────────────────────────────────────────────
    if args.passive:
        _current_net[0] = "(passive)"
        if _parsable_output:
            # Just sniff and print — no TUI
            sniff_t = threading.Thread(
                target=start_sniffer,
                args=(iface_name, args.filter, stop_event),
                daemon=True)
            sniff_t.start()
            try:
                sniff_t.join()
            except KeyboardInterrupt:
                stop_event.set()
        else:
            # TUI + passive sniff
            sniff_t = threading.Thread(
                target=start_sniffer,
                args=(iface_name, args.filter, stop_event),
                daemon=True)
            sniff_t.start()
            try:
                curses.wrapper(run_tui, stop_event)
            finally:
                stop_event.set()
        entries = data_unique.snapshot()
        if not _parsable_output:
            print_rich_results(entries, args.ports)
        _finalize(entries, args, stop_event)
        return

    # ── ACTIVE MODE ───────────────────────────────────────────────────────────
    # Start sniffer thread first (always running)
    sniff_t = threading.Thread(
        target=start_sniffer,
        args=(iface_name, args.filter, stop_event),
        daemon=True)
    sniff_t.start()

    # Injection thread
    def _inject_thread():
        time.sleep(2)   # let sniffer settle
        for r in scan_ranges:
            if stop_event.is_set():
                break
            _vprint(args.verbose, f"[*] Injecting: {r}")
            inject_range(
                cidr          = r,
                iface         = iface_name,
                src_node      = args.node,
                repeat        = args.count,
                sleep_ms      = args.sleep,
                suppress_sleep= args.suppress,
                fast_mode     = args.fast,
                stop_event    = stop_event,
                current_network_ref = _current_net,
            )
        time.sleep(2)
        _current_net[0] = "Finished!"
        _scan_finished[0] = True

        if _parsable_output:
            entries = data_unique.snapshot()
            print(f"\n-- Active scan completed, {len(entries)} Hosts found.")
            if not _continue_listening:
                stop_event.set()
            else:
                print(" Continuing to listen passively.\n")

    inject_t = threading.Thread(target=_inject_thread, daemon=True)
    inject_t.start()

    if _parsable_output:
        # No TUI — wait for injection to finish
        try:
            inject_t.join()
            if _continue_listening:
                sniff_t.join()
        except KeyboardInterrupt:
            stop_event.set()
    else:
        # Launch TUI
        try:
            curses.wrapper(run_tui, stop_event)
        finally:
            stop_event.set()

    inject_t.join(timeout=3)

    entries = data_unique.snapshot()
    if not _parsable_output:
        print_rich_results(entries, args.ports)

    _finalize(entries, args, stop_event)


def _finalize(entries: list, args, stop_event: threading.Event):
    """Export and cleanup after scan."""
    if args.json:
        export_json(entries, args.json)
    if args.csv:
        export_csv(entries, args.csv)


if __name__ == "__main__":
    main()
