#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════╗
║              N E T R E C O N  v1.0                    ║
║         Autonomous Local Network Scanner              ║
║         github.com/xploitoverload  |  Hack.The.Planet ║
╚═══════════════════════════════════════════════════════╝

ARP-based network discovery tool.
Zero config — auto-detects interface, subnet, and gateway.
"""

import sys
import os
import json
import csv
import time
import socket
import struct
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
        ARP, Ether, srp, conf as scapy_conf,
        get_if_list, get_if_hwaddr, get_if_addr,
    )
    from scapy.layers.inet import IP, TCP
    from scapy.sendrecv import sr1
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
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.text import Text
    from rich.live import Live
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    MISSING.append("rich")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ── Console ───────────────────────────────────────────────────────────────────
console = Console(highlight=False) if HAS_RICH else None

C = {
    "purple": "\033[95m", "cyan": "\033[96m", "green": "\033[92m",
    "yellow": "\033[93m", "red": "\033[91m", "bold": "\033[1m",
    "dim": "\033[2m", "reset": "\033[0m",
}

OUI_TABLE = {
    "00:50:56": "VMware",         "00:0C:29": "VMware",
    "00:1A:11": "Google",         "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",   "E4:5F:01": "Raspberry Pi",
    "00:1B:21": "Intel",          "8C:8D:28": "Intel",
    "00:25:96": "Cisco",          "00:1E:13": "Cisco",
    "FC:FB:FB": "Cisco",          "00:0D:3A": "Microsoft",
    "00:15:5D": "Microsoft (Hyper-V)", "00:50:F2": "Microsoft",
    "AC:BC:32": "Apple",          "00:1C:B3": "Apple",
    "98:01:A7": "Apple",          "3C:15:C2": "Apple",
    "00:1A:73": "Apple",          "18:65:90": "Apple",
    "60:67:20": "Apple",          "A4:5E:60": "Apple",
    "00:16:CB": "Apple",          "00:17:F2": "Apple",
    "78:4F:43": "Apple",          "34:AB:37": "Apple",
    "00:26:B9": "Dell",           "18:03:73": "Dell",
    "F0:1F:AF": "Dell",           "00:14:22": "Dell",
    "00:21:70": "Dell",           "00:25:64": "Apple",
    "CC:AF:78": "Huawei",         "00:E0:FC": "Huawei",
    "00:18:82": "Huawei",         "AC:CF:23": "Asus",
    "00:26:18": "Asus",           "04:D4:C4": "Asus",
    "00:11:2F": "Asus",           "B0:6E:BF": "TP-Link",
    "54:C8:0F": "TP-Link",        "50:C7:BF": "TP-Link",
    "D4:EE:07": "TP-Link",        "C4:E9:84": "TP-Link",
    "14:CF:92": "TP-Link",        "F4:F2:6D": "TP-Link",
    "00:1D:0F": "Netgear",        "20:4E:7F": "Netgear",
    "C0:FF:D4": "Netgear",        "00:14:6C": "Netgear",
    "00:1E:2A": "Netgear",        "10:0D:7F": "Netgear",
    "00:22:3F": "D-Link",         "1C:7E:E5": "D-Link",
    "78:54:2E": "D-Link",         "00:1C:F0": "D-Link",
    "00:15:E9": "D-Link",         "00:90:4B": "Gemtek",
    "00:0F:66": "Samsung",        "78:1F:DB": "Samsung",
    "8C:F5:A3": "Samsung",        "00:07:AB": "Samsung",
    "A0:10:81": "Samsung",        "5C:F3:70": "Xiaomi",
    "00:9E:C8": "Xiaomi",         "58:44:98": "Xiaomi",
    "AC:F7:F3": "Xiaomi",         "64:CC:2E": "Xiaomi",
    "00:1A:2B": "Fujitsu",        "00:26:73": "Belkin",
    "00:30:BD": "Belkin",         "94:10:3E": "Belkin",
}

#
# Strategy use the OS routing table as the authoritative source.
#   — open UDP socket to 8.8.8.8:80, read bound address.
#     Kernel fills in the correct source IP with zero
#     packets sent. Works on every Linux without root.
#  — parse `ip route get 8.8.8.8` output.
#  — iterate all interfaces, cross-ref with gateway.
#

# ── Virtual/irrelevant interface name prefixes to always ignore ───────────────
_SKIP_PREFIXES = (
    "lo", "virbr", "docker", "veth", "br-", "vmnet",
    "dummy", "tunl", "sit", "ip6tnl", "gre", "tun",
)


def _is_virtual(name: str) -> bool:
    return any(name.startswith(p) for p in _SKIP_PREFIXES)


# ── socket routing trick ────────────────────────────────────────────

def _active_ip_via_socket() -> str | None:
    """
    Open a UDP socket toward 8.8.8.8:80 without sending any packet.
    The kernel selects the source address using the routing table.
    Returns the local IP string, or None on failure.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip if ip and not ip.startswith("127.") else None
    except Exception:
        return None


# ── `ip route get` ─────────────────────────────────────────────────

def _active_ip_via_ip_route() -> tuple[str, str] | tuple[None, None]:
    """
    Run `ip route get 8.8.8.8`.
    Returns (local_ip, iface_name) or (None, None).
    Example output:
      8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.105 uid 0
    """
    try:
        out = subprocess.check_output(
            ["ip", "route", "get", "8.8.8.8"],
            text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            parts = line.split()
            ip   = parts[parts.index("src")  + 1] if "src"  in parts else None
            dev  = parts[parts.index("dev")  + 1] if "dev"  in parts else None
            if ip and dev and not ip.startswith("127."):
                return ip, dev
    except Exception:
        pass
    return None, None


# ── /proc/net/fib_trie prefix-length reader ───────────────────────────────────

def _prefix_len_from_fib_trie(target_ip: str) -> int | None:
    """
    Parse /proc/net/fib_trie to find the prefix length of the local subnet
    that contains target_ip. Returns prefix length int or None.
    """
    try:
        with open("/proc/net/fib_trie") as f:
            content = f.read()

        # Find LOCAL entries with our IP; the preceding line has the prefix
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if target_ip in line and "LOCAL" in line:
                # Walk up to find the closest prefix/len line
                for j in range(i - 1, max(i - 6, 0), -1):
                    m = lines[j].strip()
                    if "/" in m:
                        # Format: "+-- 192.168.1.0/24 ..."
                        cidr_part = m.split()[1] if len(m.split()) > 1 else m.split("/")[0] + "/" + m.split("/")[1].split()[0]
                        try:
                            prefix = int(cidr_part.split("/")[1])
                            return prefix
                        except Exception:
                            pass
    except Exception:
        pass
    return None


def _iface_details_from_ip_addr(iface: str, local_ip: str) -> tuple[str, str]:
  
    netmask = "255.255.255.0"
    mac = "??:??:??:??:??:??"
    try:
        out = subprocess.check_output(
            ["ip", "addr", "show", iface],
            text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            line = line.strip()
            # MAC line: "link/ether aa:bb:cc:dd:ee:ff brd ..."
            if line.startswith("link/ether"):
                mac = line.split()[1]
            # IP line: "inet 192.168.1.105/24 brd ..."
            if line.startswith("inet ") and local_ip in line:
                cidr_part = line.split()[1]   # e.g. "192.168.1.105/24"
                prefix = int(cidr_part.split("/")[1])
                net = ipaddress.IPv4Network(f"0.0.0.0/{prefix}")
                netmask = str(net.netmask)
    except Exception:
        pass
    return netmask, mac


def _iface_for_ip_netifaces(local_ip: str) -> str | None:
    """Find which interface name owns a given local IP, using netifaces."""
    if not HAS_NETIFACES:
        return None
    for iface in netifaces.interfaces():
        if _is_virtual(iface):
            continue
        addrs = netifaces.ifaddresses(iface)
        for entry in addrs.get(netifaces.AF_INET, []):
            if entry.get("addr") == local_ip:
                return iface
    return None


def _iface_for_ip_proc(local_ip: str) -> str | None:
    """Find which interface name owns a given local IP via `ip addr`."""
    try:
        out = subprocess.check_output(
            ["ip", "-o", "-4", "addr"],
            text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            iface = parts[1]
            if _is_virtual(iface):
                continue
            addr_cidr = parts[3]  # "192.168.1.105/24"
            if addr_cidr.split("/")[0] == local_ip:
                return iface
    except Exception:
        pass
    return None


def _full_record_netifaces(iface: str, local_ip: str) -> tuple[str, str, str, str] | None:
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


# ── Primary entry point ───────────────────────────────────────────────────────

def detect_active_interface() -> tuple[str, str, str, str] | None:

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
        iface_name = _iface_for_ip_netifaces(local_ip) or _iface_for_ip_proc(local_ip)

    if not iface_name:
        return None

    rec = _full_record_netifaces(iface_name, local_ip)
    if rec:
        return rec

    netmask, mac = _iface_details_from_ip_addr(iface_name, local_ip)
    return (iface_name, local_ip, netmask, mac)


def detect_all_interfaces() -> list[tuple[str, str, str, str]]:

    results = []
    if HAS_NETIFACES:
        for iface in netifaces.interfaces():
            if _is_virtual(iface):
                continue
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET not in addrs:
                continue
            for entry in addrs[netifaces.AF_INET]:
                ip = entry.get("addr", "")
                nm = entry.get("netmask", "255.255.255.0")
                mac = ""
                if netifaces.AF_LINK in addrs:
                    mac = addrs[netifaces.AF_LINK][0].get("addr", "??:??:??:??:??:??")
                if ip and not ip.startswith("127."):
                    results.append((iface, ip, nm, mac))
    else:
        try:
            out = subprocess.check_output(
                ["ip", "-o", "-4", "addr"], text=True, stderr=subprocess.DEVNULL
            )
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
                mac = _get_mac_from_ip_link(iface)
                if not ip.startswith("127."):
                    results.append((iface, ip, nm, mac))
        except Exception:
            pass
    return results


def _get_mac_from_ip_link(iface: str) -> str:
    try:
        out = subprocess.check_output(
            ["ip", "link", "show", iface], text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("link/ether"):
                return line.split()[1]
    except Exception:
        pass
    return "??:??:??:??:??:??"


def iface_to_cidr(ip: str, netmask: str) -> str:
    net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    return str(net)


def detect_gateway() -> str | None:
    if HAS_NETIFACES:
        try:
            gws = netifaces.gateways()
            gw = gws.get("default", {}).get(netifaces.AF_INET, [None])[0]
            if gw:
                return gw
        except Exception:
            pass
          
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass

    _, iproute_iface = _active_ip_via_ip_route()
    try:
        out = subprocess.check_output(
            ["ip", "route", "get", "8.8.8.8"],
            text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass

    return None



def lookup_vendor(mac: str) -> str:
    if not mac or mac == "??:??:??:??:??:??":
        return "Unknown"
    mac_upper = mac.upper()
    oui = mac_upper[:8]  
    if oui in OUI_TABLE:
        return OUI_TABLE[oui]

    if HAS_SCAPY:
        try:
            from scapy.data import ETHER_TYPES
            from scapy.libs.manuf import ManufDB
            db = ManufDB()
            result = db.get(mac)
            if result:
                return result[1] or result[0] or "Unknown"
        except Exception:
            pass
    return "Unknown"


def resolve_hostname(ip: str, timeout: float = 0.25) -> str:
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        hostname = socket.gethostbyaddr(ip)[0]
        socket.setdefaulttimeout(old)
        return hostname
    except Exception:
        return ""


# ═══════════════════════════════════════════════════════════════════════════════
# Speed strategy:
#   • Split subnet into chunks of 32 IPs each
#   • Scan all chunks concurrently in a thread pool
#   • Each thread runs its own srp() with a short timeout (0.8s)
#   • No inter-packet delay — kernel handles buffering fine on LAN
#   • Result dedup via IP-keyed dict (handles duplicate ARP replies)
#   • arp-scan binary fallback with --bandwidth flag for max throughput
#   • Raw socket ICMP ping last resort — single socket, no fork overhead
# ═══════════════════════════════════════════════════════════════════════════════

_ARP_CHUNK    = 32   
_ARP_TIMEOUT  = 0.8  
_ARP_WORKERS  = 16  

def _arp_chunk_worker(args_tuple):
    ip_list, iface = args_tuple
    results = []
    try:
        pkts = [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip) for ip in ip_list]
        from scapy.all import srp as _srp
        answered, _ = _srp(
            pkts,
            iface=iface,
            timeout=_ARP_TIMEOUT,
            verbose=0,
            inter=0,          
            retry=1,         
        )
        for _, rcv in answered:
            results.append((rcv[ARP].psrc, rcv[Ether].src.upper()))
    except Exception:
        pass
    return results


def arp_scan_scapy_fast(cidr: str, iface: str) -> list[dict]:
    scapy_conf.verb = 0

    net   = ipaddress.IPv4Network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()]

    chunks = [hosts[i:i + _ARP_CHUNK] for i in range(0, len(hosts), _ARP_CHUNK)]
    work   = [(chunk, iface) for chunk in chunks]

    seen: dict[str, str] = {}  
    try:
        with ThreadPoolExecutor(max_workers=_ARP_WORKERS) as ex:
            for batch_result in ex.map(_arp_chunk_worker, work):
                for ip, mac in batch_result:
                    seen[ip] = mac
    except PermissionError:
        print_err("Root privileges required. Run with sudo.")
        sys.exit(1)
    except Exception as e:
        _vprint(True, f"[!] Scapy parallel scan error: {e}")
        return []

    return [{"ip": ip, "mac": mac, "vendor": "", "hostname": ""}
            for ip, mac in seen.items()]


def arp_scan_binary(cidr: str, iface: str) -> list[dict]:
    try:
        cmd = [
            "arp-scan",
            f"--interface={iface}",
            "--retry=2",
            "--timeout=400",          
            "--bandwidth=1000000",    
            cidr,
        ]
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        return []
    except subprocess.CalledProcessError:
        return []

    devices = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] and parts[0][0].isdigit():
            ip  = parts[0].strip()
            mac = parts[1].strip().upper()
            devices.append({"ip": ip, "mac": mac, "vendor": "", "hostname": ""})
    return devices


def _build_icmp(seq: int) -> bytes:
    header = struct.pack("bbHHh", 8, 0, 0, os.getpid() & 0xFFFF, seq)
    checksum = 0
    for i in range(0, len(header), 2):
        checksum += (header[i] << 8) + header[i + 1]
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    header = struct.pack("bbHHh", 8, 0, socket.htons(checksum), os.getpid() & 0xFFFF, seq)
    return header


def _ping_raw(ip: str, timeout: float = 0.4) -> bool:
    """
    Send one ICMP echo request via raw socket and wait for reply.
    No subprocess fork — dramatically faster at scale.
    Returns True if host responds.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(timeout)
        s.sendto(_build_icmp(1), (ip, 0))
        s.recvfrom(1024)
        s.close()
        return True
    except Exception:
        return False


def _mac_from_arp_cache(ip: str) -> str:
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if parts and parts[0] == ip and parts[2] == "0x2":
                    return parts[3].upper()
    except Exception:
        pass
    return "N/A"


def ping_sweep_fast(cidr: str) -> list[dict]:
    net   = ipaddress.IPv4Network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()]

    alive: list[str] = []

    with ThreadPoolExecutor(max_workers=min(256, len(hosts))) as ex:
        futures = {ex.submit(_ping_raw, ip): ip for ip in hosts}
        for f in as_completed(futures):
            ip = futures[f]
            try:
                if f.result():
                    alive.append(ip)
            except Exception:
                pass

    # Brief pause to let ARP cache populate
    time.sleep(0.3)

    devices = []
    for ip in alive:
        mac = _mac_from_arp_cache(ip)
        devices.append({"ip": ip, "mac": mac, "vendor": "", "hostname": ""})
    return devices


def scan_network(cidr: str, iface: str, verbose: bool = False) -> list[dict]:
  
    net = ipaddress.IPv4Network(cidr, strict=False)
    _vprint(verbose, f"[*] Subnet: {cidr}  ({net.num_addresses - 2} hosts to scan)")

    if HAS_SCAPY:
        _vprint(verbose, f"[*] Method: Scapy parallel ARP  (iface={iface})")
        devices = arp_scan_scapy_fast(cidr, iface)
        if devices:
            _vprint(verbose, f"[*] Scapy found {len(devices)} device(s)")
            return devices
        _vprint(verbose, "[~] Scapy ARP returned 0 results, trying arp-scan binary...")

    _vprint(verbose, "[*] Method: arp-scan binary")
    devices = arp_scan_binary(cidr, iface)
    if devices:
        _vprint(verbose, f"[*] arp-scan found {len(devices)} device(s)")
        return devices
    _vprint(verbose, "[~] arp-scan not available or found nothing, falling back to ping sweep...")

    _vprint(verbose, "[*] Method: Raw ICMP ping sweep (MAC from ARP cache)")
    devices = ping_sweep_fast(cidr)
    _vprint(verbose, f"[*] Ping sweep found {len(devices)} device(s)")
    return devices


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                443, 445, 3306, 3389, 5900, 8080, 8443, 9100]

def tcp_scan_host(ip: str, ports: list[int] = COMMON_PORTS, timeout: float = 0.5) -> list[int]:
    open_ports = []
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
        for res in ex.map(check, ports):
            if res:
                open_ports.append(res)
    return sorted(open_ports)


def enrich_device(dev: dict, do_ports: bool = False) -> dict:
    dev["vendor"]   = lookup_vendor(dev["mac"])
    dev["hostname"] = resolve_hostname(dev["ip"])
    if do_ports:
        dev["ports"] = tcp_scan_host(dev["ip"])
    return dev


def enrich_all(devices: list[dict], do_ports: bool = False) -> list[dict]:
    if not devices:
        return []
    workers = min(64, len(devices))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(enrich_device, dev, do_ports): dev for dev in devices}
        enriched = []
        for f in as_completed(futures):
            enriched.append(f.result())
    enriched.sort(key=lambda d: int(ipaddress.IPv4Address(d["ip"])))
    return enriched


BANNER = r"""
  [bold purple]
  ███╗   ██╗███████╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██╔██╗ ██║█████╗     ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║ ╚████║███████╗   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝[/bold purple]
  [dim purple]          Local Network Recon  •  v1.0  •  Hack.The.Planet[/dim purple]
"""


def print_banner():
    if HAS_RICH:
        console.print(BANNER)
    else:
        print(f"{C['purple']}[NETRECON v1.0]{C['reset']} Local Network Recon")


def print_err(msg):
    if HAS_RICH:
        console.print(f"[bold red][!][/bold red] {msg}")
    else:
        print(f"{C['red']}[!]{C['reset']} {msg}")


def _vprint(verbose, msg):
    if not verbose:
        return
    if HAS_RICH:
        console.print(f"[dim]{msg}[/dim]")
    else:
        print(f"{C['dim']}{msg}{C['reset']}")


def print_local_info(ifaces, gateway):
    if HAS_RICH:
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        t.add_column(style="dim purple")
        t.add_column(style="cyan")
        for (iface, ip, nm, mac) in ifaces:
            cidr = iface_to_cidr(ip, nm)
            t.add_row("Interface", f"[bold]{iface}[/bold]  IP: {ip}  CIDR: {cidr}  MAC: {mac}")
        if gateway:
            t.add_row("Gateway", f"[bold]{gateway}[/bold]")
        console.print(Panel(t, title="[bold purple]Local Network[/bold purple]",
                            border_style="purple", padding=(0, 1)))
    else:
        for (iface, ip, nm, mac) in ifaces:
            cidr = iface_to_cidr(ip, nm)
            print(f"{C['purple']}Interface:{C['reset']} {iface}  IP: {ip}  CIDR: {cidr}  MAC: {mac}")
        if gateway:
            print(f"{C['purple']}Gateway:{C['reset']} {gateway}")


def build_table(devices: list[dict], do_ports: bool = False) -> "Table":
    t = Table(
        title=f"[bold purple]Discovered Devices — {datetime.now().strftime('%H:%M:%S')}[/bold purple]",
        box=box.HEAVY_HEAD,
        border_style="purple",
        header_style="bold magenta",
        show_lines=True,
        padding=(0, 1),
    )
    t.add_column("#",        style="dim",          width=4, justify="right")
    t.add_column("IP Address", style="bold cyan",  width=16)
    t.add_column("MAC Address", style="yellow",    width=19)
    t.add_column("Vendor",    style="green",        width=22)
    t.add_column("Hostname",  style="white",        width=28)
    if do_ports:
        t.add_column("Open Ports", style="red",    width=30)

    for idx, dev in enumerate(devices, 1):
        ports_str = ", ".join(map(str, dev.get("ports", []))) or "—"
        row = [
            str(idx),
            dev["ip"],
            dev["mac"],
            dev.get("vendor", "Unknown") or "Unknown",
            dev.get("hostname", "") or "—",
        ]
        if do_ports:
            row.append(ports_str)
        t.add_row(*row)
    return t


def print_results(devices: list[dict], do_ports: bool = False):
    if not devices:
        if HAS_RICH:
            console.print("[bold red][!] No devices found.[/bold red]")
        else:
            print(f"{C['red']}[!] No devices found.{C['reset']}")
        return
    if HAS_RICH:
        console.print(build_table(devices, do_ports))
        console.print(f"[dim purple]  Total: [bold]{len(devices)}[/bold] device(s) found[/dim purple]\n")
    else:
        # Plain fallback
        header = f"{'#':>3}  {'IP':<16}  {'MAC':<18}  {'Vendor':<22}  {'Hostname'}"
        print(f"{C['purple']}{header}{C['reset']}")
        print("-" * 80)
        for i, dev in enumerate(devices, 1):
            print(f"{i:>3}  {dev['ip']:<16}  {dev['mac']:<18}  "
                  f"{dev.get('vendor','?'):<22}  {dev.get('hostname','')}")
        print(f"\nTotal: {len(devices)} device(s)")


def export_json(devices: list[dict], path: str):
    data = {
        "scan_time": datetime.now().isoformat(),
        "total": len(devices),
        "devices": devices,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    _print_ok(f"JSON saved → {path}")


def export_csv(devices: list[dict], path: str):
    fields = ["ip", "mac", "vendor", "hostname"]
    if devices and "ports" in devices[0]:
        fields.append("ports")
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for dev in devices:
            row = dict(dev)
            if "ports" in row:
                row["ports"] = ",".join(map(str, row["ports"]))
            w.writerow(row)
    _print_ok(f"CSV saved → {path}")


def _print_ok(msg):
    if HAS_RICH:
        console.print(f"[bold green][✓][/bold green] {msg}")
    else:
        print(f"{C['green']}[✓]{C['reset']} {msg}")

def live_monitor(cidr: str, iface: str, interval: int = 15, do_ports: bool = False):
  
    if HAS_RICH:
        console.print(f"\n[bold purple][~][/bold purple] Live monitor started  "
                      f"(interval={interval}s)  — Ctrl+C to stop\n")
    else:
        print(f"[~] Live monitor — interval {interval}s. Ctrl+C to stop.")

    known: dict[str, dict] = {}  # ip → device

    try:
        while True:
            raw = scan_network(cidr, iface)
            enriched = enrich_all(raw, do_ports)
            current_ips = {d["ip"] for d in enriched}

            for dev in enriched:
                ip = dev["ip"]
                if ip not in known:
                    ts = datetime.now().strftime("%H:%M:%S")
                    if HAS_RICH:
                        console.print(f"[bold green][+][/bold green] [{ts}] NEW   "
                                      f"{ip:<16}  {dev['mac']}  {dev.get('vendor','?')}")
                    else:
                        print(f"[+] [{ts}] NEW   {ip}  {dev['mac']}")
                    known[ip] = dev

            for ip in list(known.keys()):
                if ip not in current_ips:
                    ts = datetime.now().strftime("%H:%M:%S")
                    if HAS_RICH:
                        console.print(f"[bold red][-][/bold red] [{ts}] LEFT  {ip:<16}  "
                                      f"{known[ip]['mac']}  {known[ip].get('vendor','?')}")
                    else:
                        print(f"[-] [{ts}] LEFT  {ip}  {known[ip]['mac']}")
                    del known[ip]

            time.sleep(interval)
    except KeyboardInterrupt:
        if HAS_RICH:
            console.print("\n[dim purple]Live monitor stopped.[/dim purple]")

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netrecon",
        description="Autonomous local network scanner — zero config ARP discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 netrecon.py
  sudo python3 netrecon.py --live
  sudo python3 netrecon.py --ports --json results.json
  sudo python3 netrecon.py --csv scan.csv --verbose
        """
    )
    p.add_argument("--live",    action="store_true", help="Live monitor mode (detect join/leave)")
    p.add_argument("--interval",type=int, default=15, metavar="SEC",
                   help="Live mode rescan interval (default: 15s)")
    p.add_argument("--json",    metavar="FILE", help="Export results to JSON file")
    p.add_argument("--csv",     metavar="FILE", help="Export results to CSV file")
    p.add_argument("--ports",   action="store_true", help="Enable port scan on discovered hosts")
    p.add_argument("--verbose", action="store_true", help="Show debug/verbose output")
    p.add_argument("--timeout", type=float, default=2.0, metavar="SEC",
                   help="ARP scan timeout (default: 2.0s)")
    p.add_argument("--iface",   metavar="IFACE", help="Force specific interface (auto-detect by default)")
    return p


def check_root():
    if os.geteuid() != 0:
        print_err("netrecon requires root privileges. Run: sudo python3 netrecon.py")
        sys.exit(1)


def check_deps():
    if MISSING:
        for dep in MISSING:
            print_err(f"Missing dependency: {dep}  →  pip install {dep}")
        if not HAS_SCAPY:
            print_err("Scapy is required for ARP scanning. Install it first.")
            sys.exit(1)


def resolve_forced_iface(iface_name: str) -> tuple[str, str, str, str]:
    """
    User passed --iface IFACE_NAME. Resolve its IP/netmask/MAC from the OS.
    Does NOT require the interface to be the default-route interface.
    """
    all_ifaces = detect_all_interfaces()
    for rec in all_ifaces:
        if rec[0] == iface_name:
            return rec
    print_err(f"Interface '{iface_name}' not found or has no IPv4 address.")
    sys.exit(1)


def run_scan(cidr: str, iface_name: str, args) -> list[dict]:
    t0 = time.time()
    devices = []
    net = ipaddress.IPv4Network(cidr, strict=False)
    host_count = net.num_addresses - 2

    if HAS_RICH:
        with Progress(
            SpinnerColumn(spinner_name="aesthetic", style="bold purple"),
            TextColumn("[bold purple]{task.description}"),
            BarColumn(bar_width=28, style="purple", complete_style="bright_magenta"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as prog:
            task = prog.add_task(
                f"[ARP] {cidr}  ({host_count} hosts)", total=None
            )
            raw = scan_network(cidr, iface_name, args.verbose)
            prog.update(task, description=f"[ENRICH] {len(raw)} host(s) found ...")
            devices = enrich_all(raw, args.ports)
    else:
        print(f"[*] Scanning {cidr}  ({host_count} hosts) ...")
        raw = scan_network(cidr, iface_name, args.verbose)
        print(f"[*] Enriching {len(raw)} host(s) ...")
        devices = enrich_all(raw, args.ports)

    elapsed = time.time() - t0
    if HAS_RICH:
        console.print(
            f"  [dim purple]Scan complete in [bold]{elapsed:.1f}s[/bold]  —  "
            f"[bold]{len(devices)}[/bold] device(s) found[/dim purple]\n")
    else:
        print(f"[✓] Done in {elapsed:.1f}s — {len(devices)} device(s)")
    return devices


def main():
    parser = build_parser()
    args   = parser.parse_args()

    print_banner()
    check_root()
    check_deps()

    if args.iface:
        chosen = resolve_forced_iface(args.iface)
    else:
        chosen = detect_active_interface()
        if not chosen:
            print_err(
                "Could not auto-detect an active network interface.\n"
                "  Try: sudo python3 netrecon.py --iface eth0"
            )
            sys.exit(1)

    iface_name, ip, nm, mac = chosen
    cidr    = iface_to_cidr(ip, nm)
    gateway = detect_gateway()

    print_local_info([chosen], gateway)
  
    if args.live:
        live_monitor(cidr, iface_name, args.interval, args.ports)
        return

    devices = run_scan(cidr, iface_name, args)
    print_results(devices, args.ports)

    if args.json:
        export_json(devices, args.json)
    if args.csv:
        export_csv(devices, args.csv)


if __name__ == "__main__":
    main()
