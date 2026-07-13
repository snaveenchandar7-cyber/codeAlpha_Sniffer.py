import argparse
import datetime
import sys

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list
except ImportError:
    print("Scapy is not installed. Install it with:  pip install scapy")
    sys.exit(1)

LOG_FILE = None


def get_protocol_name(packet):
    """Return a short, human-readable protocol name for the packet."""
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def format_payload(packet, max_len=60):
    """Grab a short, safe-to-print preview of the raw payload, if present."""
    if not packet.haslayer(Raw):
        return ""

    raw_bytes = bytes(packet[Raw].load)
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = raw_bytes.hex()

    text = text.replace("\n", " ").replace("\r", " ").strip()

    if len(text) > max_len:
        return text[:max_len] + "..."
    return text


def log_line(line):
    """Print a line to the console and optionally append it to a log file."""
    print(line)
    if LOG_FILE:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def process_packet(packet):
    """Callback fired by scapy for every captured packet."""
    if not packet.haslayer(IP):
        return

    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    ip_layer = packet[IP]
    proto = get_protocol_name(packet)

    src_port = dst_port = None
    if packet.haslayer(TCP):
        src_port, dst_port = packet[TCP].sport, packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port, dst_port = packet[UDP].sport, packet[UDP].dport

    port_info = f"{src_port} -> {dst_port}" if src_port else "N/A"
    payload_preview = format_payload(packet)

    line = (
        f"[{timestamp}] {proto:5} | {ip_layer.src:15} -> {ip_layer.dst:15} | "
        f"Ports: {port_info:13} | Len: {len(packet):4}B | Payload: {payload_preview}"
    )
    log_line(line)


def main():
    global LOG_FILE

    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer (Scapy-based) -- CodeAlpha Task 1"
    )
    parser.add_argument("-i", "--interface", help="Interface to sniff on (e.g. eth0, wlan0)")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Number of packets to capture (0 = run until Ctrl+C)")
    parser.add_argument("-f", "--filter", default="",
                         help="BPF filter, e.g. 'tcp port 80' or 'udp port 53'")
    parser.add_argument("-o", "--output", default=None,
                         help="Optional file path to also save the captured log")
    args = parser.parse_args()

    if args.output:
        LOG_FILE = args.output

    if not args.interface:
        print("No interface specified. Available interfaces on this machine:\n")
        for iface in get_if_list():
            print(f"  - {iface}")
        print("\nRe-run with: sudo python3 sniffer.py -i <interface_name>")
        return

    print(f"Starting capture on '{args.interface}'"
          f"{' with filter ' + repr(args.filter) if args.filter else ''}."
          f" Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=args.interface,
            prn=process_packet,
            count=args.count,
            filter=args.filter if args.filter else None,
            store=False,
        )
    except PermissionError:
        print("Permission denied. Re-run with sudo (Linux/macOS) or as Administrator (Windows).")
    except OSError as e:
        print(f"Could not open interface '{args.interface}': {e}")
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")


if __name__ == "__main__":
    main()
