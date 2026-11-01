import argparse
import ipaddress
import logging
import socket
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import matplotlib.pyplot as plt

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Common ports, in the order the --top-ports option scans them.
TOP_PORTS = [
    80, 443, 22, 21, 25, 3389, 110, 995, 143, 993,
    465, 587, 53, 8080, 8443, 3306, 5432, 6379, 27017, 1433,
    1521, 2049, 5900, 8000, 8888, 9200, 9300, 11211, 5060, 161,
    389, 636, 873, 1080, 3128, 4444, 5555, 6666, 7777, 9999,
    10000, 32768, 49152, 62078, 27015, 25565, 19132, 51820, 1194, 1723,
]

MAX_HOSTS = 256
MAX_PORTS = 1000


def setup_argparse():
    """
    Sets up command-line argument parsing.

    Returns:
        argparse.Namespace: Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Runs a real TCP connect scan of the given IP range and generates a histogram of the open ports found. A port histogram makes no vulnerability findings, and none are reported."
    )
    parser.add_argument(
        "--ip-range",
        required=True,
        help="IP range to scan in CIDR format (e.g., 192.168.1.0/24), or a single IP address."
    )
    parser.add_argument(
        "--top-ports",
        type=int,
        default=100,
        help="Scan the first N ports of the built in common ports list (default: 100, capped at the list length)."
    )
    parser.add_argument(
        "--ports",
        help="Comma-separated list of ports to scan, overriding --top-ports (e.g., 80,443,9511)."
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Per-connection timeout in seconds (default: 0.5)."
    )
    parser.add_argument(
        "--output",
        help="File path to save the histogram image (default: port_scan_histogram.png in the working directory)."
    )
    return parser.parse_args()


def parse_targets(ip_range):
    """
    Parses the --ip-range value into a list of host addresses.

    Accepts CIDR notation or a single IP address. Raises ValueError on
    anything else, including plain names: a target the tool cannot
    resolve to addresses is an error, never a finding.
    """
    # strict=False is deliberate on my part: 192.168.1.5/24 means the
    # /24 around that address, not an error. I would rather scan the
    # range the operator pointed at than argue about host bits.
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError:
        try:
            single = ipaddress.ip_address(ip_range)
            network = ipaddress.ip_network(f"{single}/32" if single.version == 4 else f"{single}/128")
        except ValueError:
            raise ValueError(f"Invalid IP range or address: {ip_range}")
    hosts = list(network.hosts()) if network.num_addresses > 1 else [network.network_address]
    # The 256 host cap is my guardrail against fat-fingering a /16 and
    # spending the afternoon on it. Narrow the range and run it again.
    if len(hosts) > MAX_HOSTS:
        raise ValueError(f"Range {ip_range} contains {len(hosts)} hosts; the limit is {MAX_HOSTS}. Narrow the range.")
    return hosts


def select_ports(args):
    """Returns the concrete port list to scan from --ports or --top-ports."""
    if args.ports:
        ports = []
        # I do not dedupe this list. Ask for 80 twice and it is scanned
        # twice, and an open result counts twice in the histogram.
        for item in args.ports.split(","):
            item = item.strip()
            if not item:
                continue
            port = int(item)
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port: {port}")
            ports.append(port)
        if not ports:
            raise ValueError("--ports was given but contained no ports.")
    else:
        if args.top_ports < 1:
            raise ValueError("--top-ports must be at least 1.")
        # The built in list holds 50 ports, so asking for the top 100
        # just takes all 50. The cap is the list, not the number given.
        ports = TOP_PORTS[: args.top_ports]
    if len(ports) > MAX_PORTS:
        raise ValueError(f"{len(ports)} ports requested; the limit is {MAX_PORTS}.")
    return ports


def _connect(host, port, timeout):
    """One TCP connect attempt. Returns 'open', 'refused', or 'unreachable'."""
    # The except order matters here: ConnectionRefusedError is an
    # OSError subclass, so it has to be caught before the catch-all or
    # every refused port would read as unreachable.
    try:
        with socket.create_connection((str(host), port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "refused"
    except (socket.timeout, TimeoutError, OSError):
        return "unreachable"


def scan_ports(hosts, ports, timeout):
    """
    Runs a real TCP connect scan of every host and port pair.

    Returns:
        tuple: (port_counts, hosts_reached, open_by_host) where
        port_counts counts open ports across all hosts, hosts_reached
        counts hosts that answered at all (an open port or a refusal,
        both of which prove the host responded), and open_by_host maps
        each host to its sorted list of open ports.
    """
    logging.info(f"Scanning {len(hosts)} host(s) on {len(ports)} port(s) each.")
    pairs = [(host, port) for host in hosts for port in ports]
    # pool.map returns in submission order, so the zip below pairs each
    # outcome with the host and port that produced it. That ordering is
    # the whole reason I use map here instead of as_completed.
    with ThreadPoolExecutor(max_workers=64) as pool:
        outcomes = list(pool.map(lambda hp: _connect(hp[0], hp[1], timeout), pairs))

    port_counts = Counter()
    open_by_host = {host: [] for host in hosts}
    reached = set()
    for (host, port), outcome in zip(pairs, outcomes):
        if outcome == "open":
            port_counts[port] += 1
            open_by_host[host].append(port)
            reached.add(host)
        # A refusal still proves the host answered, so it counts as
        # reached. Only silence reads as unreached.
        elif outcome == "refused":
            reached.add(host)
    for host in hosts:
        open_by_host[host] = sorted(open_by_host[host])
        if open_by_host[host]:
            logging.info(f"{host}: open ports {', '.join(str(p) for p in open_by_host[host])}")
    logging.info(f"Port scanning completed. {len(reached)} of {len(hosts)} host(s) responded, {sum(port_counts.values())} open port(s) found.")
    return port_counts, len(reached), open_by_host


def generate_histogram(port_counts, output_path):
    """
    Generates a histogram of open ports counted by the scan and saves it
    to output_path. With no open ports the chart is empty and its title
    says so; the counts are the scan's real results either way.
    """
    logging.info("Generating histogram for open ports.")
    ports = sorted(port_counts.keys())
    counts = [port_counts[p] for p in ports]

    plt.figure()
    # The empty chart is a real outcome, not a failure: hosts answered
    # and nothing was open, and the title below says exactly that.
    if ports:
        plt.bar([str(p) for p in ports], counts, color='skyblue')
        plt.title('Histogram of Open Ports')
    else:
        plt.bar([], [])
        plt.title('Histogram of Open Ports (none found)')
    plt.xlabel('Ports')
    plt.ylabel('Frequency')
    plt.savefig(output_path)
    plt.close()
    logging.info(f"Histogram saved to {output_path}.")


def main():
    """
    Main function to orchestrate the tool's operations.

    Returns an exit code: 0 when the scan ran against at least one
    responding host, 1 on invalid input or when no host responded, in
    which case no histogram is produced and no result is claimed.
    """
    args = setup_argparse()

    try:
        hosts = parse_targets(args.ip_range)
        ports = select_ports(args)
    except ValueError as e:
        logging.error(str(e))
        return 1

    try:
        port_counts, hosts_reached, _open_by_host = scan_ports(hosts, ports, args.timeout)
    except Exception as e:
        logging.error(f"Scan failed: {e}")
        return 1

    # No answers at all means I have nothing to chart and nothing to
    # claim. Exit 1 and leave no PNG behind to be misread later.
    if hosts_reached == 0:
        logging.error("No host in the range responded; the scan produced no results and no histogram was generated.")
        return 1

    output_path = args.output if args.output else "port_scan_histogram.png"
    try:
        generate_histogram(port_counts, output_path)
    except Exception as e:
        logging.error(f"Failed to generate histogram: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
