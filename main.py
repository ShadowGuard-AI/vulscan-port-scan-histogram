import argparse
import requests
from bs4 import BeautifulSoup
import logging
from collections import Counter
import matplotlib.pyplot as plt

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up command-line argument parsing.

    Returns:
        argparse.Namespace: Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Generates a histogram of open ports across a given IP range and scans for web application vulnerabilities."
    )
    parser.add_argument(
        "--ip-range",
        required=True,
        help="IP range to scan in CIDR format (e.g., 192.168.1.0/24)."
    )
    parser.add_argument(
        "--top-ports",
        type=int,
        default=100,
        help="Number of top ports to scan (default: 100)."
    )
    parser.add_argument(
        "--output",
        help="File path to save the histogram image (optional)."
    )
    return parser.parse_args()

def scan_ports(ip_range, top_ports):
    """
    Scans the specified IP range for open ports.

    Args:
        ip_range (str): The IP range in CIDR format.
        top_ports (int): Number of top ports to scan.

    Returns:
        dict: A dictionary with ports as keys and their occurrence count as values.
    """
    # Simulated code for port scanning (replace with actual port scan logic)
    logging.info(f"Scanning IP range: {ip_range} for top {top_ports} ports.")
    simulated_results = [80, 443, 22, 80, 8080, 22, 80, 443, 3306, 8080]
    port_counts = Counter(simulated_results)
    logging.info("Port scanning completed.")
    return port_counts

def scan_vulnerabilities(ip):
    """
    Scans a given IP for common web application vulnerabilities.

    Args:
        ip (str): The IP address to scan.

    Returns:
        list: List of detected vulnerabilities.
    """
    # Simulated vulnerability scanning (replace with real HTTP analysis logic)
    logging.info(f"Scanning IP {ip} for web application vulnerabilities.")
    simulated_vulnerabilities = ["SQL Injection", "XSS"]
    return simulated_vulnerabilities

def generate_histogram(port_counts, output_path=None):
    """
    Generates a histogram of open ports.

    Args:
        port_counts (dict): Dictionary with ports as keys and their occurrence counts as values.
        output_path (str, optional): Path to save the histogram image. Defaults to None.
    """
    logging.info("Generating histogram for open ports.")
    ports = list(port_counts.keys())
    counts = list(port_counts.values())

    plt.bar(ports, counts, color='skyblue')
    plt.xlabel('Ports')
    plt.ylabel('Frequency')
    plt.title('Histogram of Open Ports')
    if output_path:
        plt.savefig(output_path)
        logging.info(f"Histogram saved to {output_path}.")
    else:
        plt.show()

def main():
    """
    Main function to orchestrate the tool's operations.
    """
    args = setup_argparse()

    try:
        # Perform port scanning
        port_counts = scan_ports(args.ip_range, args.top_ports)

        # Generate histogram
        generate_histogram(port_counts, args.output)

        # Simulate vulnerability scanning for the first IP in the range
        logging.info("Performing vulnerability scan for the first IP in the range.")
        first_ip = args.ip_range.split('/')[0]
        vulnerabilities = scan_vulnerabilities(first_ip)
        logging.info(f"Vulnerabilities detected on {first_ip}: {', '.join(vulnerabilities)}")

    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()