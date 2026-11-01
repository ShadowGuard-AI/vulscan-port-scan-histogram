# vulscan-port-scan-histogram
Runs a real TCP connect scan of an operator named IP range and generates a histogram of the open ports the scan actually finds, counted across the hosts in the range. Earlier versions printed a fixed demonstration sample and invented vulnerability verdicts for hosts that were never contacted; that behavior is removed. A port histogram makes no vulnerability findings, and this tool reports none.

## Install
`git clone https://github.com/ShadowGuardAI/vulscan-port-scan-histogram`

## Usage
`./vulscan-port-scan-histogram [params]`

## Parameters
- `--ip-range`: IP range to scan in CIDR format (e.g. 192.168.1.0/24), or a single IP address. Required. Ranges are limited to 256 hosts.
- `--top-ports`: Scan the first N ports of the built in common ports list (default: 100, capped at the list length of 50).
- `--ports`: Comma-separated list of ports to scan, overriding `--top-ports` (e.g. 80,443,9511).
- `--timeout`: Per-connection timeout in seconds (default: 0.5).
- `--output`: File path to save the histogram image (default: port_scan_histogram.png in the working directory).

A host counts as reached when it answers at all, with an open port or a connection refusal. Exit codes: 0 when the scan ran and at least one host responded (the histogram then reflects the real counts, including an empty result when no scanned port was open). An invalid range such as a plain word, an over-large range, or a run where no host responded exits non-zero and produces no histogram and no findings.

## License
Copyright (c) CY83R-3X71NC710N
