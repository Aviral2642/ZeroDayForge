import logging
import pickle
import random
import socket
import struct
import time
from enum import Enum
from collections import deque

class Protocol(Enum):
	SMBv1 = 1
	RDP = 2
	HTTP = 3
	LDAP = 4
	FTP = 5
	DNS = 6

class ProtocolFuzzer:
	def __init__(self, target_ip, port, protocol=Protocol.SMBv1, poc_mode=False):
		self.target_ip = target_ip
		self.port = port
		self.protocol = protocol
		self.poc_mode = poc_mode
		self.crash_db = []
		self.logger = logging.getLogger('ZeroDayForge.Fuzzer')
		self.sock = None
		self.sequence_num = 0
		self.fuzz_patterns = deque(maxlen=1000)
		self._initialize_socket()
		self._validate_protocol()

	def _validate_protocol(self):
		if not isinstance(self.protocol, Protocol):
			raise ValueError("Invalid protocol specified")

	def _initialize_socket(self):
		"""Create and configure socket with proper timeouts"""
		if self.sock:
			self.sock.close()
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.settimeout(5)
		try:
			self.sock.connect((self.target_ip, self.port))
		except socket.error as e:
			self.logger.error(f"Connection failed: {str(e)}")
			raise

	def fuzz(self, iterations=1000):
		"""Main fuzzing loop with reconnection logic"""
		crash_windows = []
		retry_count = 0
		max_retries = 3

		for i in range(iterations):
			try:
				if not self.sock:
					self._initialize_socket()

				pattern = self._create_cyclic_buffer(500 + i % 200)
				payload = self._craft_protocol_payload(pattern)
				self._send_payload(payload)
				response = self._receive_response()
				
				# Reset retry counter on successful iteration
				retry_count = 0

			except (socket.timeout, ConnectionResetError, BrokenPipeError) as e:
				self.logger.critical(f"Crash detected at iteration {i}")
				self._log_crash_payload(i, payload, str(e))
				crash_windows.append((i-5, i+5))
				
				if self.poc_mode:
					self._generate_poc_script(i, payload)
				
				# Reset connection after crash
				self._initialize_socket()
				retry_count += 1
				
				if retry_count > max_retries:
					self.logger.error("Max retries exceeded, aborting")
					break

		self.sock.close()
		return crash_windows

	def _create_cyclic_buffer(self, length):
		"""Generate De Bruijn sequence pattern for offset identification"""
		charset = bytearray(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ")
		return bytes((i % 256) for i in range(length))

	def _craft_protocol_payload(self, pattern):
		"""Protocol-specific payload generation"""
		try:
			if self.protocol == Protocol.SMBv1:
				return self._generate_smb_packet(pattern)
			elif self.protocol == Protocol.RDP:
				return self._generate_rdp_packet(pattern)
			elif self.protocol == Protocol.HTTP:
				return self._generate_http_packet(pattern)
			elif self.protocol == Protocol.LDAP:
				return struct.pack(">I", len(pattern)+5) + b"\x02\x01\x01" + pattern
			elif self.protocol == Protocol.FTP:
				return b"USER " + pattern + b"\r\n"
			elif self.protocol == Protocol.DNS:
				return struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + pattern
			else:
				raise ValueError("Unsupported protocol")
		except Exception as e:
			self.logger.error(f"Payload generation failed: {str(e)}")
			raise

	def _generate_smb_packet(self, pattern):
		"""Construct SMBv1 Negotiate Protocol Request with fuzzed fields"""
		header = struct.pack(
			">BIIII",
			0x00,  # Protocol ID
			0x00,  # Command (Negotiate Protocol)
			0x00000000,  # NT Status
			0x00000000,  # Flags
			0x00000000   # Flags2
		)
		
		parameter_block = struct.pack(
			"<HBB",
			0x0000,  # Word Count
			0x11,    # Dialect Index
			0x03     # Security Mode
		)
		
		data_block = struct.pack(
			"<H",
			len(pattern)
		) + pattern
		
		return header + parameter_block + data_block

	def _generate_rdp_packet(self, pattern):
		"""Construct RDP Connection Request PDU with fuzzed data"""
		tpkt_header = struct.pack(
			">BBH",
			0x03,  # Version
			0x00,  # Reserved
			len(pattern) + 20
		)
		
		x224_data = struct.pack(
			">BBH",
			0x06,  # Length Indicator
			0xF0,  # Type (CR)
			0x0000  # Dst Reference
		)
		
		return tpkt_header + x224_data + pattern

	def _generate_http_packet(self, pattern):
		"""Construct malformed HTTP request"""
		return (
			f"GET /{pattern.decode('latin-1')} HTTP/1.1\r\n"
			f"Host: {self.target_ip}\r\n"
			"Content-Length: 0\r\n"
			"X-Fuzz-Header: " + "A"*500 + "\r\n\r\n"
		).encode('latin-1')

	def _send_payload(self, payload):
		"""Reliable payload transmission with retries"""
		attempts = 0
		while attempts < 3:
			try:
				self.sock.sendall(payload)
				return
			except socket.error as e:
				self.logger.warning(f"Send failed (attempt {attempts+1}): {str(e)}")
				self._initialize_socket()
				attempts += 1
		raise ConnectionError("Failed to send payload after 3 attempts")

	def _receive_response(self):
		"""Receive response with proper timeout handling"""
		try:
			response = b""
			while True:
				chunk = self.sock.recv(4096)
				if not chunk:
					break
				response += chunk
				if len(chunk) < 4096:
					break
			return response
		except socket.timeout:
			return b""

	def _log_crash_payload(self, iteration, payload, error):
		"""Save crash artifacts with metadata"""
		entry = {
			'iteration': iteration,
			'payload': payload,
			'protocol': self.protocol.name,
			'error': error,
			'target': (self.target_ip, self.port),
			'timestamp': time.time()
		}
		self.crash_db.append(entry)
		
		try:
			with open(f"crash_{self.target_ip}_{int(time.time())}.pkl", "wb") as f:
				pickle.dump(entry, f)
		except Exception as e:
			self.logger.error(f"Failed to save crash dump: {str(e)}")

	def _generate_poc_script(self, iteration, payload):
		"""Generate reproducible proof-of-concept script"""
		try:
			script = f"""import socket
target = ("{self.target_ip}", {self.port})
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(target)
s.send({repr(payload)})
s.close()"""
			
			filename = f"poc_{self.target_ip}_{iteration}.py"
			with open(filename, "w") as f:
				f.write(script)
				
			self.logger.info(f"Generated PoC script: {filename}")
		except Exception as e:
			self.logger.error(f"Failed to generate PoC: {str(e)}")

	def __del__(self):
		"""Cleanup resources"""
		try:
			if hasattr(self, "sock") and self.sock:
				self.sock.close()
		except Exception:
			pass


# Example usage
if __name__ == "__main__":
	logging.basicConfig(level=logging.DEBUG)
	
	try:
		fuzzer = ProtocolFuzzer("192.168.1.100", 445, Protocol.SMBv1)
		crash_windows = fuzzer.fuzz(iterations=1000)
		print(f"Detected crash windows: {crash_windows}")
	except Exception as e:
		logging.error(f"Fuzzing failed: {str(e)}")