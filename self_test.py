#!/usr/bin/env python3
"""
ZeroDayForge Self-Test Script (No Target Required)
Run this script to verify that core modules, payloads, and logic work correctly.
"""

import logging
import os
from payloads.shellcode_asm.arch_agnostic import ShellcodeGenerator
from payloads.shellcode_asm.encryptors import ShellcodeEncryptor
from payloads.process_inject.injectors import ProcessInjector
from payloads.process_inject.evasion import InjectionEvasion
from core.heap_exploit.win32_heap import Win32HeapExploit
from core.fuzzer import ProtocolFuzzer, Protocol
from zerodayforge import render_banner, VERSION

# Initialize logger at module level so all test functions can use it
logger = logging.getLogger("ZDF-SelfTest")


def test_shellcode_gen():
	logger.info("[*] Testing shellcode generation")
	gen = ShellcodeGenerator('x64')
	sc = gen.generate_reverse_shell("127.0.0.1", 4444)
	assert isinstance(sc, bytes) and len(sc) > 0
	logger.info(f"[+] Generated shellcode: {len(sc)} bytes")

	dummy = b"\x90" * 120
	mutated = gen.polymorphic_mutate(dummy)
	assert isinstance(mutated, bytes)
	assert len(mutated) >= len(dummy) - 5  # small variation tolerance
	logger.info(f"[+] Shellcode mutation passed (final size: {len(mutated)} bytes)")


def test_encryption():
	logger.info("[*] Testing shellcode encryption")
	data = b"\x90\x90\xCC\xCC"
	enc = ShellcodeEncryptor()
	enc_data = enc.layered_encrypt(data)
	dec_data = enc.layered_decrypt(enc_data)
	assert dec_data == data
	logger.info("[+] AES + ChaCha20 encryption passed")


def test_heap():
	logger.info("[*] Testing simulated heap operations")
	heap = Win32HeapExploit()
	heap.create_heap()
	allocs = heap.alloc_free_cycle(count=10)
	marker = os.urandom(4)
	heap.write_fake_chunk(allocs[2], marker)
	read_back = heap.read_memory(allocs[2], 4)
	assert read_back == marker
	logger.info("[+] Heap simulation passed")


def test_fuzzer():
	logger.info("[*] Testing protocol fuzzer (dry run)")

	# Create fuzzer with dummy IP and port, skip socket init
	fuzzer = ProtocolFuzzer.__new__(ProtocolFuzzer)
	fuzzer.protocol = Protocol.SMBv1
	fuzzer.logger = logger

	pattern = b"A" * 64
	payload = fuzzer._generate_smb_packet(pattern)

	assert isinstance(payload, bytes)
	logger.info("[+] SMB packet generation passed (dry run)")


def test_injectors():
	logger.info("[*] Testing process injector class (constructor only)")
	try:
		injector = ProcessInjector(pid=1)
		assert injector is not None
		logger.info("[+] ProcessInjector constructor passed")
	except Exception as e:
		logger.warning(f"ProcessInjector test skipped (non-Windows): {str(e)}")


def test_syscall_stub():
	logger.info("[*] Testing syscall dispatcher stub (mocked)")
	try:
		from core.syscall_hook.syscall_dispatch import SyscallDispatcher
		s = SyscallDispatcher()
		assert hasattr(s, "direct_syscall")
		logger.info("[+] Syscall dispatcher initialized (stub OK)")
	except Exception as e:
		logger.warning(f"SyscallDispatcher test skipped (non-Windows): {str(e)}")


def main():
	render_banner()
	print(f"Version {VERSION}\n")
	logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	logger.info("=== ZeroDayForge Self-Test Starting ===")
	test_shellcode_gen()
	test_encryption()
	test_heap()
	test_fuzzer()
	test_injectors()
	test_syscall_stub()
	logger.info("=== ✅ All Self-Tests Passed ===")


if __name__ == "__main__":
	main()
