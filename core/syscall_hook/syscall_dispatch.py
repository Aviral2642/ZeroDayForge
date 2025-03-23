import platform
import ctypes
import logging
import mmap
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KsError
from syscall_db import SYSCALL_DB  # Our custom syscall database

class SyscallError(Exception):
	"""Custom exception for syscall failures"""
	pass

class SyscallDispatcher:
	def __init__(self):
		self.logger = logging.getLogger('ZeroDayForge.Syscall')
		self.arch = platform.machine()
		self.os = platform.system()
		self.syscall_table = None
		self._setup_platform()
		self._verify_architecture()
		self._load_syscall_table()
		
		# Setup assembler for Windows shellcode generation
		if self.os == 'Windows':
			self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
			self.ks.syntax = Ks.SYNTAX_INTEL

	def _setup_platform(self):
		"""Detect and configure platform-specific settings"""
		if self.os == 'Windows':
			self.ntdll = ctypes.WinDLL('ntdll')
			self._setup_windows_abi()
		elif self.os in ['Linux', 'Darwin']:
			self.libc = ctypes.CDLL(None)
			self._setup_unix_abi()

	def _setup_windows_abi(self):
		"""Configure Windows x64 calling convention"""
		self.arg_types = {
			0: ctypes.c_ulonglong,
			1: ctypes.c_ulonglong,
			2: ctypes.c_ulonglong,
			3: ctypes.c_ulonglong,
			4: ctypes.c_ulonglong,
			5: ctypes.c_ulonglong
		}
		self.STDCALL = ctypes.WINFUNCTYPE(
			ctypes.c_ulonglong,
			ctypes.c_ulonglong,
			ctypes.c_ulonglong,
			ctypes.c_ulonglong,
			ctypes.c_ulonglong,
			ctypes.c_ulonglong,
			ctypes.c_ulonglong
		)

	def _setup_unix_abi(self):
		"""Configure System V AMD64 ABI"""
		self.arg_types = {
			i: ctypes.c_ulonglong for i in range(6)
		}
		
	def _verify_architecture(self):
		"""Ensure we're running on x86_64 architecture"""
		if '64' not in self.arch:
			raise SyscallError(f"Unsupported architecture: {self.arch}")

	def _load_syscall_table(self):
		"""Load version-specific syscall numbers"""
		os_info = (self.os, platform.release())
		if os_info not in SYSCALL_DB:
			raise SyscallError(f"Unsupported OS version: {os_info}")
		self.syscall_table = SYSCALL_DB[os_info]
		self.logger.debug(f"Loaded syscall table for {os_info}")

	def get_syscall_id(self, name):
		"""Get syscall number with validation"""
		if not self.syscall_table:
			raise SyscallError("Syscall table not loaded")
			
		if syscall_id := self.syscall_table.get(name):
			return syscall_id
		raise SyscallError(f"Unknown syscall: {name}")

	def direct_syscall(self, syscall_name, *args):
		"""Execute syscall with platform-specific handling"""
		try:
			syscall_id = self.get_syscall_id(syscall_name)
			
			if self.os == 'Windows':
				return self._execute_windows_syscall(syscall_id, *args)
			else:
				return self._execute_unix_syscall(syscall_id, *args)
				
		except KsError as e:
			self.logger.error(f"Assembly failed: {str(e)}")
			raise SyscallError("Syscall generation failed")
		except Exception as e:
			self.logger.error(f"Syscall execution failed: {str(e)}")
			raise

	def _execute_windows_syscall(self, syscall_id, *args):
		"""Windows syscall via dynamically generated shellcode"""
		# Generate syscall stub: mov rax, SSN; syscall; ret
		asm = f"""
			mov rax, {hex(syscall_id)}
			syscall
			ret
		"""
		
		# Assemble the shellcode
		encoding, _ = self.ks.asm(asm)
		shellcode = bytes(encoding)
		
		# Allocate RWX memory
		buf = mmap.mmap(-1, len(shellcode), prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)
		buf.write(shellcode)
		
		# Cast to function pointer
		func_ptr = self.STDCALL(ctypes.addressof(ctypes.c_char_p(buf)))
		
		# Prepare arguments
		args += (0,) * (6 - len(args))  # Pad missing args
		converted_args = [
			self.arg_types[i](arg) for i, arg in enumerate(args[:6])
		]
		
		# Execute
		result = func_ptr(*converted_args)
		buf.close()
		
		return result

	def _execute_unix_syscall(self, syscall_id, *args):
		"""Linux/macOS syscall via libc"""
		# Map arguments to ctypes types
		arg_list = []
		for i, arg in enumerate(args):
			arg_list.append(ctypes.c_ulonglong(arg))
		
		# Pad missing arguments
		arg_list += [ctypes.c_ulonglong(0)] * (6 - len(args))
		
		# Syscall signature: long syscall(long number, ...)
		result = self.libc.syscall(
			ctypes.c_ulonglong(syscall_id),
			*arg_list
		)
		
		if result < 0:
			errno = ctypes.get_errno()
			raise SyscallError(f"Syscall failed (errno={errno})")
			
		return result

	def __del__(self):
		"""Cleanup resources"""
		if hasattr(self, 'ks'):
			del self.ks

# Example usage
if __name__ == "__main__":
	logging.basicConfig(level=logging.DEBUG)
	
	try:
		dispatcher = SyscallDispatcher()
		
		# Windows example: NtAllocateVirtualMemory
		if platform.system() == 'Windows':
			alloc_size = ctypes.c_ulonglong(0x1000)
			base_addr = ctypes.c_ulonglong(0)
			result = dispatcher.direct_syscall(
				'NtAllocateVirtualMemory',
				-1,                            # ProcessHandle
				ctypes.byref(base_addr),       # BaseAddress
				0,                             # ZeroBits
				ctypes.byref(alloc_size),      # RegionSize
				0x3000,                       # AllocationType (MEM_COMMIT|MEM_RESERVE)
				0x40                          # Protect (PAGE_EXECUTE_READWRITE)
			)
			print(f"Allocated memory at 0x{base_addr.value:x}")
			
		# Linux example: sys_mmap
		elif platform.system() == 'Linux':
			size = 0x1000
			result = dispatcher.direct_syscall(
				'sys_mmap',
				0,                    # addr
				size,                  # length
				0x7,                   # prot (PROT_READ|PROT_WRITE|PROT_EXEC)
				0x22,                  # flags (MAP_PRIVATE|MAP_ANONYMOUS)
				-1,                    # fd
				0                      # offset
			)
			print(f"Mapped memory at 0x{result:x}")
			
	except SyscallError as e:
		print(f"Syscall failed: {str(e)}")
		sys.exit(1)