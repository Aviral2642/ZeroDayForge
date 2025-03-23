# syscall_db.py
# Syscall Database for Various OS Versions

SYSCALL_DB = {
	# Windows 10 (20H2 - Build 19042)
	('Windows', '10.0.19042'): {
		'NtCreateFile': 0x55,
		'NtAllocateVirtualMemory': 0x18,
		'NtWriteVirtualMemory': 0x3A,
		'NtCreateThreadEx': 0xC1,
		'NtProtectVirtualMemory': 0x50,
		'NtClose': 0x0F,
	},
	# Windows 11 (21H2 - Build 22000)
	('Windows', '10.0.22000'): {
		'NtCreateFile': 0x55,
		'NtAllocateVirtualMemory': 0x18,
		'NtWriteVirtualMemory': 0x3A,
		'NtCreateThreadEx': 0xC1,
		'NtProtectVirtualMemory': 0x50,
		'NtClose': 0x0F,
	},
	# Linux 5.15 (Ubuntu 22.04)
	('Linux', '5.15.0-86-generic'): {
		'sys_read': 0x00,
		'sys_write': 0x01,
		'sys_open': 0x02,
		'sys_close': 0x03,
		'sys_mmap': 0x09,
		'sys_mprotect': 0x0A,
	},
	# Linux 6.2 (Fedora 38)
	('Linux', '6.2.0-20-generic'): {
		'sys_read': 0x00,
		'sys_write': 0x01,
		'sys_open': 0x02,
		'sys_close': 0x03,
		'sys_mmap': 0x09,
		'sys_mprotect': 0x0A,
	},
	# macOS 13 (Ventura)
	('Darwin', '22.1.0'): {
		'syscall_open': 0x2000005,
		'syscall_close': 0x2000006,
		'syscall_mmap': 0x20000C5,
		'syscall_mprotect': 0x200004A,
	},
}