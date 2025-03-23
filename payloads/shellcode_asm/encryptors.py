import os
import random
import hashlib
import logging
from Cryptodome.Cipher import AES, ChaCha20
from Cryptodome.Util import Counter

class EncryptionError(Exception):
	"""Custom exception for encryption failures"""
	pass

class ShellcodeEncryptor:
	def __init__(self, key=None):
		self.logger = logging.getLogger('ZeroDayForge.Encryptor')
		self.key = key or os.urandom(32)
		
	def xor_encrypt(self, data):
		"""XOR cipher with random 4-byte key (fallback)"""
		try:
			xor_key = os.urandom(4)
			return xor_key + bytes([b ^ xor_key[i%4] for i, b in enumerate(data)])
		except Exception as e:
			self.logger.error(f"XOR failed: {str(e)}")
			raise EncryptionError("XOR encryption failed")

	def aes_ctr_encrypt(self, data):
		"""AES-256-CTR with random nonce"""
		try:
			nonce = os.urandom(8)
			counter = Counter.new(64, prefix=nonce)
			cipher = AES.new(self.key, AES.MODE_CTR, counter=counter)
			return nonce + cipher.encrypt(data)
		except Exception as e:
			self.logger.error(f"AES failed: {str(e)}")
			raise EncryptionError("AES encryption failed")

	def aes_ctr_decrypt(self, ciphertext):
		"""AES-256-CTR decryption"""
		try:
			nonce = ciphertext[:8]
			counter = Counter.new(64, prefix=nonce)
			cipher = AES.new(self.key, AES.MODE_CTR, counter=counter)
			return cipher.decrypt(ciphertext[8:])
		except Exception as e:
			self.logger.error(f"AES decrypt failed: {str(e)}")
			raise EncryptionError("AES decryption failed")

	def layered_encrypt(self, data):
		"""AES-CTR -> ChaCha20 encryption"""
		try:
			aes_encrypted = self.aes_ctr_encrypt(data)
			return self.chacha_custom(aes_encrypted)
		except Exception as e:
			self.logger.error(f"Layered encrypt failed: {str(e)}")
			return self.xor_encrypt(data)  # Fallback

	def layered_decrypt(self, ciphertext):
		"""ChaCha20 -> AES-CTR decryption"""
		try:
			chacha_decrypted = self.chacha_decrypt(ciphertext)
			return self.aes_ctr_decrypt(chacha_decrypted)
		except Exception as e:
			self.logger.error(f"Layered decrypt failed: {str(e)}")
			raise EncryptionError("Decryption failed")

	def chacha_custom(self, data):
		"""ChaCha20 with BLAKE2s key derivation"""
		try:
			derived_key = hashlib.blake2s(self.key, digest_size=32).digest()
			nonce = os.urandom(12)
			cipher = ChaCha20.new(key=derived_key, nonce=nonce)
			return nonce + cipher.encrypt(data)
		except Exception as e:
			self.logger.error(f"ChaCha failed: {str(e)}")
			raise EncryptionError("ChaCha encryption failed")
			
	def chacha_decrypt(self, ciphertext):
		"""ChaCha20 decryption with BLAKE2s key derivation"""
		try:
			nonce = ciphertext[:12]
			derived_key = hashlib.blake2s(self.key, digest_size=32).digest()
			cipher = ChaCha20.new(key=derived_key, nonce=nonce)
			return cipher.decrypt(ciphertext[12:])
		except Exception as e:
			self.logger.error(f"ChaCha decrypt failed: {str(e)}")
			raise EncryptionError("ChaCha decryption failed")
