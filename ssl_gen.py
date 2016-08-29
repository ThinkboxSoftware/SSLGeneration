from OpenSSL import crypto
from os import path,makedirs, remove
from datetime import datetime
import re
from shutil import copy

key_dir=path.dirname(path.realpath(__file__)) + "/keys"
key_dir=key_dir.replace('\\','/')
index_file = key_dir + '/index.txt'

class SSLCertificateGenerator:
	key_dir = None
	index_file = None
	serial = None
	
	def __init__(self, key_dir=None):
		# Define key_dir
		if key_dir:
			key_dir = key_dir.replace('\\', '/')
			if not os.path.isdir(key_dir):
				raise Exception("Key Directory does not exist or is not a directory:" + key_dir)
		else:
			key_dir = path.dirname(path.realpath(__file__)) + "/keys"
			key_dir = key_dir.replace('\\', '/')
		
		self.key_dir = key_dir
		
		self.index_file = key_dir + '/index.txt'
			
		# Get serial number
		try:
			serial_file = open(key_dir + '/serial', 'r')
			self.serial = int(serial_file.readline());
			serial_file.close
		except IOError:
			self.serial = 1
	
	def _get_cert_dn(self, cert):
		dn = ''
		for label, value in cert.get_subject().get_components():
			dn += '/' + label + '=' + value
		
		return dn
	
	def _gen_key(self):
		# Generate new key
		key = crypto.PKey()
		key.generate_key(crypto.TYPE_RSA, 2048)
		return key
	
	def _create_csr(self, cert_name, key):
		req = crypto.X509Req()
		req.get_subject().CN = cert_name
		req.set_pubkey(key)
		req.sign(key, "sha256")
		return req
	
	def _write_key_to_file(self, key, filepath):
		key_file = open(filepath, 'w')
		key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("utf-8"))
		key_file.close()
		
	def _load_key_from_file(self, filepath):
		key_file = open(filepath, 'r')
		key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read())
		key_file.close()
		return key
	
	def _write_cert_to_file(self, cert, filepath):
		cert_file = open(filepath, 'w')
		cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
		cert_file.close()
	
	def _load_cert_from_file(self, filepath):
		cert_file = open(filepath, 'r')
		cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
		cert_file.close()
		return cert
	
	def _write_csr_to_file(self, csr, filepath):
		csr_file = open(filepath, 'w')
		csr_file.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr).decode("utf-8"))
		csr_file.close()
		
	def _load_csr_from_file(self, filepath):
		csr_file = open(filepath, 'r')
		csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_file.read())
		csr_file.close()
		return csr
	
	def _write_pfx_to_file(self, pkcs12, filepath):
		pkcs12_file=open(filepath, 'w')
		pkcs12_file.write(str(pkcs12.export()))
		pkcs12_file.close()
	
	def _write_crl_to_file(self, crl, ca_cert, ca_key, filepath):
		# Write CRL file
		crl_file = open(filepath, 'w')
		crl_file.write(crl.export(ca_cert, ca_key, days=365).decode("utf-8"))
		crl_file.close()
	
	def _load_crl_from_file(self, filepath):
		try:
			crl_file = open(filepath, 'r')
			crl = crypto.load_crl(crypto.FILETYPE_PEM, crl_file.read())
			crl_file.close()
		except IOError:
			# Create new CRL file if it doesn't exist
			crl = crypto.CRL()
		
		return crl
		
	def _sign_csr(self, req, ca_key, ca_cert, cert_org=False, cert_ou=False, usage=3, days=3650, alt_names=[]):
		expiry_seconds = days * 86400
		
		# Create and sign certificate
		cert = crypto.X509()
		cert.set_subject(req.get_subject())
		if cert_org:
			cert.get_subject().O = cert_org
		else:
			cert.get_subject().O = ca_cert.get_subject().O
		if cert_ou:
			cert.get_subject().OU = cert_ou
		else:
			cert.get_subject().OU = ca_cert.get_subject().OU
		cert.set_serial_number(self.serial)
		cert.gmtime_adj_notBefore(0)
		cert.gmtime_adj_notAfter(expiry_seconds)
		cert.set_issuer(ca_cert.get_subject())
		cert.set_pubkey(req.get_pubkey())
		if usage == 1:
			cert.add_extensions([
				crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
				crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
				crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert)
			])
		elif usage == 2:
			cert.add_extensions([
				crypto.X509Extension(b"extendedKeyUsage", True, b"serverAuth"),
			])
		elif usage == 3:
			cert.add_extensions([
				crypto.X509Extension(b"extendedKeyUsage", True, b"clientAuth"),
			])
		
		# Add alt names
		if alt_names:
			for name in alt_names:
				name = "DNS:" + name
			cert.add_extensions([
				crypto.X509Extension(b"subjectAltName", False, b"DNS:" + ",DNS:".join(alt_names).encode("utf-8"))
			])
		
		cert.sign(ca_key, "sha256")
		
		# Write to index.txt
		db_line = "V\t" + cert.get_notBefore().decode("utf-8") + "\t\t" + hex(int(cert.get_serial_number())) + "\tunknown\t" + str(cert.get_subject())[18:-2] + "\n"
		index_file = open(key_dir + '/index.txt', 'a')
		index_file.write(db_line)
		index_file.close()
		
		# Write updated serial file
		serial_file = open(key_dir + '/serial', 'w')
		serial_file.write(str(self.serial + 1))
		serial_file.close()
		
		return cert
	
	
	def gen_ca(self, cert_org="Thinkbox Software", cert_ou="IT", days = 3650):
		expiry_seconds = days * 86400
		
		# Generate key
		key = crypto.PKey()
		key.generate_key(crypto.TYPE_RSA, 2048)
		
		# Set up and sign CA certificate
		ca = crypto.X509()
		ca.set_version(3)
		ca.set_serial_number(1)
		ca.get_subject().CN = "CA"
		ca.get_subject().O = cert_org
		ca.get_subject().OU = cert_ou
		ca.gmtime_adj_notBefore(0)
		ca.gmtime_adj_notAfter(expiry_seconds)
		ca.set_issuer(ca.get_subject())
		ca.set_pubkey(key)
		ca.add_extensions([
			crypto.X509Extension(b"basicConstraints", True,	b"CA:TRUE, pathlen:0"),
			crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
			crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca)
		])
		ca.sign(key, "sha256")
	
		# Create key directory if it doesn't exist
		if not path.exists(key_dir):
			makedirs(key_dir)
		
		# Write CA certificate to file
		self._write_cert_to_file(ca, self.key_dir + '/ca.crt')
	
		# Write CA key to file
		self._write_key_to_file(key, self.key_dir + '/ca.key')
		
	def gen_cert(self, cert_name, cert_org=False, cert_ou=False, usage=3, days=3650, alt_names=[]):
		# usage: 1=ca, 2=server, 3=client
		if cert_name == "":
			raise Exception("Certificate name cannot be blank")
		
		# Load CA certificate
		ca_cert = self._load_cert_from_file(self.key_dir + '/ca.crt')
		
		# Load CA key
		ca_key = self._load_key_from_file(self.key_dir + '/ca.key')
		
		# Generate new key
		key = self._gen_key()
		
		# Create CSR
		req = self._create_csr(cert_name, key)
		
		# Sign CSR
		cert = self._sign_csr(req, ca_key, ca_cert, cert_org=cert_org, cert_ou=cert_ou, usage=usage, days=days, alt_names=alt_names)
		
		# Write new key file
		self._write_key_to_file(key, self.key_dir + '/' + cert_name + '.key')
		
		# Write new certificate file
		self._write_cert_to_file(cert, self.key_dir + '/' + cert_name + '.crt')
	
	def gen_pfx(self, cert_name):
		if cert_name == "":
			raise Exception("Certificate name cannot be blank")
		
		# Load CA certificate
		ca_cert = self._load_cert_from_file(self.key_dir + '/ca.crt')
		
		# Load Certificate
		cert = self._load_cert_from_file(self.key_dir + '/' + cert_name + '.crt')
		
		# Load Private Key
		key = self._load_key_from_file(self.key_dir + '/' + cert_name + '.key')
		
		# Set up PKCS12 structure
		pkcs12 = crypto.PKCS12()
		pkcs12.set_ca_certificates([ca_cert])
		pkcs12.set_certificate(cert)
		pkcs12.set_privatekey(key)
		
		# Write PFX file
		self._write_pfx_to_file(pkcs12, self.key_dir + '/' + cert_name + '.pfx')
		
	def gen_csr(self, name, out_dir):
		key = self._gen_key()
		csr = self._create_csr(name, key)
		self._write_key_to_file(key, out_dir + '/' + name + '.key')
		self._write_csr_to_file(csr, out_dir + '/' + name + '.csr')
	
	def sign_csr(self, csr_path):
		csr = self._load_csr_from_file(csr_path)
		ca_key = self._load_key_from_file(key_dir + '/ca.key')
		ca_cert = self._load_cert_from_file(key_dir + '/ca.crt')
		cert = self._sign_csr(csr, ca_key, ca_cert)
		self._write_cert_to_file(cert, self.key_dir + '/' + csr.get_subject().CN + '.crt')
	
	def revoke_cert(self, cert_name):
		# Load CA certificate
		ca_cert = self._load_cert_from_file(self.key_dir + '/ca.crt')
		
		# Load CA Key
		ca_key = self._load_key_from_file(self.key_dir + '/ca.key')
		
		# Load Certificate
		cert = self._load_cert_from_file(self.key_dir + '/' + cert_name + '.crt')
		
		# Load Private Key
		key = self._load_key_from_file(self.key_dir + '/' + cert_name + '.key')
		
		# Load CRL File
		crl = self._load_crl_from_file(self.key_dir + '/crl.pem')
		
		print ('Revoking ' + cert_name + ' (Serial: ' + str(cert.get_serial_number()) + ')')
		
		# Revoke certificate
		revoked = crypto.Revoked()
		revoked.set_serial(hex(int(cert.get_serial_number()))[2:].encode("utf-8"))
		revoked.set_reason(b'unspecified')
		revoked.set_rev_date(datetime.utcnow().strftime('%Y%m%d%H%M%SZ').encode("utf-8"))
		crl.add_revoked(revoked)
		
		# Write CRL file
		self._write_crl_to_file(crl, ca_cert, ca_key, key_dir + '/crl.pem')
		
		# Update index file
		index_file = open(key_dir + '/index.txt', 'r')
		index_file_new = open(key_dir + '/index.txt.new', 'w')
		
		for line in index_file.readlines():
			line_split = re.split('\t', line)
			if int(line_split[3], 16) == cert.get_serial_number():
				new_line = 'R\t' + line_split[1] + '\t' + revoked.get_rev_date().decode("utf-8") + '\t' + line_split[3] + '\t' + line_split[4] + '\t' + line_split[5]
				index_file_new.write(new_line)
			else:
				index_file_new.write(line)
			
		index_file.close()
		index_file_new.close()
		
		copy('keys/index.txt.new', 'keys/index.txt')
		remove('keys/index.txt.new')
	
	def renew_crl(self):
		# Load CA certificate
		ca_cert = self._load_cert_from_file(self.key_dir + '/ca.crt')
		
		# Load CA key
		ca_key = self._load_key_from_file(self.key_dir + '/ca.key')
		
		# Load CRL File
		crl = self._load_crl_from_file(self.key_dir + '/crl.pem')
		
		# Write CRL file
		self._write_crl_to_file(crl, ca_cert, ca_key, key_dir + '/crl.pem')

if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(description='SSL Certificate Generator')

	arg_group = parser.add_mutually_exclusive_group()
	arg_group.add_argument('--ca', action='store_true', help='Generate a CA certificate')
	arg_group.add_argument('--intermediate-ca', action='store_true', help='Generate an intermediate ca certificate')
	arg_group.add_argument('--server', action='store_true', help='Generate a server certificate')
	arg_group.add_argument('--client', action='store_true', help='Generate a client certificate')
	arg_group.add_argument('--pfx', action='store_true', help='Generate a PFX File')
	arg_group.add_argument('--revoke', action='store_true', help='Revoke a certificate')
	arg_group.add_argument('--renew-crl', action='store_true', help='Renew CRL')

	parser.add_argument('--cert-name', help='Certificate name (required with --server, --client, and --pfx)')
	parser.add_argument('--cert-org', help='Certificate organization (required with --ca)')
	parser.add_argument('--cert-ou', help='Certificate organizational unit (required with --ca)')
	parser.add_argument('--alt-name', help='Subject Alternative Name', action='append')

	args = parser.parse_args()
	
	sslgen = SSLCertificateGenerator()
	
	if args.ca:
		error=False
		if args.cert_name:
			print('Error: Certificate name was specified.  CA certificate is always named "ca"')
			error=True
		if not args.cert_ou:
			print("Error: No OU specified")
			error=True
		if not args.cert_org:
			print("Error: No organization specified")
			error=True
		if error:
			exit(1)

		sslgen.gen_ca(cert_org=args.cert_org, cert_ou=args.cert_ou)
		
	elif args.intermediate_ca:
		if not args.cert_name:
			print("Error: No certificate name specified")
			exit(1)
		
		sslgen.gen_cert(args.cert_name, cert_org=args.cert_org, cert_ou=args.cert_ou, usage=1)

	elif args.server:
		if not args.cert_name:
			print("Error: No certificate name specified")
			exit(1)

		sslgen.gen_cert(args.cert_name, cert_org=args.cert_org, cert_ou=args.cert_ou, usage=2, alt_names=args.alt_name)

	elif args.client:
		if not args.cert_name:
			print("Error: No certificate name specified")
			exit(1)

		sslgen.gen_cert(args.cert_name, cert_org=args.cert_org, cert_ou=args.cert_ou, usage=3, alt_names=args.alt_name)
	
	elif args.pfx:
		if not args.cert_name:
			print("Error: No certificate name specified")
			exit(1)
		
		sslgen.gen_pfx(args.cert_name)
	
	elif args.revoke:
		if not args.cert_name:
			print("Error: No certificate name specified")
			exit(1)
		
		sslgen.revoke_cert(args.cert_name)
			
	elif args.renew_crl:
		sslgen.renew_crl()

	else:
		print("Error: Certificate type must be specified using [--ca|--server|--client|--pfx]")
		exit(1)
