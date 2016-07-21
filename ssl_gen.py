from OpenSSL import crypto
from os import path,makedirs, remove
from datetime import datetime
import re
from shutil import copy

key_dir=path.dirname(path.realpath(__file__)) + "/keys"
key_dir=key_dir.replace('\\','/')
index_file = key_dir + '/index.txt'

def _get_cert_dn(cert):
	dn = ''
	for label, value in cert.get_subject().get_components():
		dn += '/' + label + '=' + value
	
	return dn
	

def gen_ca(cert_org="Thinkbox Software", cert_ou="IT", days = 3650):
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
	cert = crypto.dump_certificate(crypto.FILETYPE_PEM, ca)
	ca_cert_file = open(key_dir + '/ca.crt', 'w')
	ca_cert_file.write(cert.decode("utf-8"))
	ca_cert_file.close()

	# Write CA key to file
	key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
	ca_key_file = open(key_dir + '/ca.key', 'w')
	ca_key_file.write(key.decode("utf-8"))
	ca_key_file.close()
	
def gen_cert(cert_name, cert_org=False, cert_ou=False, usage=3, days=3650, alt_names=[]):
	# usage: 1=ca, 2=server, 3=client
	if cert_name == "":
		raise Exception("Certificate name cannot be blank")
	
	expiry_seconds = days * 86400
	
	try:
		serial_file = open(key_dir + '/serial', 'r')
		serial = int(serial_file.readline());
		serial_file.close
	except IOError:
		serial = 1
	
	# Load CA certificate
	ca_cert_file = open(key_dir + '/ca.crt', 'r')
	ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_file.read())
	ca_cert_file.close()
	
	# Load CA key
	ca_key_file = open(key_dir + '/ca.key', 'r')
	ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key_file.read())
	ca_key_file.close()
	
	# Generate new key
	key = crypto.PKey()
	key.generate_key(crypto.TYPE_RSA, 2048)
	
	# Create CSR
	req = crypto.X509Req()
	req.get_subject().CN = cert_name
	req.set_pubkey(key)
	req.sign(key, "sha256")
	
	# Sign CSR
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
	cert.set_serial_number(serial)
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
	
	# Write new key file
	key_file = open(key_dir + '/' + cert_name + '.key', 'w')
	key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("utf-8"))
	key_file.close()
	
	# Write new certificate file
	cert_file = open(key_dir + '/' + cert_name + '.crt', 'w')
	cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
	cert_file.close()
	
	# Write to index.txt
	db_line = "V\t" + cert.get_notBefore().decode("utf-8") + "\t\t" + hex(int(cert.get_serial_number())) + "\tunknown\t" + str(cert.get_subject())[18:-2] + "\n"
	index_file = open(key_dir + '/index.txt', 'a')
	index_file.write(db_line)
	index_file.close()
	
	# Write updated serial file
	serial_file = open(key_dir + '/serial', 'w')
	serial_file.write(str(serial + 1))
	serial_file.close()

def gen_pfx(cert_name):
	if cert_name == "":
		raise Exception("Certificate name cannot be blank")
	
	# Load CA certificate
	ca_cert_file = open(key_dir + '/ca.crt', 'r')
	ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_file.read())
	ca_cert_file.close()
	
	# Load Certificate
	cert_file = open(key_dir + '/' + cert_name + '.crt', 'r')
	cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
	cert_file.close()
	
	# Load Private Key
	key_file = open(key_dir + '/' + cert_name + '.key', 'r')
	key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read())
	key_file.close()
	
	# Set up PKCS12 structure
	pkcs12 = crypto.PKCS12()
	pkcs12.set_ca_certificates([ca_cert])
	pkcs12.set_certificate(cert)
	pkcs12.set_privatekey(key)
	
	# Write PFX file
	pkcs12_file=open(key_dir + '/' + cert_name + '.pfx', 'w')
	pkcs12_file.write(str(pkcs12.export()))
	pkcs12_file.close()

def revoke_cert(cert_name):
	# Load CA certificate
	ca_cert_file = open(key_dir + '/ca.crt', 'r')
	ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_file.read())
	ca_cert_file.close()
	
	# Load CA key
	ca_key_file = open(key_dir + '/ca.key', 'r')
	ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key_file.read())
	ca_key_file.close()
	
	# Load Certificate
	cert_file = open(key_dir + '/' + cert_name + '.crt', 'r')
	cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
	cert_file.close()
	
	# Load Private Key
	key_file = open(key_dir + '/' + cert_name + '.key', 'r')
	key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read())
	key_file.close()
	
	# Load CRL File
	try:
		crl_file = open(key_dir + '/crl.pem', 'r')
		crl = crypto.load_crl(crypto.FILETYPE_PEM, crl_file.read())
		crl_file.close()
	except IOError:
		# Create new CRL file if it doesn't exist
		crl = crypto.CRL()
	
	print ('Revoking ' + cert_name + ' (Serial: ' + str(cert.get_serial_number()) + ')')
	
	# Revoke certificate
	revoked = crypto.Revoked()
	revoked.set_serial(hex(int(cert.get_serial_number()))[2:].encode("utf-8"))
	revoked.set_reason(b'unspecified')
	revoked.set_rev_date(datetime.utcnow().strftime('%Y%m%d%H%M%SZ').encode("utf-8"))
	crl.add_revoked(revoked)
	
	# Write CRL file
	crl_file = open(key_dir + '/crl.pem', 'w')
	crl_file.write(crl.export(ca_cert, ca_key, days=365).decode("utf-8"))
	crl_file.close()
	
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

def renew_crl():
	# Load CA certificate
	ca_cert_file = open(key_dir + '/ca.crt', 'r')
	ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_file.read())
	ca_cert_file.close()
	
	# Load CA key
	ca_key_file = open(key_dir + '/ca.key', 'r')
	ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key_file.read())
	ca_key_file.close()
	
	# Load CRL file
	try:
		crl_file = open(key_dir + '/crl.pem', 'r')
		crl = crypto.load_crl(crypto.FILETYPE_PEM, crl_file.read())
		crl_file.close()
	except IOError:
		# Create new CRL file if it doesn't exist
		crl = crypto.CRL()
	
	# Write CRL file
	crl_file = open(key_dir + '/crl.pem', 'w')
	crl_file.write(crl.export(ca_cert, ca_key, days=365).decode("utf-8"))
	crl_file.close()

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

		gen_ca(cert_org=args.cert_org, cert_ou=args.cert_ou)
		
	elif args.intermediate_ca:
		if not args.cert_name:
			print("Error: No certificate name specified")
			exit(1)
		
		gen_cert(args.cert_name, cert_org=args.cert_org, cert_ou=args.cert_ou, usage=1)

	elif args.server:
		if not args.cert_name:
			print("Error: No certificate name specified")
			exit(1)

		gen_cert(args.cert_name, cert_org=args.cert_org, cert_ou=args.cert_ou, usage=2, alt_names=args.alt_name)

	elif args.client:
		if not args.cert_name:
			print("Error: No certificate name specified")
			exit(1)

		gen_cert(args.cert_name, cert_org=args.cert_org, cert_ou=args.cert_ou, usage=3)
	
	elif args.pfx:
		if not args.cert_name:
			print("Error: No certificate name specified")
			exit(1)
		
		gen_pfx(args.cert_name)
	
	elif args.revoke:
		if not args.cert_name:
			print("Error: No certificate name specified")
			exit(1)
		
		revoke_cert(args.cert_name)
			
	elif args.renew_crl:
		renew_crl()

	else:
		print("Error: Certificate type must be specified using [--ca|--server|--client|--pfx]")
		exit(1)
