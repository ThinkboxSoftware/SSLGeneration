from OpenSSL import crypto
from os import path,makedirs

key_dir=path.dirname(path.realpath(__file__)) + "/keys"

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
		crypto.X509Extension("basicConstraints", True, "CA:TRUE, pathlen:0"),
		crypto.X509Extension("keyUsage", True, "keyCertSign, cRLSign"),
		crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=ca)
	])
	ca.sign(key, "sha1")

	# Create key directory if it doesn't exist
	if not path.exists(key_dir):
		makedirs(key_dir)
	
	# Write CA certificate to file
	cert = crypto.dump_certificate(crypto.FILETYPE_PEM, ca)
	ca_cert_file = open(key_dir + '/ca.crt', 'w')
	ca_cert_file.write(cert)
	ca_cert_file.close()

	# Write CA key to file
	key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
	ca_key_file = open(key_dir + '/ca.key', 'w')
	ca_key_file.write(key)
	ca_key_file.close()
	
def gen_cert(cert_name, cert_org=False, cert_ou=False, server=False, days=3650):
	if cert_name == "":
		raise Exception("Certificate name cannot be blank")
	
	expiry_seconds = days * 86400
	
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
	req.sign(key, "sha1")
	
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
	cert.set_serial_number(1)
	cert.gmtime_adj_notBefore(0)
	cert.gmtime_adj_notAfter(expiry_seconds)
	cert.set_issuer(ca_cert.get_subject())
	cert.set_pubkey(req.get_pubkey())
	if server == True:
		cert.add_extensions([
			crypto.X509Extension("extendedKeyUsage", True, "serverAuth"),
		])
	else:
		cert.add_extensions([
			crypto.X509Extension("extendedKeyUsage", True, "clientAuth"),
		])
	cert.sign(ca_key, "sha1")
	
	# Write new key file
	key_file = open(key_dir + '/' + cert_name + '.key', 'w')
	key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
	key_file.close()
	
	# Write new certificate file
	cert_file = open(key_dir + '/' + cert_name + '.crt', 'w')
	cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
	cert_file.close()

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
	pkcs12_file.write(pkcs12.export())
	pkcs12_file.close()
	

if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(description='SSL Certificate Generator')

	arg_group = parser.add_mutually_exclusive_group()
	arg_group.add_argument('--ca', action='store_true', help='Generate a CA certificate')
	arg_group.add_argument('--server', action='store_true', help='Generate a server certificate')
	arg_group.add_argument('--client', action='store_true', help='Generate a client certificate')
	arg_group.add_argument('--pfx', action='store_true', help='Generate a PFX File')

	parser.add_argument('--cert-name', help='Certificate name (required with --server, --client, and --pfx)')
	parser.add_argument('--cert-org', help='Certificate organization (required with --ca')
	parser.add_argument('--cert-ou', help='Certificate organizational unit (required with --ca')

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

	elif args.server:
		if not args.cert_name:
			print("Error: No certificate name specified")
			exit(1)

		gen_cert(args.cert_name, cert_org=args.cert_org, cert_ou=args.cert_ou, server=True)

	elif args.client:
		if not args.cert_name:
			print("Error: No certificate name specified")
			exit(1)

		gen_cert(args.cert_name, cert_org=args.cert_org, cert_ou=args.cert_ou, server=False)
	
	elif args.pfx:
		if not args.cert_name:
			print("Error: No certificate name specified")
			exit(1)
		
		gen_pfx(args.cert_name)
			
	else:
		print("Error: Certificate type must be specified using [--ca|--server|--client|--pfx]")
		exit(1)
