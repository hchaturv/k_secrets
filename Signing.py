#!/bin/python
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
import datetime

def write_to_file(typ, buffer):
	if typ == 'cert':
		fp = open("./CACert.pem","wb")
		fp.write(buffer.public_bytes(serialization.Encoding.PEM))
		fp.close()
		return

def cert_gen():
	one_day = datetime.timedelta(1,0,0)
	private_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048, backend = default_backend())
	public_key = private_key.public_key()
	builder = x509.CertificateBuilder()
	builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'harsh.c')]))
	builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'harsh.c')]))
	builder = builder.not_valid_before(datetime.datetime.today() - one_day)
	builder = builder.not_valid_after(datetime.datetime(2017,10,1))
	builder = builder.serial_number(x509.random_serial_number())
	builder = builder.public_key(public_key)
	#builder = builder.add_extentsion(x509.SubjectAlternativeName([x509.DNSName()]))
	certificate = builder.sign(private_key=private_key,algorithm=hashes.SHA512(),backend=default_backend())
	write_to_file('cert',certificate)
	return

def gen_key():
	key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048, backend = default_backend())
	with open("./test_priv_key_cust.pem","wb") as fp:
		fp.write(key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.TraditionalOpenSSL,
		encryption_algorithm=serialization.BestAvailableEncryption(b"test")))

def cert_sign_req():
	csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
		x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
		x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
		x509.NameAttribute(NameOID.LOCALITY_NAME, u"SANTA CLARA"),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"TEST CO"),
		x509.NameAttribute(NameOID.COMMON_NAME, u"test.co"),
		])).add_extension(
			x509.SubjectAlternativeName([
			x509.DNSName(b"test.co"),
			x509.DNSName(b"www.test.co"),
			x509.DNSName(b"subdomain.test.co")]),
			critical=False,
			).sign(key,hashes.SHA512(),default_backend())
	with open("./my_test_cert.pem","wb") as f:
		f.write(csr.public_bytes(serialization.Encoding.PEM))

cert_gen()