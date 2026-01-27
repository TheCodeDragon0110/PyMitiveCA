import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa


'''
Przykład generuje CSR i wysyła go na serwer w celu wystawienia certyfikatu. 
Nowy certyfikat jest pobierany i odczytywany.
DN issuera i subjecta, klucz publiczny i algorytm hashowania podpisu. 
'''

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

with open("my_private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  # lub z hasłem
    ))

csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "PL"),
    x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "MyOrg"),
    x509.NameAttribute(x509.NameOID.COMMON_NAME, "Jan Kowalski"),
])).sign(private_key, hashes.SHA256())


with open("my_csr.pem", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))

with open("my_csr.pem") as f:
    csr_pem = f.read()

url = "http://localhost:8000/issue_cert/"
data = {
    "csr_pem": csr_pem,
}

response = requests.post(url, data=data)

if response.status_code == 200:
    cert_pem = response.text
    with open("my_cert.pem", "w") as f:
        f.write(cert_pem)
    print("Certyfikat zapisany do my_cert.pem")

    cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
    print(cert.subject)
    print(cert.issuer)
    public_key = cert.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(public_pem.decode("utf-8"))
    print(cert.signature_hash_algorithm.name)

else:
    print("Błąd:", response.status_code, response.text)


