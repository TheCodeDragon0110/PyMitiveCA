import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

'''
Przykład generuje certyfikat na serwerze, pobiera go i odczytuje
DN issuera i subjecta, klucz publiczny i algorytm hashowania podpisu. 
'''

url = "http://localhost:8000/generate_cert/"
data = {
    "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
    "valid_days": 365
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


