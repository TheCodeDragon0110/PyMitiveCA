import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

'''
Przykład pobiera certyfikat z serwera i odczytuje
DN issuera i subjecta, klucz publiczny i algorytm hashowania podpisu. 
'''

url = "http://localhost:8000/get_cert/"
data = [
    {
        "fingerprint": "bf7947482932f212e8edb425274499885a57a478abc63557ffab803539360049",
        "serial": "1769461001946839"
    },
    {
        "serial": "1769461001946839",
    }
]
for _ in range(len(data)):
    response = requests.get(url, params=data[_])

    if response.status_code == 200:
        cert_pem = response.text
        with open(f"my_cert_{_}.pem", "w") as f:
            f.write(cert_pem)
        print(f"Certyfikat zapisany do my_cert_{_}.pem")

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