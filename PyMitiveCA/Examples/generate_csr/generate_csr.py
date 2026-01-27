import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

'''
Przykład generuje csr na serwerze, pobiera go i odczytuje
DN, klucz publiczny i algorytm hashowania podpisu. 
'''

url = "http://localhost:8000/generate_csr/"
data = {
    "dn": "CN=Jan Kowalski,O=MyOrg,C=PL",
    "valid_days": 365
}

response = requests.post(url, data=data)

if response.status_code == 200:
    csr_pem = response.text
    with open("my_csr.pem", "w") as f:
        f.write(csr_pem)
    print("CSR zapisany do my_csr.pem")

    csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'), default_backend())
    print(csr.subject)
    public_key = csr.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(public_pem.decode("utf-8"))
    print(csr.signature_hash_algorithm.name)

else:
    print("Błąd:", response.status_code, response.text)


