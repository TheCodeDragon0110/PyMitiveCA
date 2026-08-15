import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

'''
Przykład pobiera CSR-a i odczytuje
DN, klucz publiczny i algorytm hashowania podpisu. 
'''

url = "http://localhost:8000/get_csr/"
data = {
    "fingerprint": "4010ee636d96eb035adb76c3bc9327d439f0996952a8c6a6fd0edf83fe04301b",
}

response = requests.get(url, params=data)

if response.status_code == 200:
    csr_pem = response.text
    with open("my_csr1.pem", "w") as f:
        f.write(csr_pem)
    print("CSR zapisany do my_csr1.pem")

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


url = "http://localhost:8000/get_csr/"
data = {
    "id": "1",
}

response = requests.get(url, params=data)

if response.status_code == 200:
    csr_pem = response.text
    with open("my_csr2.pem", "w") as f:
        f.write(csr_pem)
    print("CSR zapisany do my_csr2.pem")

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