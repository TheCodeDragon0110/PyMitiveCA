import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


'''
Przykład odwołuje jeden z certyfikatów i pobiera CRL z bazy
i wyświetla listę odwołanych cetyfikatów. 
'''

url = "http://localhost:8000/revoke/"
data = [
    {
        "fingerprint": "bf7947482932f212e8edb425274499885a57a478abc63557ffab803539360049",
    },
    {
        "serial": "1769461061043067",
    }
]
for _ in range(len(data)):
    response = requests.get(url, params=data[_])

    if response.status_code == 200:
        print("Cert revoked.")
    else:
        print("Błąd:", response.status_code, response.text)

url = "http://localhost:8000/get_crl/"
response = requests.get(url)

if response.status_code == 200:
    crl_pem = response.text
    crl = x509.load_pem_x509_crl(crl_pem.encode('utf-8'), default_backend())
    print([revoked_cert.serial_number for revoked_cert in crl])
else:
    print("Błąd:", response.status_code, response.text)
