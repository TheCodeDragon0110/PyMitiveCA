import os

import pytest
import requests

# Port 8000 (dawny bezpośredni dostęp do serwera deweloperskiego Django)
# teraz tylko przekierowuje na HTTPS (patrz deploy/nginx/conf.d/pymitiveca.conf),
# więc testy łączą się z aplikacją przez nginx+TLS, tak jak realny ruch.
BASE_URL = "https://localhost"

# Certyfikat serwera jest wystawiony przez lokalne CA projektu
# (deploy/nginx/generate-ca-chain.sh) - ufamy mu przez CA_BUNDLE zamiast
# wyłączać weryfikację TLS (verify=False).
CA_BUNDLE = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "deploy", "nginx", "certs", "rootCA.pem")
)


@pytest.fixture(autouse=True)
def _default_https_verification(monkeypatch):
    '''
    Wstrzykuje domyślny CA_BUNDLE do każdego requests.get/post w testach,
    żeby nie trzeba było powtarzać `verify=CA_BUNDLE` w każdym wywołaniu.
    '''
    if not os.path.isfile(CA_BUNDLE):
        pytest.skip(
            f"Brak {CA_BUNDLE} - wygeneruj łańcuch certyfikatów przed testami: "
            "./deploy/nginx/generate-ca-chain.sh"
        )

    original_request = requests.Session.request

    def patched_request(self, method, url, *args, **kwargs):
        kwargs.setdefault("verify", CA_BUNDLE)
        return original_request(self, method, url, *args, **kwargs)

    monkeypatch.setattr(requests.Session, "request", patched_request)
