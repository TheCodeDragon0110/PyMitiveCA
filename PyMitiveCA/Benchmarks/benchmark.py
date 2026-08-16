#!/usr/bin/env python3
"""
Badanie wydajności endpointów PyMitiveCA.

Dla każdego endpointu i każdego wariantu algorytmu/parametru wykonuje
N (domyślnie 100) powtórzeń, mierząc:

* czas odpowiedzi - opóźnienie mierzone po stronie klienta, end-to-end
  (`time.perf_counter()` wokół pojedynczego żądania),
* rozmiar odpowiedzi w bajtach,
* zużycie zasobów procesu serwera (% CPU, RSS) w oknie czasowym danego
  żądania - patrz `ServerMonitor`. 100% CPU odpowiada pełnemu wykorzystaniu
  jednego rdzenia (jak w `top`). Działa tylko wtedy, gdy benchmark jest
  uruchamiany na tym samym hoście co `manage.py runserver` (tak jak w
  devcontainerze - patrz .devcontainer/nginx.conf). W środowisku
  produkcyjnym (docker-compose.prod.yml), gdzie aplikacja żyje w osobnym
  kontenerze, proces nie jest widoczny z hosta - monitor po prostu zgłasza
  się jako niedostępny i benchmark mierzy wyłącznie czas odpowiedzi.

Wyniki trafiają do katalogu wyjściowego (domyślnie
Benchmarks/results/<znacznik czasu>/):

* results_raw.csv     - jeden wiersz na pojedynczy pomiar,
* results_summary.csv - jeden wiersz na scenariusz (endpoint + wariant):
                         średnia i odchylenie standardowe każdej metryki
                         - to jest właściwy wynik badania,
* boxplot_latency_<endpoint>.png, boxplot_cpu_<endpoint>.png - rozkłady
  per scenariusz (plotnine/ggplot2; pomijane przy --no-plot).

Wymaga uruchomionego serwera (patrz README.md / deploy/README.md) -
domyślnie łączy się z https://localhost, tak jak PyMitiveCA/Tests/.

Przykłady:
    python benchmark.py                             # pełny przebieg, 100 powtórzeń
    python benchmark.py --repeats 10 --yes           # szybki przebieg próbny
    python benchmark.py --endpoints generate_cert,issue_cert
    python benchmark.py --algorithms RSA-2048,ED25519,ML-KEM-1024

Wymagane zależności (nie są częścią requirements.txt aplikacji - patrz
Benchmarks/requirements-benchmark.txt):
    pip install -r Benchmarks/requirements-benchmark.txt
"""
import argparse
import base64
import statistics
import sys
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone as dt_timezone
from pathlib import Path
from typing import Callable, Optional

import requests

# --- ścieżki projektu -------------------------------------------------
# Ten plik leży w <repo>/PyMitiveCA/Benchmarks/benchmark.py; PROJECT_DIR to
# <repo>/PyMitiveCA (zawiera manage.py, secrets.json i pakiet PyMitiveCA/).
BENCHMARKS_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BENCHMARKS_DIR.parent
REPO_ROOT = PROJECT_DIR.parent
sys.path.insert(0, str(PROJECT_DIR))

# keygen.py i crmf.py nie importują Django (patrz ich nagłówki) - można je
# więc użyć bezpośrednio, bez DJANGO_SETTINGS_MODULE, do lokalnego
# przygotowania kluczy/CSR/CRMF na potrzeby scenariuszy issue_cert/confirm_cert.
from PyMitiveCA import crmf, keygen  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.serialization import pkcs12  # noqa: E402
from cryptography.x509 import ocsp as x509_ocsp  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

import pandas as pd  # noqa: E402

try:
    import psutil
except ImportError:
    psutil = None


DN_STR = "CN=Benchmark,O=MyOrg,C=PL"
SUBJECT_NAME = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyOrg"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Benchmark"),
])

VALID_DAYS_VARIANTS = (30, 365, 3650)

ALL_ENDPOINTS = (
    "generate_cert", "generate_csr", "issue_cert", "confirm_cert",
    "get_cert", "cert_info", "get_csr", "ocsp", "revoke", "get_crl",
)

# Warianty, dla których każde powtórzenie generate_cert/generate_csr jest
# istotnie wolniejsze - używane tylko do ostrzeżenia przed długim przebiegiem.
SLOW_LABELS = ("RSA-4096", "RSA-8192")


@dataclass(frozen=True)
class AlgorithmVariant:
    label: str
    form: dict  # parametry POST dla generate_cert/generate_csr (bez "dn")


ALGORITHM_VARIANTS = (
    AlgorithmVariant("RSA-2048", {"algorithm": "RSA", "key_size": "2048"}),
    AlgorithmVariant("RSA-3072", {"algorithm": "RSA", "key_size": "3072"}),
    AlgorithmVariant("RSA-4096", {"algorithm": "RSA", "key_size": "4096"}),
    AlgorithmVariant("RSA-8192", {"algorithm": "RSA", "key_size": "8192"}),
    AlgorithmVariant("ECDSA-secp256r1", {"algorithm": "ECDSA", "curve": "secp256r1"}),
    AlgorithmVariant("ECDSA-secp384r1", {"algorithm": "ECDSA", "curve": "secp384r1"}),
    AlgorithmVariant("ECDSA-secp521r1", {"algorithm": "ECDSA", "curve": "secp521r1"}),
    AlgorithmVariant("ECDSA-secp256k1", {"algorithm": "ECDSA", "curve": "secp256k1"}),
    AlgorithmVariant("ED25519", {"algorithm": "ED25519"}),
    AlgorithmVariant("ML-KEM-768", {"algorithm": "ML-KEM", "key_size": "768"}),
    AlgorithmVariant("ML-KEM-1024", {"algorithm": "ML-KEM", "key_size": "1024"}),
)


@dataclass
class Scenario:
    endpoint: str
    label: str
    repeats: int
    # `call(i)` wykonuje i mierzy dokładnie JEDNO żądanie HTTP (i-te
    # powtórzenie, 0-indeksowane) - cały setup potrzebny do jego zbudowania
    # musi być już gotowy (patrz build_scenarios).
    call: Callable[[int], requests.Response]


# --- monitor zasobów serwera -------------------------------------------

class ServerMonitor:
    """
    Najlepszej-jakości (best-effort) próbkowanie zużycia CPU/RAM procesu
    serwera Django - patrz nagłówek modułu. Jeżeli proces nie zostanie
    znaleziony (inny host, brak psutil, docker-compose.prod.yml), `available`
    jest False i wszystkie metody zwracają None - benchmark działa dalej,
    po prostu bez tych kolumn.
    """

    def __init__(self, port: Optional[int]):
        self._process = None
        self._warned = False
        if psutil is None or port is None:
            return
        try:
            for conn in psutil.net_connections(kind="tcp"):
                if conn.status == psutil.CONN_LISTEN and conn.laddr and conn.laddr.port == port and conn.pid:
                    self._process = psutil.Process(conn.pid)
                    break
        except (psutil.AccessDenied, PermissionError):
            pass
        if self._process is not None:
            # Pierwsze wywołanie cpu_percent() tylko ustawia punkt odniesienia
            # (zwraca % zużyty od startu procesu, co nas nie interesuje) -
            # patrz cpu_percent() niżej.
            self._safe(lambda: self._process.cpu_percent(interval=None))

    @property
    def available(self) -> bool:
        return self._process is not None

    def _safe(self, fn):
        try:
            return fn()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            if not self._warned:
                print("  UWAGA: proces serwera zniknął w trakcie pomiaru - "
                      "dalsze próbkowanie zasobów wyłączone.")
                self._warned = True
            self._process = None
            return None

    def cpu_percent(self) -> Optional[float]:
        """
        Procent CPU zużyty przez proces serwera MIĘDZY tym a POPRZEDNIM
        wywołaniem tej metody (semantyka psutil.Process.cpu_percent(interval=None)
        przy naprzemiennym wywoływaniu - patrz jej dokumentacja). timed_call()
        wywołuje ją dokładnie dwa razy na żądanie (tuż przed i tuż po), więc
        drugie wywołanie zwraca średnie zużycie CPU w oknie tego żądania.
        100% odpowiada pełnemu wykorzystaniu jednego rdzenia (jak w `top`) -
        przy żądaniach obsługiwanych wielowątkowo wartość może przekroczyć 100%.
        """
        if not self.available:
            return None
        return self._safe(lambda: self._process.cpu_percent(interval=None))

    def rss_kb(self) -> Optional[float]:
        if not self.available:
            return None
        return self._safe(lambda: self._process.memory_info().rss / 1024)


def timed_call(monitor: ServerMonitor, request_fn: Callable[[], requests.Response]) -> dict:
    """Wykonuje jedno żądanie i zwraca wszystkie zmierzone metryki jako dict."""
    monitor.cpu_percent()  # zeruje punkt odniesienia tuż przed startem żądania
    rss0 = monitor.rss_kb()
    t0 = time.perf_counter()
    try:
        response = request_fn()
        elapsed = time.perf_counter() - t0
        status_code = response.status_code
        ok = 200 <= status_code < 300
        response_bytes = len(response.content)
    except requests.RequestException as exc:
        elapsed = time.perf_counter() - t0
        status_code = None
        ok = False
        response_bytes = 0
        print(f"    BŁĄD żądania: {exc}")
    server_cpu_percent = monitor.cpu_percent()  # % CPU zużyty MIĘDZY powyższymi dwoma wywołaniami
    rss1 = monitor.rss_kb()
    return {
        "latency_s": elapsed,
        "ok": ok,
        "status_code": status_code,
        "response_bytes": response_bytes,
        "server_cpu_percent": server_cpu_percent,
        "server_rss_kb": rss1,
        "server_rss_delta_kb": (rss1 - rss0) if (rss0 is not None and rss1 is not None) else None,
    }


# --- pomocnicze budowanie CSR/CRMF/OCSP lokalnie (bez Django) -----------

def _build_signing_request(variant: AlgorithmVariant) -> dict:
    """
    Buduje dane POST dla issue_cert/ (csr_pem albo crmf_pem) dla danego
    wariantu - klucz jest generowany RAZ, lokalnie, poza mierzonym oknem
    czasowym, bo issue_cert/ ma mierzyć koszt podpisania/obsłużenia
    żądania przez CA, a nie koszt generacji klucza (ten mierzy już
    generate_cert/generate_csr).
    """
    if variant.label.startswith("ML-KEM"):
        key_size = int(variant.form["key_size"])
        private_key = keygen.ML_KEM_VARIANTS[key_size].generate()
        crmf_pem = crmf.build_crmf_request_pem(SUBJECT_NAME, private_key.public_key())
        return {"crmf_pem": crmf_pem}

    algorithm = variant.form["algorithm"]
    key_size = variant.form.get("key_size")
    curve = variant.form.get("curve")
    private_key, _resolved_size, _resolved_curve = keygen.generate_keypair(algorithm, key_size, curve)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(SUBJECT_NAME)
        .sign(private_key, keygen.signing_hash_algorithm(private_key))
    )
    return {"csr_pem": csr.public_bytes(serialization.Encoding.PEM)}


def _build_kem_pop_pool(session, base_url, variant, count, timeout):
    """
    Przygotowuje `count` niezależnych par (fingerprint, private_key_pem) do
    confirm_cert/ - w odróżnieniu od issue_cert/get_cert/itd. ten endpoint
    KONSUMUJE stan (pop_pending -> False po pierwszym udanym potwierdzeniu,
    kolejne wywołania na tym samym certyfikacie kończą się błędem 400 bez
    wykonania realnej pracy), więc każde z 100 powtórzeń musi operować na
    OSOBNYM certyfikacie oczekującym na POP.
    """
    key_size = int(variant.form["key_size"])
    pool = []
    for _ in range(count):
        private_key = keygen.ML_KEM_VARIANTS[key_size].generate()
        crmf_pem = crmf.build_crmf_request_pem(SUBJECT_NAME, private_key.public_key())
        response = session.post(f"{base_url}/issue_cert/", data={"crmf_pem": crmf_pem}, timeout=timeout)
        response.raise_for_status()
        fingerprint = response.json()["fingerprint"]
        private_key_pem = private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
        ).decode("utf-8")
        pool.append((fingerprint, private_key_pem))
    return pool


def _issue_reference_cert(session, base_url, variant, timeout) -> dict:
    """Wystawia certyfikat referencyjny (jeden na wariant) do scenariuszy odczytu."""
    response = session.post(f"{base_url}/generate_cert/", data={"dn": DN_STR, **variant.form}, timeout=timeout)
    response.raise_for_status()
    cert = x509.load_pem_x509_certificate(response.content)
    return {
        "serial": str(cert.serial_number),
        "fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "certificate": cert,
    }


def _issue_reference_csr(session, base_url, variant, timeout) -> dict:
    """Wystawia żądanie CSR referencyjne (jedno na wariant) do get_csr/."""
    response = session.post(f"{base_url}/generate_csr/", data={"dn": DN_STR, **variant.form}, timeout=timeout)
    response.raise_for_status()
    if variant.label.startswith("ML-KEM"):
        fingerprint = response.json()["fingerprint"]
    else:
        csr = x509.load_pem_x509_csr(response.content)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(csr.public_bytes(serialization.Encoding.DER))
        fingerprint = digest.finalize().hex()
    return {"fingerprint": fingerprint}


def _load_signing_ca_certificate() -> x509.Certificate:
    """
    Wczytuje certyfikat CA aplikacji z ca.p12 (ten sam, którym CA podpisuje
    certyfikaty i odpowiedzi OCSP) - potrzebny do zbudowania poprawnego
    OCSPRequest (issuer_name_hash/issuer_key_hash). To INNY certyfikat niż
    rootCA.pem z deploy/nginx/certs, który służy wyłącznie do TLS.
    """
    import json

    with open(PROJECT_DIR / "secrets.json") as secrets_file:
        secrets_data = json.load(secrets_file)

    p12_path = PROJECT_DIR / "PyMitiveCA" / secrets_data["CA_P12_PATH"]
    with open(p12_path, "rb") as p12_file:
        _key, ca_cert, _extra = pkcs12.load_key_and_certificates(
            p12_file.read(), secrets_data["CA_P12_PASSWORD"].encode()
        )
    return ca_cert


def _ocsp_der_request(ca_cert, cert, hash_algorithm) -> bytes:
    return (
        x509_ocsp.OCSPRequestBuilder()
        .add_certificate(cert, ca_cert, hash_algorithm)
        .build()
        .public_bytes(serialization.Encoding.DER)
    )


# --- budowanie scenariuszy ----------------------------------------------

def build_scenarios(session, base_url, repeats, algorithms_filter, endpoints_filter, timeout):
    """
    Przygotowuje pełną listę scenariuszy do zmierzenia. Zasada projektowa:
    setup, którego koszt NIE jest tym, co dany endpoint ma mierzyć (np.
    generacja klucza przed pomiarem issue_cert/, które mierzy tylko
    podpisanie żądania), wykonuje się RAZ, poza mierzonym oknem czasowym -
    patrz komentarze przy poszczególnych blokach.
    """
    variants = [v for v in ALGORITHM_VARIANTS if not algorithms_filter or v.label in algorithms_filter]
    if not variants:
        raise SystemExit(
            f"Brak wariantów pasujących do --algorithms. Dostępne: "
            f"{', '.join(v.label for v in ALGORITHM_VARIANTS)}"
        )

    def wanted(endpoint):
        return endpoints_filter is None or endpoint in endpoints_filter

    scenarios = []
    reference_cert_cache = {}

    def reference_cert(variant):
        """Certyfikat referencyjny WSPÓLNY dla get_cert/cert_info/ocsp (czyste odczyty, bez skutków ubocznych)."""
        if variant.label not in reference_cert_cache:
            reference_cert_cache[variant.label] = _issue_reference_cert(session, base_url, variant, timeout)
        return reference_cert_cache[variant.label]

    # --- generate_cert/ i generate_csr/: KAŻDE powtórzenie robi pełny
    # keygen po stronie serwera - to jest dokładnie to, co te endpointy
    # mają liczyć, więc setup poza pętlą tu nie ma zastosowania.
    if wanted("generate_cert"):
        for v in variants:
            scenarios.append(Scenario(
                "generate_cert", v.label, repeats,
                lambda i, v=v: session.post(
                    f"{base_url}/generate_cert/", data={"dn": DN_STR, **v.form}, timeout=timeout
                ),
            ))
        if any(v.label == "RSA-2048" for v in variants):
            for days in VALID_DAYS_VARIANTS:
                scenarios.append(Scenario(
                    "generate_cert", f"RSA-2048-valid_days={days}", repeats,
                    lambda i, days=days: session.post(
                        f"{base_url}/generate_cert/",
                        data={"dn": DN_STR, "algorithm": "RSA", "key_size": "2048", "valid_days": str(days)},
                        timeout=timeout,
                    ),
                ))

    if wanted("generate_csr"):
        for v in variants:
            scenarios.append(Scenario(
                "generate_csr", v.label, repeats,
                lambda i, v=v: session.post(
                    f"{base_url}/generate_csr/", data={"dn": DN_STR, **v.form}, timeout=timeout
                ),
            ))

    # --- issue_cert/: klucz/CSR/CRMF wygenerowany RAZ lokalnie (setup) -
    # powtórne wysłanie TEGO SAMEGO csr_pem/crmf_pem jest bezpieczne (CA
    # nadaje nowy numer seryjny i sygnaturę czasową przy każdym podpisaniu,
    # a CertRequest jest po prostu aktualizowany - patrz update_or_create
    # w issue_cert/), więc mierzymy czysto koszt podpisania/zapisu, bez
    # powtarzania (drogiej dla RSA-8192) generacji klucza 100 razy.
    if wanted("issue_cert"):
        print("  przygotowanie CSR/CRMF do issue_cert/ ...")
        for v in variants:
            request_kwargs = _build_signing_request(v)
            scenarios.append(Scenario(
                "issue_cert", v.label, repeats,
                lambda i, kw=request_kwargs: session.post(f"{base_url}/issue_cert/", data=kw, timeout=timeout),
            ))

    # --- confirm_cert/: tylko warianty ML-KEM (jedyna ścieżka POP w tym
    # systemie). Endpoint konsumuje stan, więc każde powtórzenie dostaje
    # WŁASNY certyfikat pop_pending - patrz _build_kem_pop_pool.
    if wanted("confirm_cert"):
        kem_variants = [v for v in variants if v.label.startswith("ML-KEM")]
        if kem_variants:
            print("  przygotowanie certyfikatów pop_pending do confirm_cert/ ...")
        for v in kem_variants:
            pool = _build_kem_pop_pool(session, base_url, v, repeats, timeout)
            scenarios.append(Scenario(
                "confirm_cert", v.label, repeats,
                lambda i, pool=pool: session.post(
                    f"{base_url}/confirm_cert/",
                    data={"fingerprint": pool[i][0], "private_key_pem": pool[i][1]},
                    timeout=timeout,
                ),
            ))

    # --- get_cert/, cert_info/: czysty odczyt, bez skutków ubocznych -
    # JEDEN certyfikat referencyjny na wariant, używany we wszystkich
    # powtórzeniach (mierzymy koszt odczytu z bazy, nie generacji).
    if wanted("get_cert"):
        for v in variants:
            ref = reference_cert(v)
            scenarios.append(Scenario(
                "get_cert", v.label, repeats,
                lambda i, ref=ref: session.get(f"{base_url}/get_cert/", params={"serial": ref["serial"]}, timeout=timeout),
            ))

    if wanted("cert_info"):
        for v in variants:
            ref = reference_cert(v)
            scenarios.append(Scenario(
                "cert_info", v.label, repeats,
                lambda i, ref=ref: session.get(f"{base_url}/cert_info/", params={"serial": ref["serial"]}, timeout=timeout),
            ))

    if wanted("get_csr"):
        for v in variants:
            csr_ref = _issue_reference_csr(session, base_url, v, timeout)
            scenarios.append(Scenario(
                "get_csr", v.label, repeats,
                lambda i, ref=csr_ref: session.get(
                    f"{base_url}/get_csr/", params={"fingerprint": ref["fingerprint"]}, timeout=timeout
                ),
            ))

    # --- ocsp/: dla każdego wariantu - transport POST, SHA-1 (domyślny w
    # RFC 6960). Dodatkowo, na jednym reprezentatywnym certyfikacie
    # (RSA-2048), porównanie SHA-256 oraz transportu GET - odpowiedź
    # respondera zależy od klucza CA (zawsze ten sam), nie od algorytmu
    # certyfikatu podmiotu, więc pełna macierz 11 algorytmów x transport x
    # hash nie wniosłaby dodatkowej informacji.
    if wanted("ocsp"):
        ca_cert = _load_signing_ca_certificate()
        for v in variants:
            ref = reference_cert(v)
            der_request = _ocsp_der_request(ca_cert, ref["certificate"], hashes.SHA1())
            scenarios.append(Scenario(
                "ocsp", f"{v.label}-POST-sha1", repeats,
                lambda i, der=der_request: session.post(
                    f"{base_url}/ocsp/", data=der,
                    headers={"Content-Type": "application/ocsp-request"}, timeout=timeout,
                ),
            ))

        probe_variant = next((v for v in variants if v.label == "RSA-2048"), variants[0])
        probe_ref = reference_cert(probe_variant)

        der_sha256 = _ocsp_der_request(ca_cert, probe_ref["certificate"], hashes.SHA256())
        scenarios.append(Scenario(
            "ocsp", f"{probe_variant.label}-POST-sha256", repeats,
            lambda i, der=der_sha256: session.post(
                f"{base_url}/ocsp/", data=der,
                headers={"Content-Type": "application/ocsp-request"}, timeout=timeout,
            ),
        ))
        for hash_name, hash_algorithm in (("sha1", hashes.SHA1()), ("sha256", hashes.SHA256())):
            der_request = _ocsp_der_request(ca_cert, probe_ref["certificate"], hash_algorithm)
            encoded = urllib.parse.quote(base64.b64encode(der_request).decode("ascii"), safe="")
            get_url = f"{base_url}/ocsp/{encoded}"
            scenarios.append(Scenario(
                "ocsp", f"{probe_variant.label}-GET-{hash_name}", repeats,
                lambda i, url=get_url: session.get(url, timeout=timeout),
            ))

    # --- revoke/: OSOBNA pula certyfikatów (nie reference_cert()) - inaczej
    # unieważnilibyśmy certyfikaty używane przez get_cert/cert_info/ocsp i
    # zafałszowali te scenariusze. Uwaga: tylko PIERWSZE powtórzenie na
    # danym certyfikacie jest "prawdziwym" unieważnieniem - kolejne 99 to
    # wywołania idempotentne (Cert.Revoke() nadal wykonuje pełny odczyt +
    # zapis do bazy, ale nie zmienia już revoked_at/revocation_reason).
    # Osobna, świeża pula 100 certyfikatów per algorytm kosztowałaby przy
    # RSA-8192 dodatkowe ~100x18s, więc świadomie mierzymy koszt
    # endpointu (odczyt+zapis), a nie koszt "pierwszego unieważnienia".
    if wanted("revoke"):
        print("  przygotowanie certyfikatów do revoke/ ...")
        for v in variants:
            revoke_ref = _issue_reference_cert(session, base_url, v, timeout)
            scenarios.append(Scenario(
                "revoke", v.label, repeats,
                lambda i, ref=revoke_ref: session.get(
                    f"{base_url}/revoke/", params={"serial": ref["serial"], "reason": "unspecified"}, timeout=timeout
                ),
            ))

    # --- get_crl/: bezparametrowy, jeden scenariusz - serwer cache'uje
    # wygenerowaną listę, więc powtórzenia poza pierwszym trafiają w
    # ścieżkę odczytu z cache (patrz Crl.get_or_create_current_crl).
    if wanted("get_crl"):
        scenarios.append(Scenario(
            "get_crl", "default", repeats,
            lambda i: session.get(f"{base_url}/get_crl/", timeout=timeout),
        ))

    return scenarios


# --- pętla pomiarowa ------------------------------------------------------

def estimate_and_confirm(scenarios, skip_confirmation):
    slow = [
        s for s in scenarios
        if s.endpoint in ("generate_cert", "generate_csr") and any(lbl in s.label for lbl in SLOW_LABELS)
    ]
    total_requests = sum(s.repeats for s in scenarios)
    print(f"Do wykonania: {len(scenarios)} scenariuszy, {total_requests} żądań łącznie.")
    if slow:
        print(
            "UWAGA: warianty RSA-4096/RSA-8192 w generate_cert/ i generate_csr/ są "
            "znacznie wolniejsze niż pozostałe (RSA-8192 to ok. 15-20s NA POWTÓRZENIE "
            "po stronie serwera - 100 powtórzeń to ~25-35 minut NA SAM TEN SCENARIUSZ). "
            "Pełny przebieg wszystkich scenariuszy z domyślnymi ustawieniami może zająć "
            "ponad godzinę. Użyj --repeats, --algorithms albo --endpoints, żeby zawęzić "
            "zakres, albo --yes, żeby pominąć to potwierdzenie."
        )
        if not skip_confirmation:
            answer = input("Kontynuować mimo to? [y/N]: ").strip().lower()
            if answer != "y":
                print("Przerwano.")
                sys.exit(1)


def run_scenarios(scenarios, monitor):
    samples = []
    run_started = time.perf_counter()
    try:
        for idx, scenario in enumerate(scenarios, start=1):
            print(f"[{idx}/{len(scenarios)}] {scenario.endpoint}/ :: {scenario.label} ({scenario.repeats} powt.)")
            scenario_started = time.perf_counter()
            checkpoint = max(1, scenario.repeats // 4)
            for i in range(scenario.repeats):
                result = timed_call(monitor, lambda i=i: scenario.call(i))
                result["endpoint"] = scenario.endpoint
                result["scenario"] = scenario.label
                result["iteration"] = i
                result["timestamp_utc"] = datetime.now(dt_timezone.utc).isoformat()
                samples.append(result)
                if (i + 1) % checkpoint == 0 or i == scenario.repeats - 1:
                    print(f"    {i + 1}/{scenario.repeats}")
            scenario_elapsed = time.perf_counter() - scenario_started
            latencies = [
                s["latency_s"] for s in samples
                if s["endpoint"] == scenario.endpoint and s["scenario"] == scenario.label and s["ok"]
            ]
            if latencies:
                mean = statistics.fmean(latencies)
                sd = statistics.stdev(latencies) if len(latencies) > 1 else 0.0
                print(f"  -> latency: średnia={mean:.4f}s  sd={sd:.4f}s  (scenariusz zajął {scenario_elapsed:.1f}s)")
            else:
                print(f"  -> WSZYSTKIE {scenario.repeats} powtórzeń zakończyły się błędem")
    except KeyboardInterrupt:
        print("\nPrzerwano (Ctrl-C) - zapisuję dotychczasowe wyniki...")
    total_elapsed = time.perf_counter() - run_started
    print(f"\nZakończono w {total_elapsed / 60:.1f} min ({len(samples)} pomiarów).")
    return samples


# --- podsumowanie i zapis -------------------------------------------------

METRIC_COLUMNS = ("latency_s", "response_bytes", "server_cpu_percent", "server_rss_kb")


def summarize(raw_df: pd.DataFrame) -> pd.DataFrame:
    """
    Jeden wiersz na (endpoint, scenariusz): n, liczba błędów oraz
    średnia/odchylenie standardowe każdej metryki (liczone tylko po udanych
    żądaniach - błąd 400/404/500 nie należy do tego samego rozkładu co
    udany pomiar czasu generacji klucza).
    """
    def aggregate(group: pd.DataFrame) -> pd.Series:
        ok = group[group["ok"]]
        data = {"n_total": len(group), "n_errors": int((~group["ok"]).sum())}
        for column in METRIC_COLUMNS:
            values = ok[column].dropna()
            if len(values):
                data[f"{column}_mean"] = values.mean()
                data[f"{column}_sd"] = values.std() if len(values) > 1 else 0.0
            else:
                data[f"{column}_mean"] = None
                data[f"{column}_sd"] = None
        return pd.Series(data)

    summary = raw_df.groupby(["endpoint", "scenario"], sort=False).apply(
        aggregate, include_groups=False
    ).reset_index()
    return summary


def make_plots(raw_df: pd.DataFrame, output_dir: Path):
    from plotnine import ggplot, aes, geom_boxplot, labs, theme_bw, theme, element_text, scale_y_log10

    ok_df = raw_df[raw_df["ok"]]
    if ok_df.empty:
        print("  brak udanych pomiarów - pomijam boxploty.")
        return

    def boxplot(df, y_column, y_label, title_suffix, filename_prefix):
        for endpoint, group in df.groupby("endpoint"):
            scenario_count = group["scenario"].nunique()
            width = max(6.0, scenario_count * 0.9)
            plot = (
                ggplot(group, aes(x="scenario", y=y_column))
                + geom_boxplot(outlier_alpha=0.4)
                + labs(title=f"{endpoint}/ - {title_suffix}", x="Wariant (algorytm/parametr)", y=y_label)
                + theme_bw()
                + theme(axis_text_x=element_text(rotation=45, ha="right"), figure_size=(width, 5))
            )
            # Skala logarytmiczna tylko gdy WSZYSTKIE wartości są dodatnie
            # (log10(0) = -inf potrafi się zdarzyć przy server_cpu_percent -
            # rozdzielczość psutil.cpu_times() to ~10ms, więc bardzo krótkie
            # żądania często mierzą się jako dokładnie 0.0%) i rozstęp jest
            # duży - inaczej boxplot traci te punkty.
            min_value = group[y_column].min()
            max_value = group[y_column].max()
            if min_value > 0 and max_value / min_value > 50:
                plot = plot + scale_y_log10()
            out_path = output_dir / f"{filename_prefix}_{endpoint}.png"
            plot.save(out_path, dpi=150, verbose=False)
            print(f"  zapisano {out_path.name}")

    boxplot(ok_df, "latency_s", "Czas odpowiedzi [s]", "czas odpowiedzi", "boxplot_latency")

    cpu_df = ok_df.dropna(subset=["server_cpu_percent"])
    if not cpu_df.empty:
        boxplot(cpu_df, "server_cpu_percent", "Zużycie CPU serwera [%]", "zużycie CPU serwera na żądanie", "boxplot_cpu")
    else:
        print("  (monitor zasobów niedostępny - pomijam boxploty CPU)")


# --- CLI -------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Badanie wydajności endpointów PyMitiveCA.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--base-url", default="https://localhost")
    parser.add_argument("--ca-bundle", default=None, help="Ścieżka do rootCA.pem (domyślnie deploy/nginx/certs/rootCA.pem)")
    parser.add_argument("--insecure", action="store_true", help="Wyłącz weryfikację TLS zamiast używać --ca-bundle")
    parser.add_argument("--repeats", type=int, default=100, help="Liczba powtórzeń na scenariusz (domyślnie 100)")
    parser.add_argument("--timeout", type=float, default=120.0, help="Limit czasu pojedynczego żądania w sekundach")
    parser.add_argument("--endpoints", default=None, help=f"Lista po przecinku, spośród: {', '.join(ALL_ENDPOINTS)}")
    parser.add_argument("--algorithms", default=None, help=f"Lista po przecinku, spośród: {', '.join(v.label for v in ALGORITHM_VARIANTS)}")
    parser.add_argument("--output-dir", default=None, help="Domyślnie Benchmarks/results/<znacznik czasu>")
    parser.add_argument("--server-port", type=int, default=8001, help="Port lokalnego serwera Django do monitorowania zasobów")
    parser.add_argument("--no-resource-monitor", action="store_true")
    parser.add_argument("--no-plot", action="store_true")
    parser.add_argument("-y", "--yes", action="store_true", help="Nie pytaj o potwierdzenie przed długim przebiegiem")
    return parser.parse_args()


def main():
    args = parse_args()
    base_url = args.base_url.rstrip("/")

    output_dir = Path(args.output_dir) if args.output_dir else (
        BENCHMARKS_DIR / "results" / datetime.now().strftime("%Y%m%d_%H%M%S")
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    if args.insecure:
        session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    else:
        ca_bundle = Path(args.ca_bundle) if args.ca_bundle else REPO_ROOT / "deploy" / "nginx" / "certs" / "rootCA.pem"
        if not ca_bundle.is_file():
            sys.exit(
                f"Brak {ca_bundle} - wygeneruj łańcuch certyfikatów "
                f"(./deploy/nginx/generate-ca-chain.sh) albo uruchom z --insecure."
            )
        session.verify = str(ca_bundle)

    endpoints_filter = None
    if args.endpoints:
        endpoints_filter = set(args.endpoints.split(","))
        unknown = endpoints_filter - set(ALL_ENDPOINTS)
        if unknown:
            sys.exit(f"Nieznane endpointy: {', '.join(sorted(unknown))}. Dostępne: {', '.join(ALL_ENDPOINTS)}")

    algorithms_filter = None
    if args.algorithms:
        algorithms_filter = set(args.algorithms.split(","))
        known_labels = {v.label for v in ALGORITHM_VARIANTS}
        unknown = algorithms_filter - known_labels
        if unknown:
            sys.exit(f"Nieznane warianty: {', '.join(sorted(unknown))}. Dostępne: {', '.join(sorted(known_labels))}")

    if args.no_resource_monitor or psutil is None:
        if psutil is None and not args.no_resource_monitor:
            print("UWAGA: psutil nie jest zainstalowany - pomiar zużycia zasobów serwera wyłączony.")
        monitor = ServerMonitor(port=None)
    else:
        monitor = ServerMonitor(args.server_port)
        if not monitor.available:
            print(
                f"UWAGA: nie znaleziono procesu nasłuchującego na porcie {args.server_port} na tym hoście - "
                f"pomiar zużycia zasobów wyłączony (działa tylko wtedy, gdy serwer jest uruchomiony "
                f"bezpośrednio na tym hoście, np. w devcontainerze; w docker-compose.prod.yml aplikacja "
                f"żyje w osobnym kontenerze)."
            )

    print(f"Sprawdzanie serwera pod {base_url} ...")
    try:
        session.get(f"{base_url}/get_crl/", timeout=args.timeout)
    except requests.RequestException as exc:
        sys.exit(f"Nie udało się połączyć z {base_url}: {exc}")

    print("Budowanie scenariuszy (jednorazowy setup: certyfikaty/CSR referencyjne) ...")
    scenarios = build_scenarios(session, base_url, args.repeats, algorithms_filter, endpoints_filter, args.timeout)
    print()

    estimate_and_confirm(scenarios, args.yes)
    print(f"Monitor zasobów serwera: {'dostępny' if monitor.available else 'niedostępny'}\n")

    samples = run_scenarios(scenarios, monitor)
    if not samples:
        sys.exit("Brak pomiarów do zapisania.")

    raw_df = pd.DataFrame(samples)
    raw_path = output_dir / "results_raw.csv"
    raw_df.to_csv(raw_path, index=False)
    print(f"\nZapisano surowe wyniki: {raw_path}")

    summary_df = summarize(raw_df)
    summary_path = output_dir / "results_summary.csv"
    summary_df.to_csv(summary_path, index=False)
    print(f"Zapisano podsumowanie (średnie i odchylenia standardowe): {summary_path}")

    if not args.no_plot:
        print("Generowanie boxplotów (plotnine) ...")
        make_plots(raw_df, output_dir)

    print("\nGotowe.")


if __name__ == "__main__":
    main()
