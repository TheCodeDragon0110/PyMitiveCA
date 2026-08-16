# PyMitiveCA
Prosty urząd certyfikacji oparty na Pyhonie i frameworku Django. 

Jest to serwer HTTP uruchomiony na porcie 5000 adresu localhost. Jego dane opierają się o kilka podstawowych modeli:

* **Cert** - klasa reprezentująca certyfikaty zgodne ze standardami RFC 5280
* **CertRequest** - żądania wystawienia certyfikatu zgodne ze standardem PKCS#10
* **Crl** - Listy odwołania certyfikatów zgodne z RFC 5280

Serwer ma następujące endpointy:

* **issue_cert/** = wystanienie certyfikatu na podstaiwe żądania wystawienia certyfikatu
* **generate_cert/** - genetacja certyfikatu na podstawie struktury DistinguishedName przyszłego właściciela certyfikatu.
* **generte_csr/** - generacja żądania wystawienia certyfikatu na podstawie Distinguished Name przyszłego właściciela certyfikatu.
* **confirm_cert/** - potwierdzenie posiadania klucza (POP) dla certyfikatu wystawionego na klucz ML-KEM.
* **get_cert/** - pobranie certyfikatu na podstawie jego hasha lub numeru seryjnego
* **get_csr/** - pobranie żądania wystawienia certyfikatu na podstawie jego hasha lub id bazodanowego
* **get_crl/** - pobranie najnowszej wersji listy odwołań certyfikatów. Jeżeli obecna jest nieaktualna jest tworzona nowa.
* **cert_info/** - metadane certyfikatu w formacie JSON (m.in. algorytm i długość klucza).
* **ocsp/** - serwis OCSP (RFC 6960) sprawdzający status certyfikatu.
* **revoke/** - unieważnienie certyfikatu, opcjonalnie z powodem (`reason`).

## Algorytmy i długości kluczy

| Algorytm | Parametr | Dozwolone wartości | Wartość domyślna |
| --- | --- | --- | --- |
| RSA | `key_size` | 2048, 3072, 4096, 8192 | 2048 |
| ECDSA | `curve` | secp256r1, secp384r1, secp521r1, secp256k1 | secp256r1 |
| ED25519 | – | – (klucz ma zawsze 255 bitów) | – |
| ML-KEM | `key_size` | 768, 1024 (wariant algorytmu) | 768 |

Długość klucza jest zapisywana w bazie dla każdego algorytmu i raportowana
przez API na dwa sposoby:

* w nagłówkach odpowiedzi zwracających PEM - `X-Public-Key-Algorithm` oraz
  `X-Key-Size`,
* w JSON-ie z endpointu **cert_info/** (pola `public_key_algorithm` i
  `key_size`), a dla żądań ML-KEM także w odpowiedziach `generate_csr/` i
  `issue_cert/`.

Dla RSA i ECDSA jest to liczba bitów (odpowiednio moduł i rząd krzywej), dla
ED25519 - 255 bitów krzywej Curve25519, a dla ML-KEM numer wariantu
(768/1024), bo parametry tego algorytmu nie sprowadzają się do jednej
długości w bitach.

## Serwis OCSP

Endpoint **ocsp/** to responder OCSP zgodny z RFC 6960. Odpowiedzi są
podpisywane bezpośrednio kluczem CA (responderID jako skrót klucza
publicznego CA), więc nie jest potrzebny osobny certyfikat respondera
delegowanego.

Obsługiwane są oba sposoby transportu z RFC 6960:

```bash
# POST z żądaniem DER w ciele
curl --data-binary @request.der -H "Content-Type: application/ocsp-request" \
     https://localhost/ocsp/ --output response.der

# GET z żądaniem zakodowanym base64 w ścieżce
curl "https://localhost/ocsp/$(base64 -w0 request.der | jq -sRr @uri)" --output response.der
```

Najprościej odpytać responder klientem `openssl`:

```bash
openssl ocsp -issuer ca.pem -cert certyfikat.pem -url https://localhost/ocsp/ -CAfile ca.pem
```

Status wynika wprost z bazy CA: certyfikat znany i ważny to `good`,
unieważniony - `revoked` wraz z datą unieważnienia, a nieznany numer
seryjny - `unknown`. Pytanie o certyfikat obcego wystawcy kończy się
odpowiedzią `unauthorized`. Zgodnie z RFC 6960 błędy protokołu są
sygnalizowane statusem w odpowiedzi OCSP, a nie kodem HTTP.

Wystawiane certyfikaty niosą adres respondera w rozszerzeniu Authority
Information Access oraz adres CRL w CRL Distribution Points, więc klient
znajduje oba punkty sam. Adresy te konfiguruje się zmiennymi środowiskowymi
`CA_BASE_URL`, `OCSP_URL` i `CRL_URL` (domyślnie `https://localhost`).

## Powody unieważnienia

**revoke/** przyjmuje opcjonalny parametr `reason` (domyślnie
`unspecified`) - jedną z wartości RFC 5280 CRLReason:

`unspecified`, `key_compromise`, `ca_compromise`, `affiliation_changed`,
`superseded`, `cessation_of_operation`, `certificate_hold`,
`privilege_withdrawn`, `aa_compromise`

```bash
curl "https://localhost/revoke/?serial=<numer>&reason=key_compromise"
```

Nieznana wartość `reason` kończy się błędem 400. Powód jest zapisywany
razem z datą unieważnienia przy pierwszym wywołaniu `revoke/` na danym
certyfikacie - kolejne wywołania (nawet z innym `reason`) go nie zmieniają,
bo system nie wspiera cofania unieważnień. Zapisany powód trafia do
rozszerzenia `CRLReason` w CRL oraz do `revocationReason` w odpowiedziach
OCSP, a w JSON-ie z **cert_info/** widoczny jest w polu
`revocation_reason`.

## Instalacja

Aplikacja wymaga środowiska wirtualnego Pythona (venv). Wymagana wersja Pythona to **3.14**.
Po pobraniu projektu należy wykonać komendy:
```bash
python -m venv .venv
source .venv/bin/activate
```
Lub w przypadku systemu operacyjnego Windows:

```bash
python -m venv .venv
 .venv/Scripts/activate
```

Następnie należy zainstalować wszystkie zależności potrzebne do działania programu.

```bash
pip install -r requirements.txt
```

Następnie należy wejść do katalogu PyMitiveCA, dokonać migracji i uruchomić serwer Django.
```bash
python manage.py migrate
python manage.py runserver

Od tej pory projekt uruchamia się ostatnią komendą.
```
### Plik secrets.json

Jest to plik w którym znajdują się klucze, ścieżki i hasła certyfikatów. Plik został zostawiony dla celów edukacyjnych i  wygody, jednak w późniejszych wersjach, jeżeli aplikacja będzie rozwijana, plik ten zostanie zastąpiony generacją indywidualnych plików z danymi wrażliwymi.

Z tego powodu ZABRONIONE JEST korzystanie z umieszczonego w repozytorium pliku secrets.json w zastosowaniach produkcyjnych.



## Testy automatyczne

Do komponentu dołączone są testy automatyczne. Najlepiej je wykonać tuż po instalacji komponentu. Należy je uruchamiać wewnątrz katalogu z plikiem requirements.txt.
Uruchamia się je komendą:

```bash
pytest .\PyMitiveCA\Tests\
```

Jeżeli wszystkie 121 testów przejdą, komponent jest gotowy do pracy. Testowane są wszystkie dostępne endpointy, w tym wszystkie obsługiwane algorytmy (RSA, ECDSA, ED25519, ML-KEM) wraz z ich długościami kluczy, serwis OCSP oraz powody unieważnienia.

## Przykłady

W folderze PyMitiveCA/Examples umieszczone są przykłady aplikacji wysyłających żądania i przechwytujących odpowiedzi z poszczególnych endpointów. Do każdego z nich jest po jednym przykładzie. Uruchamia się je jak standardowy skrypt pythonowy:

```bash
python get_csr.py
```

Trzeba jednak pamiętać o pozostawieniu serwera włączonym.

Wszelkie szczegóły dokumentacyjno-implementacyjne znajdują się w plikach z kodem.

## Badanie wydajności

W `PyMitiveCA/Benchmarks/benchmark.py` znajduje się skrypt mierzący czas
odpowiedzi i zużycie zasobów każdego endpointu, dla wszystkich obsługiwanych
algorytmów i wybranych parametrów (długość klucza RSA, krzywa ECDSA, okres
ważności certyfikatu, hash i transport OCSP). Wymaga uruchomionego serwera
(tak jak `PyMitiveCA/Tests/`) oraz dodatkowych zależności:

```bash
pip install -r PyMitiveCA/Benchmarks/requirements-benchmark.txt
python PyMitiveCA/Benchmarks/benchmark.py
```

Domyślnie każdy scenariusz (endpoint x wariant algorytmu/parametru) jest
powtarzany 100 razy. Wyniki trafiają do
`PyMitiveCA/Benchmarks/results/<znacznik czasu>/`:

* `results_raw.csv` - jeden wiersz na pojedynczy pomiar,
* `results_summary.csv` - jeden wiersz na scenariusz: średnia i odchylenie
  standardowe czasu odpowiedzi, rozmiaru odpowiedzi oraz (gdy dostępne)
  zużycia CPU/RAM serwera,
* `boxplot_latency_<endpoint>.png`, `boxplot_cpu_<endpoint>.png` - boxploty
  rozkładów per scenariusz (plotnine, składnia ggplot2).

Zużycie CPU/RAM serwera jest mierzone tylko wtedy, gdy benchmark jest
uruchamiany na tym samym hoście co `manage.py runserver` (np. w
devcontainerze) - w środowisku produkcyjnym (`docker-compose.prod.yml`),
gdzie aplikacja żyje w osobnym kontenerze, ta kolumna zostaje pusta, a
mierzony jest wyłącznie czas odpowiedzi.

**Uwaga na czas trwania**: generacja klucza RSA-8192 zajmuje ok. 15-20s NA
POWTÓRZENIE, więc pełny przebieg (wszystkie algorytmy x 100 powtórzeń) może
zająć ponad godzinę - skrypt ostrzega o tym i prosi o potwierdzenie
(pomijalne przez `--yes`). Zakres można zawęzić:

```bash
python benchmark.py --repeats 10                        # szybki przebieg próbny
python benchmark.py --endpoints generate_cert,issue_cert
python benchmark.py --algorithms RSA-2048,ED25519,ML-KEM-1024
```

Pełna lista opcji: `python PyMitiveCA/Benchmarks/benchmark.py --help`.

## Uruchomienie z HTTPS (nginx + certbot)

Do komponentu dołączona jest gotowa konfiguracja nginx jako reverse proxy z
terminacją TLS przed aplikacją (uruchamianą przez Daphne, serwer ASGI z
obsługą WebSocket) oraz opcjonalna integracja z certbotem. Szczegóły i
instrukcja uruchomienia znajdują się w [deploy/README.md](deploy/README.md).

## Dalszy rozwój aplikacji

* **Uruchomienie protokołu WebSocket** - Został on wpisany do aplikacji jednak zwracany jest błąd HTTP 404 przy próbie podłączenia do niego.
* **Dalszy rozwój aplikacji** o nowe możliwości takie jak podpisy elektroniczne.
* **Cofanie unieważnień** - RFC 5280 przewiduje tymczasowe zawieszenie (`certificate_hold`) i jego cofnięcie przez `removeFromCRL` w delta CRL; ten system zapisuje unieważnienie jako nieodwracalne, niezależnie od podanego powodu.

