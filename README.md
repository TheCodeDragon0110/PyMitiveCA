# PyMitiveCA
Prosty urząd certyfikacji oparty na Pyhonie i frameworku Django. 

Jest to serwer HTTP uruchomiony na porcie 5000 adresu localhost. Jego dane opierają się o kilka podstawowych modeli:

* **Cert** - klasa reprezentująca certyfikaty zgodne ze standardami RFC 5280
* **CertRequest** - żądania wystawienia certyfikatu zgodne ze standardem PKCS#10
* **Crl** - Listy odwołania certyfikatów zgodne z RFC 5280

Serwer ma siedem endpointów:

* **issue_cert/** = wystanienie certyfikatu na podstaiwe żądania wystawienia certyfikatu
* **generate_cert/** - genetacja certyfikatu na podstawie struktury DistinguishedName przyszłego właściciela certyfikatu.
* **generte_csr/** - generacja żądania wystawienia certyfikatu na podstawie Distinguished Name przyszłego właściciela certyfikatu.
* **get_cert/** - pobranie certyfikatu na podstawie jego hasha lub numeru seryjnego
* **get_csr/** - pobranie żądania wystawienia certyfikatu na podstawie jego hasha lub id bazodanowego
* **get_crl/** - pobranie najnowszej wersji listy odwołań certyfikatów. Jeżeli obecna jest nieaktualna jest tworzona nowa.

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

Jeżeli wszystkie 34 testy przejdą, komponent jest gotowy do pracy. Testowane są wszystkie dostępne endpointy

## Przykłady

W folderze PyMitiveCA/Examples umieszczone są przykłady aplikacji wysyłających żądania i przechwytujących odpowiedzi z poszczególnych endpointów. Do każdego z nich jest po jednym przykładzie. Uruchamia się je jak standardowy skrypt pythonowy:

```bash
python get_csr.py
```

Trzeba jednak pamiętać o pozostawieniu serwera włączonym.

Wszelkie szczegóły dokumentacyjno-implementacyjne znajdują się w plikach z kodem.

## Uruchomienie z HTTPS (nginx + certbot)

Do komponentu dołączona jest gotowa konfiguracja nginx jako reverse proxy z
terminacją TLS przed aplikacją (uruchamianą przez Daphne, serwer ASGI z
obsługą WebSocket) oraz opcjonalna integracja z certbotem. Szczegóły i
instrukcja uruchomienia znajdują się w [deploy/README.md](deploy/README.md).

## Dalszy rozwój aplikacji

* **Uruchomienie protokołu WebSocket** - Został on wpisany do aplikacji jednak zwracany jest błąd HTTP 404 przy próbie podłączenia do niego.
* **Dalszy rozwój aplikacji** o nowe możliwości takie jak podpisy elektroniczne, algorytmy oparte na krzywych eliptycznych, można byłoby się nawet pokusić o implementację algorytmów postkwantowych.
* **Rozbudowa sprawdzania certyfikatu** oraz innych funkcji.

