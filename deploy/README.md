# HTTPS dla PyMitiveCA (nginx + certbot)

Ten katalog zawiera konfigurację nginx jako reverse proxy z terminacją TLS
przed aplikacją Django (uruchamianą przez Daphne, serwer ASGI obsługujący
zarówno HTTP, jak i WebSocket z Django Channels).

Ponieważ Let's Encrypt / certbot wymaga realnej, publicznie zarejestrowanej
domeny wskazującej na serwer (walidacja przez HTTP-01 na porcie 80), a ten
komponent jest przykładem akademickim bez takiej domeny, domyślnie
skonfigurowany jest **certyfikat samopodpisany**. Przeglądarka pokaże
ostrzeżenie o niezaufanym certyfikacie — to oczekiwane w tym trybie.

## Uruchomienie (bez realnej domeny)

Do wyboru są dwie opcje generowania certyfikatu dla nginx — obie zapisują
wynik w `deploy/nginx/certs/` pod tymi samymi nazwami plików, więc
konfiguracja nginx (`ssl_certificate` / `ssl_certificate_key`) nie wymaga
zmian niezależnie od wyboru.

**Opcja A — pojedynczy certyfikat samopodpisany** (najprostsza):

```bash
./deploy/nginx/generate-self-signed.sh
```

**Opcja B — pełny łańcuch certyfikatów** (Root CA → Intermediate CA →
certyfikat serwera), bliższy temu, jak wygląda prawdziwe PKI i spójny z
tym, że PyMitiveCA sam jest urzędem certyfikacji:

```bash
./deploy/nginx/generate-ca-chain.sh
```

Skrypt tworzy w `deploy/nginx/certs/`:
* `privkey.pem` — klucz prywatny certyfikatu serwera,
* `fullchain.pem` — certyfikat serwera + certyfikat pośredni (Intermediate
  CA); to jest to, co nginx faktycznie wysyła klientowi,
* `rootCA.pem` — certyfikat głównego CA. **Root celowo nie wchodzi w skład
  `fullchain.pem`** (tak jak w prawdziwym PKI) — żeby przeglądarka/klient
  nie pokazywały ostrzeżenia o niezaufanym certyfikacie, trzeba zaimportować
  `rootCA.pem` do lokalnego magazynu zaufanych CA (np. na macOS: Pęk kluczy
  → import + "Always Trust"; na Linuksie: skopiować do
  `/usr/local/share/ca-certificates/` i wykonać `update-ca-certificates`;
  w przeglądarce: ustawienia → certyfikaty → zaufane urzędy główne).

Obie opcje przyjmują opcjonalny argument z nazwą hosta wpisaną do
certyfikatu (domyślnie `localhost`), np. `./deploy/nginx/generate-ca-chain.sh moja-domena.local`.

Następnie uruchom cały stos:

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

Aplikacja będzie dostępna pod `https://localhost/`. Endpointy WebSocket
(`/ws/...`) i pozostałe (`/issue_cert/`, `/get_cert/` itd.) są proxowane
przez nginx do Daphne pod `app:8001`.

## Przejście na certbot (gdy pojawi się realna domena)

Gdy komponent będzie wdrażany na serwerze z publicznym adresem IP i domeną
wskazującą na ten serwer (rekord DNS A/AAAA), można uzyskać prawdziwy
certyfikat Let's Encrypt:

1. Ustaw zmienne środowiskowe `DOMAIN` i `EMAIL` (np. w pliku `.env` obok
   `docker-compose.prod.yml`):
   ```
   DOMAIN=twoja-domena.pl
   EMAIL=admin@twoja-domena.pl
   ```
2. W `docker-compose.prod.yml` odkomentuj usługę `certbot`.
3. Zmień w `deploy/nginx/conf.d/pymitiveca.conf` ścieżki `ssl_certificate`
   i `ssl_certificate_key` na katalog wystawiany przez certbota, np.:
   ```
   ssl_certificate     /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
   ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
   ```
   i zamontuj `./deploy/certbot/conf:/etc/letsencrypt:ro` w usłudze `nginx`.
4. Upewnij się, że porty 80 i 443 są publicznie osiągalne z internetu
   (certbot waliduje domenę przez `/.well-known/acme-challenge/` na porcie 80,
   który już jest obsłużony w `pymitiveca.conf`).
5. Uruchom jednorazowo wystawienie certyfikatu:
   ```bash
   docker compose -f docker-compose.prod.yml run --rm certbot
   docker compose -f docker-compose.prod.yml restart nginx
   ```
6. Odnawianie: certyfikaty Let's Encrypt są ważne 90 dni. Warto dodać
   cykliczne zadanie (np. cron) uruchamiające `certbot renew` w kontenerze
   `certbot` i restart nginx po odnowieniu.

## Uwagi

* `ALLOWED_HOSTS` aplikacji Django jest sterowane zmienną środowiskową
  `DJANGO_ALLOWED_HOSTS` (patrz `PyMitiveCA/PyMitiveCA/settings.py`) —
  przy realnej domenie dopisz ją do tej listy.
* Plik `secrets.json` (klucze CA) i tak nie powinien być używany w
  produkcji — patrz ostrzeżenie w głównym `README.md`.
