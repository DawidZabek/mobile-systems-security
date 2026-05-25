#slide 1
## layout
definition
## slide title
mDNS record anatomy — Co to jest
## term
mDNS record anatomy
## definition
mDNS ogłasza usługi w LAN przez rekordy PTR, SRV i TXT wysyłane na UDP 5353.
## teleprompter:
Slajd 1. mDNS record anatomy. Lokalna sieć i discovery.

mDNS ogłasza usługi w LAN przez rekordy PTR, SRV i TXT wysyłane na UDP 5353. To jest punkt startowy do zrozumienia, jak działa cały blok o lokalna sieć i discovery.

Dlaczego to nie jest tylko hasło. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 2
## layout
bullet
## slide title
mDNS record anatomy — Jak działa
## bullets
- Krok 1: mDNS ogłasza usługi w LAN przez rekordy PTR, SRV i TXT wysyłane na UDP 5353.
- Krok 2: W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 2. mDNS record anatomy. Lokalna sieć i discovery.

Najpierw rozpisz przebieg mDNS record anatomy krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 3
## layout
bullet
## slide title
mDNS record anatomy — Jak pęka
## bullets
- Warunek powodzenia: mDNS ogłasza usługi w LAN przez rekordy PTR, SRV i TXT wysyłane na UDP 5353.
- Kontrola atakującego: Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 3. mDNS record anatomy. Lokalna sieć i discovery.

Tu interesuje nas dokładnie moment, w którym mDNS record anatomy przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 4
## layout
bullet
## slide title
mDNS record anatomy — Jak się bronić
## bullets
- Reguła: Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 4. mDNS record anatomy. Lokalna sieć i discovery.

Obrona dla mDNS record anatomy musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 5
## layout
definition
## slide title
SSDP discovery — Co to jest
## term
SSDP discovery
## definition
SSDP wykrywa urządzenia przez M-SEARCH, NOTIFY i nagłówek LOCATION.
## teleprompter:
Slajd 5. SSDP discovery. Lokalna sieć i discovery.

SSDP wykrywa urządzenia przez M-SEARCH, NOTIFY i nagłówek LOCATION. To jest punkt startowy do zrozumienia, jak działa cały blok o lokalna sieć i discovery.

Dlaczego to nie jest tylko hasło. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 6
## layout
bullet
## slide title
SSDP discovery — Jak działa
## bullets
- Krok 1: SSDP wykrywa urządzenia przez M-SEARCH, NOTIFY i nagłówek LOCATION.
- Krok 2: W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 6. SSDP discovery. Lokalna sieć i discovery.

Najpierw rozpisz przebieg SSDP discovery krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 7
## layout
bullet
## slide title
SSDP discovery — Jak pęka
## bullets
- Warunek powodzenia: SSDP wykrywa urządzenia przez M-SEARCH, NOTIFY i nagłówek LOCATION.
- Kontrola atakującego: Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 7. SSDP discovery. Lokalna sieć i discovery.

Tu interesuje nas dokładnie moment, w którym SSDP discovery przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 8
## layout
bullet
## slide title
SSDP discovery — Jak się bronić
## bullets
- Reguła: Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 8. SSDP discovery. Lokalna sieć i discovery.

Obrona dla SSDP discovery musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 9
## layout
definition
## slide title
IPv6 link-local — Co to jest
## term
IPv6 link-local
## definition
IPv6 link-local działa tylko na jednej karcie sieciowej i używa zakresu fe80::/10.
## teleprompter:
Slajd 9. IPv6 link-local. Lokalna sieć i discovery.

IPv6 link-local działa tylko na jednej karcie sieciowej i używa zakresu fe80::/10. To jest punkt startowy do zrozumienia, jak działa cały blok o lokalna sieć i discovery.

Dlaczego to nie jest tylko hasło. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 10
## layout
bullet
## slide title
IPv6 link-local — Jak działa
## bullets
- Krok 1: IPv6 link-local działa tylko na jednej karcie sieciowej i używa zakresu fe80::/10.
- Krok 2: W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 10. IPv6 link-local. Lokalna sieć i discovery.

Najpierw rozpisz przebieg IPv6 link-local krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 11
## layout
bullet
## slide title
IPv6 link-local — Jak pęka
## bullets
- Warunek powodzenia: IPv6 link-local działa tylko na jednej karcie sieciowej i używa zakresu fe80::/10.
- Kontrola atakującego: Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 11. IPv6 link-local. Lokalna sieć i discovery.

Tu interesuje nas dokładnie moment, w którym IPv6 link-local przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 12
## layout
bullet
## slide title
IPv6 link-local — Jak się bronić
## bullets
- Reguła: Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 12. IPv6 link-local. Lokalna sieć i discovery.

Obrona dla IPv6 link-local musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 13
## layout
definition
## slide title
Raw socket access — Co to jest
## term
Raw socket access
## definition
Surowe sockety pozwalają aplikacji próbować mDNS i SSDP nawet wtedy, gdy ma tylko INTERNET.
## teleprompter:
Slajd 13. Raw socket access. Lokalna sieć i discovery.

Surowe sockety pozwalają aplikacji próbować mDNS i SSDP nawet wtedy, gdy ma tylko INTERNET. To jest punkt startowy do zrozumienia, jak działa cały blok o lokalna sieć i discovery.

Dlaczego to nie jest tylko hasło. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 14
## layout
bullet
## slide title
Raw socket access — Jak działa
## bullets
- Krok 1: Surowe sockety pozwalają aplikacji próbować mDNS i SSDP nawet wtedy, gdy ma tylko INTERNET.
- Krok 2: W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 14. Raw socket access. Lokalna sieć i discovery.

Najpierw rozpisz przebieg Raw socket access krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 15
## layout
bullet
## slide title
Raw socket access — Jak pęka
## bullets
- Warunek powodzenia: Surowe sockety pozwalają aplikacji próbować mDNS i SSDP nawet wtedy, gdy ma tylko INTERNET.
- Kontrola atakującego: Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 15. Raw socket access. Lokalna sieć i discovery.

Tu interesuje nas dokładnie moment, w którym Raw socket access przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 16
## layout
bullet
## slide title
Raw socket access — Jak się bronić
## bullets
- Reguła: Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 16. Raw socket access. Lokalna sieć i discovery.

Obrona dla Raw socket access musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 17
## layout
definition
## slide title
NsdManager — Co to jest
## term
NsdManager
## definition
NsdManager jest frameworkowym API do discovery, które odciąża aplikację od ręcznego skanowania LAN.
## teleprompter:
Slajd 17. NsdManager. Lokalna sieć i discovery.

NsdManager jest frameworkowym API do discovery, które odciąża aplikację od ręcznego skanowania LAN. To jest punkt startowy do zrozumienia, jak działa cały blok o lokalna sieć i discovery.

Dlaczego to nie jest tylko hasło. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 18
## layout
bullet
## slide title
NsdManager — Jak działa
## bullets
- Krok 1: NsdManager jest frameworkowym API do discovery, które odciąża aplikację od ręcznego skanowania LAN.
- Krok 2: W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 18. NsdManager. Lokalna sieć i discovery.

Najpierw rozpisz przebieg NsdManager krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 19
## layout
bullet
## slide title
NsdManager — Jak pęka
## bullets
- Warunek powodzenia: NsdManager jest frameworkowym API do discovery, które odciąża aplikację od ręcznego skanowania LAN.
- Kontrola atakującego: Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 19. NsdManager. Lokalna sieć i discovery.

Tu interesuje nas dokładnie moment, w którym NsdManager przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 20
## layout
bullet
## slide title
NsdManager — Jak się bronić
## bullets
- Reguła: Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 20. NsdManager. Lokalna sieć i discovery.

Obrona dla NsdManager musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 21
## layout
definition
## slide title
Casting path — Co to jest
## term
Casting path
## definition
Casting zwykle powinien iść przez systemowy picker lub output switcher zamiast przez własne skanowanie usług.
## teleprompter:
Slajd 21. Casting path. Lokalna sieć i discovery.

Casting zwykle powinien iść przez systemowy picker lub output switcher zamiast przez własne skanowanie usług. To jest punkt startowy do zrozumienia, jak działa cały blok o lokalna sieć i discovery.

Dlaczego to nie jest tylko hasło. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 22
## layout
bullet
## slide title
Casting path — Jak działa
## bullets
- Krok 1: Casting zwykle powinien iść przez systemowy picker lub output switcher zamiast przez własne skanowanie usług.
- Krok 2: W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 22. Casting path. Lokalna sieć i discovery.

Najpierw rozpisz przebieg Casting path krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 23
## layout
bullet
## slide title
Casting path — Jak pęka
## bullets
- Warunek powodzenia: Casting zwykle powinien iść przez systemowy picker lub output switcher zamiast przez własne skanowanie usług.
- Kontrola atakującego: Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 23. Casting path. Lokalna sieć i discovery.

Tu interesuje nas dokładnie moment, w którym Casting path przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 24
## layout
bullet
## slide title
Casting path — Jak się bronić
## bullets
- Reguła: Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 24. Casting path. Lokalna sieć i discovery.

Obrona dla Casting path musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 25
## layout
definition
## slide title
Android 16 opt-in — Co to jest
## term
Android 16 opt-in
## definition
Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby ujawnić ukryte zależności od LAN.
## teleprompter:
Slajd 25. Android 16 opt-in. Lokalna sieć i discovery.

Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby ujawnić ukryte zależności od LAN. To jest punkt startowy do zrozumienia, jak działa cały blok o lokalna sieć i discovery.

Dlaczego to nie jest tylko hasło. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 26
## layout
bullet
## slide title
Android 16 opt-in — Jak działa
## bullets
- Krok 1: Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby ujawnić ukryte zależności od LAN.
- Krok 2: W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 26. Android 16 opt-in. Lokalna sieć i discovery.

Najpierw rozpisz przebieg Android 16 opt-in krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 27
## layout
bullet
## slide title
Android 16 opt-in — Jak pęka
## bullets
- Warunek powodzenia: Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby ujawnić ukryte zależności od LAN.
- Kontrola atakującego: Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 27. Android 16 opt-in. Lokalna sieć i discovery.

Tu interesuje nas dokładnie moment, w którym Android 16 opt-in przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 28
## layout
bullet
## slide title
Android 16 opt-in — Jak się bronić
## bullets
- Reguła: Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 28. Android 16 opt-in. Lokalna sieć i discovery.

Obrona dla Android 16 opt-in musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 29
## layout
definition
## slide title
Android 17 enforcement — Co to jest
## term
Android 17 enforcement
## definition
Android 17 blokuje LAN domyślnie dla targetSdk 37+ i wprowadza ACCESS_LOCAL_NETWORK.
## teleprompter:
Slajd 29. Android 17 enforcement. Lokalna sieć i discovery.

Android 17 blokuje LAN domyślnie dla targetSdk 37+ i wprowadza ACCESS_LOCAL_NETWORK. To jest punkt startowy do zrozumienia, jak działa cały blok o lokalna sieć i discovery.

Dlaczego to nie jest tylko hasło. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 30
## layout
bullet
## slide title
Android 17 enforcement — Jak działa
## bullets
- Krok 1: Android 17 blokuje LAN domyślnie dla targetSdk 37+ i wprowadza ACCESS_LOCAL_NETWORK.
- Krok 2: W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 30. Android 17 enforcement. Lokalna sieć i discovery.

Najpierw rozpisz przebieg Android 17 enforcement krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 31
## layout
bullet
## slide title
Android 17 enforcement — Jak pęka
## bullets
- Warunek powodzenia: Android 17 blokuje LAN domyślnie dla targetSdk 37+ i wprowadza ACCESS_LOCAL_NETWORK.
- Kontrola atakującego: Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 31. Android 17 enforcement. Lokalna sieć i discovery.

Tu interesuje nas dokładnie moment, w którym Android 17 enforcement przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 32
## layout
bullet
## slide title
Android 17 enforcement — Jak się bronić
## bullets
- Reguła: Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 32. Android 17 enforcement. Lokalna sieć i discovery.

Obrona dla Android 17 enforcement musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 33
## layout
definition
## slide title
Permission split — Co to jest
## term
Permission split
## definition
Przejście zaczyna się jeszcze przez NEARBY_WIFI_DEVICES, a docelowo trafia do NEARBY_DEVICES.
## teleprompter:
Slajd 33. Permission split. Lokalna sieć i discovery.

Przejście zaczyna się jeszcze przez NEARBY_WIFI_DEVICES, a docelowo trafia do NEARBY_DEVICES. To jest punkt startowy do zrozumienia, jak działa cały blok o lokalna sieć i discovery.

Dlaczego to nie jest tylko hasło. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 34
## layout
bullet
## slide title
Permission split — Jak działa
## bullets
- Krok 1: Przejście zaczyna się jeszcze przez NEARBY_WIFI_DEVICES, a docelowo trafia do NEARBY_DEVICES.
- Krok 2: W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 34. Permission split. Lokalna sieć i discovery.

Najpierw rozpisz przebieg Permission split krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 35
## layout
bullet
## slide title
Permission split — Jak pęka
## bullets
- Warunek powodzenia: Przejście zaczyna się jeszcze przez NEARBY_WIFI_DEVICES, a docelowo trafia do NEARBY_DEVICES.
- Kontrola atakującego: Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 35. Permission split. Lokalna sieć i discovery.

Tu interesuje nas dokładnie moment, w którym Permission split przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 36
## layout
bullet
## slide title
Permission split — Jak się bronić
## bullets
- Reguła: Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 36. Permission split. Lokalna sieć i discovery.

Obrona dla Permission split musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 37
## layout
definition
## slide title
Broad access path — Co to jest
## term
Broad access path
## definition
Broad access path to klasyczny runtime permission request dla lokalnej sieci.
## teleprompter:
Slajd 37. Broad access path. Lokalna sieć i discovery.

Broad access path to klasyczny runtime permission request dla lokalnej sieci. To jest punkt startowy do zrozumienia, jak działa cały blok o lokalna sieć i discovery.

Dlaczego to nie jest tylko hasło. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 38
## layout
bullet
## slide title
Broad access path — Jak działa
## bullets
- Krok 1: Broad access path to klasyczny runtime permission request dla lokalnej sieci.
- Krok 2: W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 38. Broad access path. Lokalna sieć i discovery.

Najpierw rozpisz przebieg Broad access path krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 39
## layout
bullet
## slide title
Broad access path — Jak pęka
## bullets
- Warunek powodzenia: Broad access path to klasyczny runtime permission request dla lokalnej sieci.
- Kontrola atakującego: Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 39. Broad access path. Lokalna sieć i discovery.

Tu interesuje nas dokładnie moment, w którym Broad access path przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 40
## layout
bullet
## slide title
Broad access path — Jak się bronić
## bullets
- Reguła: Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 40. Broad access path. Lokalna sieć i discovery.

Obrona dla Broad access path musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 41
## layout
definition
## slide title
Privacy-preserving picker — Co to jest
## term
Privacy-preserving picker
## definition
System-mediated discovery pozwala uniknąć szerokiego grantu dla sieci lokalnej.
## teleprompter:
Slajd 41. Privacy-preserving picker. Lokalna sieć i discovery.

System-mediated discovery pozwala uniknąć szerokiego grantu dla sieci lokalnej. To jest punkt startowy do zrozumienia, jak działa cały blok o lokalna sieć i discovery.

Dlaczego to nie jest tylko hasło. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 42
## layout
bullet
## slide title
Privacy-preserving picker — Jak działa
## bullets
- Krok 1: System-mediated discovery pozwala uniknąć szerokiego grantu dla sieci lokalnej.
- Krok 2: W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 42. Privacy-preserving picker. Lokalna sieć i discovery.

Najpierw rozpisz przebieg Privacy-preserving picker krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 43
## layout
bullet
## slide title
Privacy-preserving picker — Jak pęka
## bullets
- Warunek powodzenia: System-mediated discovery pozwala uniknąć szerokiego grantu dla sieci lokalnej.
- Kontrola atakującego: Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 43. Privacy-preserving picker. Lokalna sieć i discovery.

Tu interesuje nas dokładnie moment, w którym Privacy-preserving picker przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 44
## layout
bullet
## slide title
Privacy-preserving picker — Jak się bronić
## bullets
- Reguła: Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 44. Privacy-preserving picker. Lokalna sieć i discovery.

Obrona dla Privacy-preserving picker musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 45
## layout
definition
## slide title
Host app inheritance — Co to jest
## term
Host app inheritance
## definition
WebView dziedziczy stan dostępu do lokalnej sieci po aplikacji hosta.
## teleprompter:
Slajd 45. Host app inheritance. Lokalna sieć i discovery.

WebView dziedziczy stan dostępu do lokalnej sieci po aplikacji hosta. To jest punkt startowy do zrozumienia, jak działa cały blok o lokalna sieć i discovery.

Dlaczego to nie jest tylko hasło. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 46
## layout
bullet
## slide title
Host app inheritance — Jak działa
## bullets
- Krok 1: WebView dziedziczy stan dostępu do lokalnej sieci po aplikacji hosta.
- Krok 2: W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 46. Host app inheritance. Lokalna sieć i discovery.

Najpierw rozpisz przebieg Host app inheritance krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 47
## layout
bullet
## slide title
Host app inheritance — Jak pęka
## bullets
- Warunek powodzenia: WebView dziedziczy stan dostępu do lokalnej sieci po aplikacji hosta.
- Kontrola atakującego: Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 47. Host app inheritance. Lokalna sieć i discovery.

Tu interesuje nas dokładnie moment, w którym Host app inheritance przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 48
## layout
bullet
## slide title
Host app inheritance — Jak się bronić
## bullets
- Reguła: Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 48. Host app inheritance. Lokalna sieć i discovery.

Obrona dla Host app inheritance musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.
