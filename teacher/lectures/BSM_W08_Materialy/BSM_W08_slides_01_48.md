#slide 1
## layout
definition
## slide title
mDNS record anatomy
## subtitle
Co to jest
## term
mDNS record anatomy
## definition
mDNS ogłasza usługi w LAN przez rekordy PTR, SRV i TXT wysyłane na UDP 5353.
## teleprompter:
Slajd 1. mDNS record anatomy. Lokalna sieć i discovery.

mDNS ogłasza usługi w LAN przez rekordy PTR, SRV i TXT wysyłane na UDP 5353.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.

#slide 2
## layout
bullet
## slide title
mDNS record anatomy
## subtitle
Jak działa
## bullets
- Krok 1: mDNS ogłasza usługi w LAN przez rekordy PTR, SRV i TXT wysyłane na UDP 5353.
- Krok 2: mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 2. mDNS record anatomy. Lokalna sieć i discovery.

Przebieg mDNS record anatomy krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 3
## layout
bullet
## slide title
mDNS record anatomy
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: mDNS ogłasza usługi w LAN przez rekordy PTR, SRV i TXT wysyłane na UDP 5353.
- Kontrola atakującego: Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 3. mDNS record anatomy. Lokalna sieć i discovery.

mDNS record anatomy przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 4
## layout
bullet
## slide title
mDNS record anatomy
## subtitle
Jak się bronić
## bullets
- Reguła: LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 4. mDNS record anatomy. Lokalna sieć i discovery.

Obrona dla mDNS record anatomy wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 5
## layout
definition
## slide title
SSDP discovery
## subtitle
Co to jest
## term
SSDP discovery
## definition
SSDP wykrywa urządzenia przez M-SEARCH, NOTIFY i nagłówek LOCATION.
## teleprompter:
Slajd 5. SSDP discovery. Lokalna sieć i discovery.

SSDP wykrywa urządzenia przez M-SEARCH, NOTIFY i nagłówek LOCATION.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.

#slide 6
## layout
bullet
## slide title
SSDP discovery
## subtitle
Jak działa
## bullets
- Krok 1: SSDP wykrywa urządzenia przez M-SEARCH, NOTIFY i nagłówek LOCATION.
- Krok 2: mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 6. SSDP discovery. Lokalna sieć i discovery.

Przebieg SSDP discovery krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 7
## layout
bullet
## slide title
SSDP discovery
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: SSDP wykrywa urządzenia przez M-SEARCH, NOTIFY i nagłówek LOCATION.
- Kontrola atakującego: Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 7. SSDP discovery. Lokalna sieć i discovery.

SSDP discovery przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 8
## layout
bullet
## slide title
SSDP discovery
## subtitle
Jak się bronić
## bullets
- Reguła: LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 8. SSDP discovery. Lokalna sieć i discovery.

Obrona dla SSDP discovery wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 9
## layout
definition
## slide title
IPv6 link-local
## subtitle
Co to jest
## term
IPv6 link-local
## definition
IPv6 link-local działa tylko na jednej karcie sieciowej i używa zakresu fe80::/10.
## teleprompter:
Slajd 9. IPv6 link-local. Lokalna sieć i discovery.

IPv6 link-local działa tylko na jednej karcie sieciowej i używa zakresu fe80::/10.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.

#slide 10
## layout
bullet
## slide title
IPv6 link-local
## subtitle
Jak działa
## bullets
- Krok 1: IPv6 link-local działa tylko na jednej karcie sieciowej i używa zakresu fe80::/10.
- Krok 2: mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 10. IPv6 link-local. Lokalna sieć i discovery.

Przebieg IPv6 link-local krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 11
## layout
bullet
## slide title
IPv6 link-local
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: IPv6 link-local działa tylko na jednej karcie sieciowej i używa zakresu fe80::/10.
- Kontrola atakującego: Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 11. IPv6 link-local. Lokalna sieć i discovery.

IPv6 link-local przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 12
## layout
bullet
## slide title
IPv6 link-local
## subtitle
Jak się bronić
## bullets
- Reguła: LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 12. IPv6 link-local. Lokalna sieć i discovery.

Obrona dla IPv6 link-local wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 13
## layout
definition
## slide title
Raw socket access
## subtitle
Co to jest
## term
Raw socket access
## definition
Surowe sockety pozwalają aplikacji próbować mDNS i SSDP nawet wtedy, gdy ma tylko INTERNET.
## teleprompter:
Slajd 13. Raw socket access. Lokalna sieć i discovery.

Surowe sockety pozwalają aplikacji próbować mDNS i SSDP nawet wtedy, gdy ma tylko INTERNET.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.

#slide 14
## layout
bullet
## slide title
Raw socket access
## subtitle
Jak działa
## bullets
- Krok 1: Surowe sockety pozwalają aplikacji próbować mDNS i SSDP nawet wtedy, gdy ma tylko INTERNET.
- Krok 2: mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 14. Raw socket access. Lokalna sieć i discovery.

Przebieg Raw socket access krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 15
## layout
bullet
## slide title
Raw socket access
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Surowe sockety pozwalają aplikacji próbować mDNS i SSDP nawet wtedy, gdy ma tylko INTERNET.
- Kontrola atakującego: Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 15. Raw socket access. Lokalna sieć i discovery.

Raw socket access przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 16
## layout
bullet
## slide title
Raw socket access
## subtitle
Jak się bronić
## bullets
- Reguła: LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 16. Raw socket access. Lokalna sieć i discovery.

Obrona dla Raw socket access wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 17
## layout
definition
## slide title
NsdManager
## subtitle
Co to jest
## term
NsdManager
## definition
NsdManager jest frameworkowym API do discovery, które odciąża aplikację od ręcznego skanowania LAN.
## teleprompter:
Slajd 17. NsdManager. Lokalna sieć i discovery.

NsdManager jest frameworkowym API do discovery, które odciąża aplikację od ręcznego skanowania LAN.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.

#slide 18
## layout
bullet
## slide title
NsdManager
## subtitle
Jak działa
## bullets
- Krok 1: NsdManager jest frameworkowym API do discovery, które odciąża aplikację od ręcznego skanowania LAN.
- Krok 2: mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 18. NsdManager. Lokalna sieć i discovery.

Przebieg NsdManager krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 19
## layout
bullet
## slide title
NsdManager
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: NsdManager jest frameworkowym API do discovery, które odciąża aplikację od ręcznego skanowania LAN.
- Kontrola atakującego: Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 19. NsdManager. Lokalna sieć i discovery.

NsdManager przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 20
## layout
bullet
## slide title
NsdManager
## subtitle
Jak się bronić
## bullets
- Reguła: LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 20. NsdManager. Lokalna sieć i discovery.

Obrona dla NsdManager wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 21
## layout
definition
## slide title
Casting path
## subtitle
Co to jest
## term
Casting path
## definition
Casting zwykle powinien iść przez systemowy picker lub output switcher zamiast przez własne skanowanie usług.
## teleprompter:
Slajd 21. Casting path. Lokalna sieć i discovery.

Casting zwykle powinien iść przez systemowy picker lub output switcher zamiast przez własne skanowanie usług.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.

#slide 22
## layout
bullet
## slide title
Casting path
## subtitle
Jak działa
## bullets
- Krok 1: Casting zwykle powinien iść przez systemowy picker lub output switcher zamiast przez własne skanowanie usług.
- Krok 2: mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 22. Casting path. Lokalna sieć i discovery.

Przebieg Casting path krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 23
## layout
bullet
## slide title
Casting path
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Casting zwykle powinien iść przez systemowy picker lub output switcher zamiast przez własne skanowanie usług.
- Kontrola atakującego: Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 23. Casting path. Lokalna sieć i discovery.

Casting path przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 24
## layout
bullet
## slide title
Casting path
## subtitle
Jak się bronić
## bullets
- Reguła: LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 24. Casting path. Lokalna sieć i discovery.

Obrona dla Casting path wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 25
## layout
definition
## slide title
Android 16 opt-in
## subtitle
Co to jest
## term
Android 16 opt-in
## definition
Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby ujawnić ukryte zależności od LAN.
## teleprompter:
Slajd 25. Android 16 opt-in. Lokalna sieć i discovery.

Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby ujawnić ukryte zależności od LAN.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.

#slide 26
## layout
bullet
## slide title
Android 16 opt-in
## subtitle
Jak działa
## bullets
- Krok 1: Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby ujawnić ukryte zależności od LAN.
- Krok 2: mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 26. Android 16 opt-in. Lokalna sieć i discovery.

Przebieg Android 16 opt-in krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 27
## layout
bullet
## slide title
Android 16 opt-in
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby ujawnić ukryte zależności od LAN.
- Kontrola atakującego: Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 27. Android 16 opt-in. Lokalna sieć i discovery.

Android 16 opt-in przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 28
## layout
bullet
## slide title
Android 16 opt-in
## subtitle
Jak się bronić
## bullets
- Reguła: LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 28. Android 16 opt-in. Lokalna sieć i discovery.

Obrona dla Android 16 opt-in wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 29
## layout
definition
## slide title
Android 17 enforcement
## subtitle
Co to jest
## term
Android 17 enforcement
## definition
Android 17 blokuje LAN domyślnie dla targetSdk 37+ i wprowadza ACCESS_LOCAL_NETWORK.
## teleprompter:
Slajd 29. Android 17 enforcement. Lokalna sieć i discovery.

Android 17 blokuje LAN domyślnie dla targetSdk 37+ i wprowadza ACCESS_LOCAL_NETWORK.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.

#slide 30
## layout
bullet
## slide title
Android 17 enforcement
## subtitle
Jak działa
## bullets
- Krok 1: Android 17 blokuje LAN domyślnie dla targetSdk 37+ i wprowadza ACCESS_LOCAL_NETWORK.
- Krok 2: mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 30. Android 17 enforcement. Lokalna sieć i discovery.

Przebieg Android 17 enforcement krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 31
## layout
bullet
## slide title
Android 17 enforcement
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Android 17 blokuje LAN domyślnie dla targetSdk 37+ i wprowadza ACCESS_LOCAL_NETWORK.
- Kontrola atakującego: Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 31. Android 17 enforcement. Lokalna sieć i discovery.

Android 17 enforcement przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 32
## layout
bullet
## slide title
Android 17 enforcement
## subtitle
Jak się bronić
## bullets
- Reguła: LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 32. Android 17 enforcement. Lokalna sieć i discovery.

Obrona dla Android 17 enforcement wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 33
## layout
definition
## slide title
Permission split
## subtitle
Co to jest
## term
Permission split
## definition
Przejście zaczyna się jeszcze przez NEARBY_WIFI_DEVICES, a docelowo trafia do NEARBY_DEVICES.
## teleprompter:
Slajd 33. Permission split. Lokalna sieć i discovery.

Przejście zaczyna się jeszcze przez NEARBY_WIFI_DEVICES, a docelowo trafia do NEARBY_DEVICES.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.

#slide 34
## layout
bullet
## slide title
Permission split
## subtitle
Jak działa
## bullets
- Krok 1: Przejście zaczyna się jeszcze przez NEARBY_WIFI_DEVICES, a docelowo trafia do NEARBY_DEVICES.
- Krok 2: mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 34. Permission split. Lokalna sieć i discovery.

Przebieg Permission split krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 35
## layout
bullet
## slide title
Permission split
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Przejście zaczyna się jeszcze przez NEARBY_WIFI_DEVICES, a docelowo trafia do NEARBY_DEVICES.
- Kontrola atakującego: Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 35. Permission split. Lokalna sieć i discovery.

Permission split przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 36
## layout
bullet
## slide title
Permission split
## subtitle
Jak się bronić
## bullets
- Reguła: LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 36. Permission split. Lokalna sieć i discovery.

Obrona dla Permission split wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 37
## layout
definition
## slide title
Broad access path
## subtitle
Co to jest
## term
Broad access path
## definition
Broad access path to klasyczny runtime permission request dla lokalnej sieci.
## teleprompter:
Slajd 37. Broad access path. Lokalna sieć i discovery.

Broad access path to klasyczny runtime permission request dla lokalnej sieci.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.

#slide 38
## layout
bullet
## slide title
Broad access path
## subtitle
Jak działa
## bullets
- Krok 1: Broad access path to klasyczny runtime permission request dla lokalnej sieci.
- Krok 2: mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 38. Broad access path. Lokalna sieć i discovery.

Przebieg Broad access path krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 39
## layout
bullet
## slide title
Broad access path
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Broad access path to klasyczny runtime permission request dla lokalnej sieci.
- Kontrola atakującego: Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 39. Broad access path. Lokalna sieć i discovery.

Broad access path przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 40
## layout
bullet
## slide title
Broad access path
## subtitle
Jak się bronić
## bullets
- Reguła: LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 40. Broad access path. Lokalna sieć i discovery.

Obrona dla Broad access path wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 41
## layout
definition
## slide title
Privacy-preserving picker
## subtitle
Co to jest
## term
Privacy-preserving picker
## definition
System-mediated discovery pozwala uniknąć szerokiego grantu dla sieci lokalnej.
## teleprompter:
Slajd 41. Privacy-preserving picker. Lokalna sieć i discovery.

System-mediated discovery pozwala uniknąć szerokiego grantu dla sieci lokalnej.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.

#slide 42
## layout
bullet
## slide title
Privacy-preserving picker
## subtitle
Jak działa
## bullets
- Krok 1: System-mediated discovery pozwala uniknąć szerokiego grantu dla sieci lokalnej.
- Krok 2: mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 42. Privacy-preserving picker. Lokalna sieć i discovery.

Przebieg Privacy-preserving picker krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 43
## layout
bullet
## slide title
Privacy-preserving picker
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: System-mediated discovery pozwala uniknąć szerokiego grantu dla sieci lokalnej.
- Kontrola atakującego: Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 43. Privacy-preserving picker. Lokalna sieć i discovery.

Privacy-preserving picker przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 44
## layout
bullet
## slide title
Privacy-preserving picker
## subtitle
Jak się bronić
## bullets
- Reguła: LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 44. Privacy-preserving picker. Lokalna sieć i discovery.

Obrona dla Privacy-preserving picker wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 45
## layout
definition
## slide title
Host app inheritance
## subtitle
Co to jest
## term
Host app inheritance
## definition
WebView dziedziczy stan dostępu do lokalnej sieci po aplikacji hosta.
## teleprompter:
Slajd 45. Host app inheritance. Lokalna sieć i discovery.

WebView dziedziczy stan dostępu do lokalnej sieci po aplikacji hosta.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.

#slide 46
## layout
bullet
## slide title
Host app inheritance
## subtitle
Jak działa
## bullets
- Krok 1: WebView dziedziczy stan dostępu do lokalnej sieci po aplikacji hosta.
- Krok 2: mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 46. Host app inheritance. Lokalna sieć i discovery.

Przebieg Host app inheritance krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 47
## layout
bullet
## slide title
Host app inheritance
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: WebView dziedziczy stan dostępu do lokalnej sieci po aplikacji hosta.
- Kontrola atakującego: Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 47. Host app inheritance. Lokalna sieć i discovery.

Host app inheritance przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 48
## layout
bullet
## slide title
Host app inheritance
## subtitle
Jak się bronić
## bullets
- Reguła: LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 48. Host app inheritance. Lokalna sieć i discovery.

Obrona dla Host app inheritance wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.
