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
mDNS działa przez multicast DNS na UDP 5353 i ogłasza usługi przez rekordy PTR, SRV i TXT. Rekord PTR mówi, jaką nazwę usługi ma rozwiązać klient, SRV prowadzi do hosta i portu, a TXT niesie parę dodatkowych parametrów usługi. W praktyce ten sam wzorzec ujawnia nazwę urządzenia, typ usługi i adres, zanim aplikacja w ogóle wykona własne uwierzytelnienie.
W Android 16 lokalna sieć jest funkcją opt-in, żeby developerzy znaleźli zależności od implicit local network access. Android 17 ma ten model wymuszać dla nowych targetów, a sam dokument wymienia też typowe błędy socketów oraz NDK helper do sprawdzania, dlaczego ruch został zablokowany. To jest ważne, bo zwykły `INTERNET` nie odcina aplikacji od LAN.
W praktyce mDNS staje się źródłem fingerprintingu i enumeracji usług. Jeśli aplikacja przyjmuje rekord lokalny bez własnej walidacji, przeciwnik może podszyć się pod usługę, podmienić odpowiedź albo wymusić błędny routing. Odpowiedź obronna musi mówić wprost, które sockety mają prawo widzieć LAN, a które powinny dostać blokadę.

#slide 2
## layout
bullet
## slide title
mDNS record anatomy
## subtitle
Jak działa
## bullets
- Rekordy PTR, SRV i TXT
- Multicast na UDP 5353
- LAN widoczny zanim padnie auth
- Typ usługi i port
## teleprompter:
Najpierw mDNS wysyła zapytanie lub odpowiedź na multicast, a potem klient dostaje nazwę usługi, hostname, port i pola TXT. To nie jest zwykłe „odkrycie”, tylko zbudowanie mapy usług w otoczeniu zanim zacznie się jakakolwiek autoryzacja.
W Androidzie problem polega na tym, że zwykłe `INTERNET` nie zamyka dostępu do LAN. `RESTRICT_LOCAL_NETWORK` i późniejsze `ACCESS_LOCAL_NETWORK` służą właśnie do tego, żeby zobaczyć i potem wymusić, które sockety naprawdę mają prawo rozmawiać z mDNS i resztą lokalnych protokołów.
Jeśli aplikacja bierze lokalny rekord za prawdziwy, a nie sprawdza hosta, portu albo źródła odpowiedzi, to atakujący może wstawić własną usługę i podmienić ścieżkę komunikacji. Wtedy widać już nie tylko nazwę hosta, ale cały punkt zaczepienia dla dalszego ruchu.

#slide 3
## layout
bullet
## slide title
mDNS record anatomy
## subtitle
Jak pęka
## bullets
- Spoofing odpowiedzi
- Korelacja broadcastów
- Lokalny rekord bez walidacji
- Błędny host albo port
## teleprompter:
Atak zaczyna się od odpowiedzi udającej prawdziwy rekord mDNS. Jeśli klient nie sprawdza źródła, hosta i portu, to traktuje lokalną odpowiedź jak zaufaną i buduje na niej dalszą komunikację.
W takim scenariuszu przeciwnik nie potrzebuje przełamywać całego systemu. Wystarczy, że podstawi rekord z własnym hostname albo własnym portem i zmusi aplikację do połączenia z fałszywą usługą.
Na urządzeniu widać to jako błędny routing, timeout, albo połączenie do obcej usługi podszywającej się pod prawdziwą. Jeśli aplikacja używa NsdManager, błąd może wyglądać jak poprawne znalezienie usługi, a w rzeczywistości prowadzić do podstawionej odpowiedzi.

#slide 4
## layout
bullet
## slide title
mDNS record anatomy
## subtitle
Jak się bronić
## bullets
- RESTRICT_LOCAL_NETWORK w Android 16
- ACCESS_LOCAL_NETWORK w Android 17
- `android_getnetworkblockedreason`
- WebView i sockety
## teleprompter:
Obrona zaczyna się od rozdzielenia tego, co ma widzieć Internet, od tego, co ma widzieć LAN. Android 16 daje opt-in, żeby znaleźć zależności od lokalnej sieci, a Android 17 ma ten model wymuszać dla nowych targetów.
Jeśli aplikacja naprawdę potrzebuje discovery, trzeba to wyrazić wprost przez uprawnienie i przetestować reakcję na blokadę socketu. Jeśli potrzebuje tylko wyboru usługi przez system, to nie powinna dostawać szerokiego dostępu do całej podsieci.
NDK helper pokazuje, dlaczego ruch został zablokowany, a WebView przypomina, że stan dostępu może być dziedziczony po host app, więc sam manifest nie kończy tematu. Obrona jest poprawna dopiero wtedy, gdy zły przypadek faktycznie się wywraca, a dobry przechodzi bez obejścia blokady.

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
SSDP wykrywa urządzenia przez M-SEARCH, NOTIFY i nagłówek LOCATION.
mDNS, SSDP i link-local IPv6 pokazują, że sama obecność w LAN daje aplikacji bardzo dużo informacji o pobliskich usługach i urządzeniach. mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi. SSDP wykrywa urządzenia przez M-SEARCH, NOTIFY i nagłówek LOCATION. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 6
## layout
bullet
## slide title
SSDP discovery
## subtitle
Jak działa
## bullets
- M-SEARCH i NOTIFY
- Nagłówek LOCATION
- Odpowiedź bez weryfikacji
- Źródło usługi
## teleprompter:
SSDP zaczyna od broadcastu `M-SEARCH`, a urządzenie odpowiada zwykle przez nagłówek `LOCATION`, który wskazuje endpoint usługi. To jest prostszy mechanizm niż mDNS, ale problem bezpieczeństwa jest podobny: odpowiedź z sieci jest traktowana jako wskazówka, gdzie iść dalej.
Jeśli aplikacja przyjmuje `LOCATION` bez sprawdzenia, może połączyć się z podstawioną usługą albo z urządzeniem, które tylko udaje prawdziwy endpoint. W lokalnej sieci nie ma gwarancji, że odpowiedź przyszła od tego, kto powinien ją wysłać.
W praktyce SSDP służy do odkrywania sprzętu i usług, ale jednocześnie daje przeciwnikowi możliwość spoofingu i korelacji ruchu. Najłatwiej zobaczyć to wtedy, gdy aplikacja bazuje na odpowiedzi z sieci zamiast na własnym sprawdzeniu hosta i portu.

#slide 7
## layout
bullet
## slide title
SSDP discovery
## subtitle
Jak pęka
## bullets
- Broadcast `M-SEARCH`
- Nagłówek `LOCATION`
- Podstawiona usługa
- Lokalny endpoint
## teleprompter:
Atak na SSDP nie musi być skomplikowany. Wystarczy odpowiedź z poprawnym formatem i własnym `LOCATION`, żeby klient poszedł do fałszywego endpointu.
Jeżeli aplikacja traktuje lokalną odpowiedź jak dowód tożsamości usługi, to przegrana zaczyna się jeszcze przed autoryzacją. Przeciwnik nie łamie protokołu, tylko wykorzystuje to, że protokół zakłada zaufanie do sieci lokalnej.
W praktyce skutkiem jest połączenie z nieautoryzowanym urządzeniem, błędna identyfikacja sprzętu albo przynajmniej mylący wynik discovery, który potem trafia do UI lub do logiki połączenia.

#slide 8
## layout
bullet
## slide title
SSDP discovery
## subtitle
Jak się bronić
## bullets
- LAN i Internet osobno
- Wymuszony runtime permission
- NDK helper na blokadę
- WebView inheritance
## teleprompter:
Obrona w SSDP nie polega na „wyłączaniu discovery”, tylko na ograniczeniu tego, kto w ogóle może mówić do sieci lokalnej. Jeśli aplikacja potrzebuje tylko pojedynczego urządzenia, nie ma powodu, by dawała broad access do całej podsieci.
Android 16 i 17 pokazują, jak platforma przesuwa kontrolę z domyślnego dostępu do LAN na model explicite przyznanego uprawnienia. NDK helper pomaga wykryć blokadę, a WebView przypomina, że nie wolno zakładać, iż tylko kod Java zna stan uprawnienia.
Test obrony powinien sprawdzić zarówno blokadę socketu, jak i to, czy UI nie pokazuje usług znalezionych na podstawie fałszywego `LOCATION`.

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
IPv6 link-local działa tylko na jednej karcie sieciowej i używa zakresu fe80::/10.
mDNS, SSDP i link-local IPv6 pokazują, że sama obecność w LAN daje aplikacji bardzo dużo informacji o pobliskich usługach i urządzeniach. mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi. IPv6 link-local działa tylko na jednej karcie sieciowej i używa zakresu fe80::/10. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 10
## layout
bullet
## slide title
IPv6 link-local
## subtitle
Jak działa
## bullets
- IPv6 link-local: mDNS używa rekordów PTR SRV i TXT na…
- IPv6 link-local: mDNS SSDP i link-local IPv6 pokazują że sama…
- IPv6 link-local: LAN powinien być odcięty od Internetu na poziomie…
## teleprompter:
IPv6 link-local zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 11
## layout
bullet
## slide title
IPv6 link-local
## subtitle
Jak pęka
## bullets
- IPv6 link-local: Spoofing odpowiedzi korelacja broadcastów i akceptowanie lokalnych rekordów…
- IPv6 link-local: mDNS używa rekordów PTR SRV i TXT na…
- IPv6 link-local: mDNS SSDP i link-local IPv6 pokazują że sama…
## teleprompter:
IPv6 link-local przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 12
## layout
bullet
## slide title
IPv6 link-local
## subtitle
Jak się bronić
## bullets
- IPv6 link-local: LAN powinien być odcięty od Internetu na poziomie…
- IPv6 link-local: mDNS używa rekordów PTR SRV i TXT na…
- IPv6 link-local: Spoofing odpowiedzi korelacja broadcastów i akceptowanie lokalnych rekordów…
## teleprompter:
IPv6 link-local wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Surowe sockety pozwalają aplikacji próbować mDNS i SSDP nawet wtedy, gdy ma tylko INTERNET.
mDNS, SSDP i link-local IPv6 pokazują, że sama obecność w LAN daje aplikacji bardzo dużo informacji o pobliskich usługach i urządzeniach. mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi. Surowe sockety pozwalają aplikacji próbować mDNS i SSDP nawet wtedy, gdy ma tylko INTERNET. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 14
## layout
bullet
## slide title
Raw socket access
## subtitle
Jak działa
## bullets
- Raw socket access: mDNS używa rekordów PTR SRV i TXT na…
- Raw socket access: mDNS SSDP i link-local IPv6 pokazują że sama…
- Raw socket access: LAN powinien być odcięty od Internetu na poziomie…
## teleprompter:
Raw socket access zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 15
## layout
bullet
## slide title
Raw socket access
## subtitle
Jak pęka
## bullets
- Raw socket access: Spoofing odpowiedzi korelacja broadcastów i akceptowanie lokalnych rekordów…
- Raw socket access: mDNS używa rekordów PTR SRV i TXT na…
- Raw socket access: mDNS SSDP i link-local IPv6 pokazują że sama…
## teleprompter:
Raw socket access przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 16
## layout
bullet
## slide title
Raw socket access
## subtitle
Jak się bronić
## bullets
- Raw socket access: LAN powinien być odcięty od Internetu na poziomie…
- Raw socket access: mDNS używa rekordów PTR SRV i TXT na…
- Raw socket access: Spoofing odpowiedzi korelacja broadcastów i akceptowanie lokalnych rekordów…
## teleprompter:
Raw socket access wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
NsdManager jest frameworkowym API do discovery, które odciąża aplikację od ręcznego skanowania LAN.
mDNS, SSDP i link-local IPv6 pokazują, że sama obecność w LAN daje aplikacji bardzo dużo informacji o pobliskich usługach i urządzeniach. mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi. NsdManager jest frameworkowym API do discovery, które odciąża aplikację od ręcznego skanowania LAN. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 18
## layout
bullet
## slide title
NsdManager
## subtitle
Jak działa
## bullets
- NsdManager: mDNS używa rekordów PTR SRV i TXT na…
- NsdManager: mDNS SSDP i link-local IPv6 pokazują że sama…
- NsdManager: LAN powinien być odcięty od Internetu na poziomie…
## teleprompter:
NsdManager zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 19
## layout
bullet
## slide title
NsdManager
## subtitle
Jak pęka
## bullets
- NsdManager: Spoofing odpowiedzi korelacja broadcastów i akceptowanie lokalnych rekordów…
- NsdManager: mDNS używa rekordów PTR SRV i TXT na…
- NsdManager: mDNS SSDP i link-local IPv6 pokazują że sama…
## teleprompter:
NsdManager przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 20
## layout
bullet
## slide title
NsdManager
## subtitle
Jak się bronić
## bullets
- NsdManager: LAN powinien być odcięty od Internetu na poziomie…
- NsdManager: mDNS używa rekordów PTR SRV i TXT na…
- NsdManager: Spoofing odpowiedzi korelacja broadcastów i akceptowanie lokalnych rekordów…
## teleprompter:
NsdManager wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Casting zwykle powinien iść przez systemowy picker lub output switcher zamiast przez własne skanowanie usług.
mDNS, SSDP i link-local IPv6 pokazują, że sama obecność w LAN daje aplikacji bardzo dużo informacji o pobliskich usługach i urządzeniach. mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi. Casting zwykle powinien iść przez systemowy picker lub output switcher zamiast przez własne skanowanie usług. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 22
## layout
bullet
## slide title
Casting path
## subtitle
Jak działa
## bullets
- Casting path: mDNS używa rekordów PTR SRV i TXT na…
- Casting path: mDNS SSDP i link-local IPv6 pokazują że sama…
- Casting path: LAN powinien być odcięty od Internetu na poziomie…
## teleprompter:
Casting path zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 23
## layout
bullet
## slide title
Casting path
## subtitle
Jak pęka
## bullets
- Casting path: Spoofing odpowiedzi korelacja broadcastów i akceptowanie lokalnych rekordów…
- Casting path: mDNS używa rekordów PTR SRV i TXT na…
- Casting path: mDNS SSDP i link-local IPv6 pokazują że sama…
## teleprompter:
Casting path przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 24
## layout
bullet
## slide title
Casting path
## subtitle
Jak się bronić
## bullets
- Casting path: LAN powinien być odcięty od Internetu na poziomie…
- Casting path: mDNS używa rekordów PTR SRV i TXT na…
- Casting path: Spoofing odpowiedzi korelacja broadcastów i akceptowanie lokalnych rekordów…
## teleprompter:
Casting path wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby ujawnić ukryte zależności od LAN.
mDNS, SSDP i link-local IPv6 pokazują, że sama obecność w LAN daje aplikacji bardzo dużo informacji o pobliskich usługach i urządzeniach. mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby ujawnić ukryte zależności od LAN. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 26
## layout
bullet
## slide title
Android 16 opt-in
## subtitle
Jak działa
## bullets
- Android 16 opt-in: mDNS używa rekordów PTR SRV i TXT na…
- Android 16 opt-in: mDNS SSDP i link-local IPv6 pokazują że sama…
- Android 16 opt-in: LAN powinien być odcięty od Internetu na poziomie…
## teleprompter:
Android 16 opt-in zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 27
## layout
bullet
## slide title
Android 16 opt-in
## subtitle
Jak pęka
## bullets
- Android 16 opt-in: Spoofing odpowiedzi korelacja broadcastów i akceptowanie lokalnych rekordów…
- Android 16 opt-in: mDNS używa rekordów PTR SRV i TXT na…
- Android 16 opt-in: mDNS SSDP i link-local IPv6 pokazują że sama…
## teleprompter:
Android 16 opt-in przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 28
## layout
bullet
## slide title
Android 16 opt-in
## subtitle
Jak się bronić
## bullets
- Android 16 opt-in: LAN powinien być odcięty od Internetu na poziomie…
- Android 16 opt-in: mDNS używa rekordów PTR SRV i TXT na…
- Android 16 opt-in: Spoofing odpowiedzi korelacja broadcastów i akceptowanie lokalnych rekordów…
## teleprompter:
Android 16 opt-in wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Android 17 blokuje LAN domyślnie dla targetSdk 37+ i wprowadza ACCESS_LOCAL_NETWORK.
mDNS, SSDP i link-local IPv6 pokazują, że sama obecność w LAN daje aplikacji bardzo dużo informacji o pobliskich usługach i urządzeniach. mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi. Android 17 blokuje LAN domyślnie dla targetSdk 37+ i wprowadza ACCESS_LOCAL_NETWORK. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 30
## layout
bullet
## slide title
Android 17 enforcement
## subtitle
Jak działa
## bullets
- Android 17 enforcement: mDNS używa rekordów PTR SRV i TXT na…
- Android 17 enforcement: mDNS SSDP i link-local IPv6 pokazują że sama…
- Android 17 enforcement: LAN powinien być odcięty od Internetu na poziomie…
## teleprompter:
Android 17 enforcement zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 31
## layout
bullet
## slide title
Android 17 enforcement
## subtitle
Jak pęka
## bullets
- Android 17 enforcement: Spoofing odpowiedzi korelacja broadcastów i akceptowanie lokalnych rekordów…
- Android 17 enforcement: mDNS używa rekordów PTR SRV i TXT na…
- Android 17 enforcement: mDNS SSDP i link-local IPv6 pokazują że sama…
## teleprompter:
Android 17 enforcement przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 32
## layout
bullet
## slide title
Android 17 enforcement
## subtitle
Jak się bronić
## bullets
- Android 17 enforcement: LAN powinien być odcięty od Internetu na poziomie…
- Android 17 enforcement: mDNS używa rekordów PTR SRV i TXT na…
- Android 17 enforcement: Spoofing odpowiedzi korelacja broadcastów i akceptowanie lokalnych rekordów…
## teleprompter:
Android 17 enforcement wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Przejście zaczyna się jeszcze przez NEARBY_WIFI_DEVICES, a docelowo trafia do NEARBY_DEVICES.
mDNS, SSDP i link-local IPv6 pokazują, że sama obecność w LAN daje aplikacji bardzo dużo informacji o pobliskich usługach i urządzeniach. mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi. Przejście zaczyna się jeszcze przez NEARBY_WIFI_DEVICES, a docelowo trafia do NEARBY_DEVICES. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 34
## layout
bullet
## slide title
Permission split
## subtitle
Jak działa
## bullets
- Permission split: mDNS używa rekordów PTR SRV i TXT na…
- Permission split: mDNS SSDP i link-local IPv6 pokazują że sama…
- Permission split: LAN powinien być odcięty od Internetu na poziomie…
## teleprompter:
Permission split zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 35
## layout
bullet
## slide title
Permission split
## subtitle
Jak pęka
## bullets
- Permission split: Spoofing odpowiedzi korelacja broadcastów i akceptowanie lokalnych rekordów…
- Permission split: mDNS używa rekordów PTR SRV i TXT na…
- Permission split: mDNS SSDP i link-local IPv6 pokazują że sama…
## teleprompter:
Permission split przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 36
## layout
bullet
## slide title
Permission split
## subtitle
Jak się bronić
## bullets
- Permission split: LAN powinien być odcięty od Internetu na poziomie…
- Permission split: mDNS używa rekordów PTR SRV i TXT na…
- Permission split: Spoofing odpowiedzi korelacja broadcastów i akceptowanie lokalnych rekordów…
## teleprompter:
Permission split wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Broad access path to klasyczny runtime permission request dla lokalnej sieci.
mDNS, SSDP i link-local IPv6 pokazują, że sama obecność w LAN daje aplikacji bardzo dużo informacji o pobliskich usługach i urządzeniach. mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi. Broad access path to klasyczny runtime permission request dla lokalnej sieci. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 38
## layout
bullet
## slide title
Broad access path
## subtitle
Jak działa
## bullets
- Broad access path: mDNS używa rekordów PTR SRV i TXT na…
- Broad access path: mDNS SSDP i link-local IPv6 pokazują że sama…
- Broad access path: LAN powinien być odcięty od Internetu na poziomie…
## teleprompter:
Broad access path zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 39
## layout
bullet
## slide title
Broad access path
## subtitle
Jak pęka
## bullets
- Broad access path: Spoofing odpowiedzi korelacja broadcastów i akceptowanie lokalnych rekordów…
- Broad access path: mDNS używa rekordów PTR SRV i TXT na…
- Broad access path: mDNS SSDP i link-local IPv6 pokazują że sama…
## teleprompter:
Broad access path przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 40
## layout
bullet
## slide title
Broad access path
## subtitle
Jak się bronić
## bullets
- Broad access path: LAN powinien być odcięty od Internetu na poziomie…
- Broad access path: mDNS używa rekordów PTR SRV i TXT na…
- Broad access path: Spoofing odpowiedzi korelacja broadcastów i akceptowanie lokalnych rekordów…
## teleprompter:
Broad access path wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
System-mediated discovery pozwala uniknąć szerokiego grantu dla sieci lokalnej.
mDNS, SSDP i link-local IPv6 pokazują, że sama obecność w LAN daje aplikacji bardzo dużo informacji o pobliskich usługach i urządzeniach. mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi. System-mediated discovery pozwala uniknąć szerokiego grantu dla sieci lokalnej. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 42
## layout
bullet
## slide title
Privacy-preserving picker
## subtitle
Jak działa
## bullets
- Privacy-preserving picker: mDNS używa rekordów PTR SRV i TXT na…
- Privacy-preserving picker: mDNS SSDP i link-local IPv6 pokazują że sama…
- Privacy-preserving picker: LAN powinien być odcięty od Internetu na poziomie…
## teleprompter:
Privacy-preserving picker zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 43
## layout
bullet
## slide title
Privacy-preserving picker
## subtitle
Jak pęka
## bullets
- Privacy-preserving picker: Spoofing odpowiedzi korelacja broadcastów i akceptowanie lokalnych rekordów…
- Privacy-preserving picker: mDNS używa rekordów PTR SRV i TXT na…
- Privacy-preserving picker: mDNS SSDP i link-local IPv6 pokazują że sama…
## teleprompter:
Privacy-preserving picker przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 44
## layout
bullet
## slide title
Privacy-preserving picker
## subtitle
Jak się bronić
## bullets
- Privacy-preserving picker: LAN powinien być odcięty od Internetu na poziomie…
- Privacy-preserving picker: mDNS używa rekordów PTR SRV i TXT na…
- Privacy-preserving picker: Spoofing odpowiedzi korelacja broadcastów i akceptowanie lokalnych rekordów…
## teleprompter:
Privacy-preserving picker wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
WebView dziedziczy stan dostępu do lokalnej sieci po aplikacji hosta.
mDNS, SSDP i link-local IPv6 pokazują, że sama obecność w LAN daje aplikacji bardzo dużo informacji o pobliskich usługach i urządzeniach. mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi. WebView dziedziczy stan dostępu do lokalnej sieci po aplikacji hosta. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 46
## layout
bullet
## slide title
Host app inheritance
## subtitle
Jak działa
## bullets
- Host app inheritance: mDNS używa rekordów PTR SRV i TXT na…
- Host app inheritance: mDNS SSDP i link-local IPv6 pokazują że sama…
- Host app inheritance: LAN powinien być odcięty od Internetu na poziomie…
## teleprompter:
Host app inheritance zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 47
## layout
bullet
## slide title
Host app inheritance
## subtitle
Jak pęka
## bullets
- Host app inheritance: Spoofing odpowiedzi korelacja broadcastów i akceptowanie lokalnych rekordów…
- Host app inheritance: mDNS używa rekordów PTR SRV i TXT na…
- Host app inheritance: mDNS SSDP i link-local IPv6 pokazują że sama…
## teleprompter:
Host app inheritance przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 48
## layout
bullet
## slide title
Host app inheritance
## subtitle
Jak się bronić
## bullets
- Host app inheritance: LAN powinien być odcięty od Internetu na poziomie…
- Host app inheritance: mDNS używa rekordów PTR SRV i TXT na…
- Host app inheritance: Spoofing odpowiedzi korelacja broadcastów i akceptowanie lokalnych rekordów…
## teleprompter:
Host app inheritance wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.
