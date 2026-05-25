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
mDNS ogłasza usługi w LAN przez rekordy PTR, SRV i TXT wysyłane na UDP 5353.
mDNS, SSDP i link-local IPv6 pokazują, że sama obecność w LAN daje aplikacji bardzo dużo informacji o pobliskich usługach i urządzeniach. mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi. mDNS ogłasza usługi w LAN przez rekordy PTR, SRV i TXT wysyłane na UDP 5353. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 2
## layout
bullet
## slide title
mDNS record anatomy
## subtitle
Jak działa
## bullets
- Wejście
- Przebieg
- Wynik
## teleprompter:
mDNS record anatomy zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 3
## layout
bullet
## slide title
mDNS record anatomy
## subtitle
Jak pęka
## bullets
- Warunek
- Kontrola
- Skutek
## teleprompter:
mDNS record anatomy przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 4
## layout
bullet
## slide title
mDNS record anatomy
## subtitle
Jak się bronić
## bullets
- Reguła
- Egzekwowanie
- Test
## teleprompter:
mDNS record anatomy wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
- Wejście
- Przebieg
- Wynik
## teleprompter:
SSDP discovery zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 7
## layout
bullet
## slide title
SSDP discovery
## subtitle
Jak pęka
## bullets
- Warunek
- Kontrola
- Skutek
## teleprompter:
SSDP discovery przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 8
## layout
bullet
## slide title
SSDP discovery
## subtitle
Jak się bronić
## bullets
- Reguła
- Egzekwowanie
- Test
## teleprompter:
SSDP discovery wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
- Wejście
- Przebieg
- Wynik
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
- Warunek
- Kontrola
- Skutek
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
- Reguła
- Egzekwowanie
- Test
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
- Wejście
- Przebieg
- Wynik
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
- Warunek
- Kontrola
- Skutek
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
- Reguła
- Egzekwowanie
- Test
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
- Wejście
- Przebieg
- Wynik
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
- Warunek
- Kontrola
- Skutek
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
- Reguła
- Egzekwowanie
- Test
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
- Wejście
- Przebieg
- Wynik
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
- Warunek
- Kontrola
- Skutek
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
- Reguła
- Egzekwowanie
- Test
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
- Wejście
- Przebieg
- Wynik
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
- Warunek
- Kontrola
- Skutek
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
- Reguła
- Egzekwowanie
- Test
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
- Wejście
- Przebieg
- Wynik
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
- Warunek
- Kontrola
- Skutek
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
- Reguła
- Egzekwowanie
- Test
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
- Wejście
- Przebieg
- Wynik
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
- Warunek
- Kontrola
- Skutek
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
- Reguła
- Egzekwowanie
- Test
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
- Wejście
- Przebieg
- Wynik
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
- Warunek
- Kontrola
- Skutek
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
- Reguła
- Egzekwowanie
- Test
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
- Wejście
- Przebieg
- Wynik
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
- Warunek
- Kontrola
- Skutek
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
- Reguła
- Egzekwowanie
- Test
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
- Wejście
- Przebieg
- Wynik
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
- Warunek
- Kontrola
- Skutek
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
- Reguła
- Egzekwowanie
- Test
## teleprompter:
Host app inheritance wymaga konkretnej reguły i miejsca egzekwowania.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.
