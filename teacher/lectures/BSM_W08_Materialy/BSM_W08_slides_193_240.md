#slide 193
## layout
definition
## slide title
Continuity overview
## subtitle
Co to jest
## term
Continuity overview
## definition
Apple's Continuity obejmuje Handoff, Universal Clipboard i Wi-Fi Password Sharing.
## teleprompter:
Apple's Continuity obejmuje Handoff, Universal Clipboard i Wi-Fi Password Sharing.
Continuity w ekosystemie Apple to Handoff, Universal Clipboard i Wi-Fi Password Sharing działające przez BLE, AWDL i Wi-Fi. Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów. Apple's Continuity obejmuje Handoff, Universal Clipboard i Wi-Fi Password Sharing. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 194
## layout
bullet
## slide title
Continuity overview
## subtitle
Jak działa
## bullets
- Wejście
- Przebieg
- Wynik
## teleprompter:
Continuity overview zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 195
## layout
bullet
## slide title
Continuity overview
## subtitle
Jak pęka
## bullets
- Warunek
- Kontrola
- Skutek
## teleprompter:
Continuity overview przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 196
## layout
bullet
## slide title
Continuity overview
## subtitle
Jak się bronić
## bullets
- Reguła
- Egzekwowanie
- Test
## teleprompter:
Continuity overview wymaga konkretnej reguły i miejsca egzekwowania.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 197
## layout
definition
## slide title
Handoff discovery
## subtitle
Co to jest
## term
Handoff discovery
## definition
Handoff zaczyna się od BLE discovery i przenosi activity state w stacku Continuity.
## teleprompter:
Handoff zaczyna się od BLE discovery i przenosi activity state w stacku Continuity.
Continuity w ekosystemie Apple to Handoff, Universal Clipboard i Wi-Fi Password Sharing działające przez BLE, AWDL i Wi-Fi. Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów. Handoff zaczyna się od BLE discovery i przenosi activity state w stacku Continuity. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 198
## layout
bullet
## slide title
Handoff discovery
## subtitle
Jak działa
## bullets
- Wejście
- Przebieg
- Wynik
## teleprompter:
Handoff discovery zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 199
## layout
bullet
## slide title
Handoff discovery
## subtitle
Jak pęka
## bullets
- Warunek
- Kontrola
- Skutek
## teleprompter:
Handoff discovery przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 200
## layout
bullet
## slide title
Handoff discovery
## subtitle
Jak się bronić
## bullets
- Reguła
- Egzekwowanie
- Test
## teleprompter:
Handoff discovery wymaga konkretnej reguły i miejsca egzekwowania.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 201
## layout
definition
## slide title
AirDrop discovery
## subtitle
Co to jest
## term
AirDrop discovery
## definition
AirDrop używa discovery, authentication i transferu na bazie BLE, AWDL i Wi-Fi.
## teleprompter:
AirDrop używa discovery, authentication i transferu na bazie BLE, AWDL i Wi-Fi.
Continuity w ekosystemie Apple to Handoff, Universal Clipboard i Wi-Fi Password Sharing działające przez BLE, AWDL i Wi-Fi. Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów. AirDrop używa discovery, authentication i transferu na bazie BLE, AWDL i Wi-Fi. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 202
## layout
bullet
## slide title
AirDrop discovery
## subtitle
Jak działa
## bullets
- Wejście
- Przebieg
- Wynik
## teleprompter:
AirDrop discovery zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 203
## layout
bullet
## slide title
AirDrop discovery
## subtitle
Jak pęka
## bullets
- Warunek
- Kontrola
- Skutek
## teleprompter:
AirDrop discovery przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 204
## layout
bullet
## slide title
AirDrop discovery
## subtitle
Jak się bronić
## bullets
- Reguła
- Egzekwowanie
- Test
## teleprompter:
AirDrop discovery wymaga konkretnej reguły i miejsca egzekwowania.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 205
## layout
definition
## slide title
PrivateDrop
## subtitle
Co to jest
## term
PrivateDrop
## definition
PrivateDrop zastępuje leaked contact checks mechanizmem PSI, żeby nie ujawniać phone number ani email.
## teleprompter:
PrivateDrop zastępuje leaked contact checks mechanizmem PSI, żeby nie ujawniać phone number ani email.
Continuity w ekosystemie Apple to Handoff, Universal Clipboard i Wi-Fi Password Sharing działające przez BLE, AWDL i Wi-Fi. Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów. PrivateDrop zastępuje leaked contact checks mechanizmem PSI, żeby nie ujawniać phone number ani email. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 206
## layout
bullet
## slide title
PrivateDrop
## subtitle
Jak działa
## bullets
- Wejście
- Przebieg
- Wynik
## teleprompter:
PrivateDrop zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 207
## layout
bullet
## slide title
PrivateDrop
## subtitle
Jak pęka
## bullets
- Warunek
- Kontrola
- Skutek
## teleprompter:
PrivateDrop przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 208
## layout
bullet
## slide title
PrivateDrop
## subtitle
Jak się bronić
## bullets
- Reguła
- Egzekwowanie
- Test
## teleprompter:
PrivateDrop wymaga konkretnej reguły i miejsca egzekwowania.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 209
## layout
definition
## slide title
AWDL and BLE
## subtitle
Co to jest
## term
AWDL and BLE
## definition
AWDL i BLE niosą niskopoziomowy ruch discovery oraz widoczny dla użytkownika stan Continuity.
## teleprompter:
AWDL i BLE niosą niskopoziomowy ruch discovery oraz widoczny dla użytkownika stan Continuity.
Continuity w ekosystemie Apple to Handoff, Universal Clipboard i Wi-Fi Password Sharing działające przez BLE, AWDL i Wi-Fi. Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów. AWDL i BLE niosą niskopoziomowy ruch discovery oraz widoczny dla użytkownika stan Continuity. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 210
## layout
bullet
## slide title
AWDL and BLE
## subtitle
Jak działa
## bullets
- Wejście
- Przebieg
- Wynik
## teleprompter:
AWDL and BLE zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 211
## layout
bullet
## slide title
AWDL and BLE
## subtitle
Jak pęka
## bullets
- Warunek
- Kontrola
- Skutek
## teleprompter:
AWDL and BLE przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 212
## layout
bullet
## slide title
AWDL and BLE
## subtitle
Jak się bronić
## bullets
- Reguła
- Egzekwowanie
- Test
## teleprompter:
AWDL and BLE wymaga konkretnej reguły i miejsca egzekwowania.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 213
## layout
definition
## slide title
Cross-device identity
## subtitle
Co to jest
## term
Cross-device identity
## definition
Messagi Continuity mogą ujawniać typ urządzenia, wersję OS i zachowanie pasywnemu obserwatorowi.
## teleprompter:
Messagi Continuity mogą ujawniać typ urządzenia, wersję OS i zachowanie pasywnemu obserwatorowi.
Continuity w ekosystemie Apple to Handoff, Universal Clipboard i Wi-Fi Password Sharing działające przez BLE, AWDL i Wi-Fi. Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów. Messagi Continuity mogą ujawniać typ urządzenia, wersję OS i zachowanie pasywnemu obserwatorowi. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 214
## layout
bullet
## slide title
Cross-device identity
## subtitle
Jak działa
## bullets
- Wejście
- Przebieg
- Wynik
## teleprompter:
Cross-device identity zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 215
## layout
bullet
## slide title
Cross-device identity
## subtitle
Jak pęka
## bullets
- Warunek
- Kontrola
- Skutek
## teleprompter:
Cross-device identity przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 216
## layout
bullet
## slide title
Cross-device identity
## subtitle
Jak się bronić
## bullets
- Reguła
- Egzekwowanie
- Test
## teleprompter:
Cross-device identity wymaga konkretnej reguły i miejsca egzekwowania.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 217
## layout
definition
## slide title
Spoof relay downgrade
## subtitle
Co to jest
## term
Spoof relay downgrade
## definition
Atakujący może spoofować, relayować albo downgrade'ować discovery i authentication.
## teleprompter:
Atakujący może spoofować, relayować albo downgrade'ować discovery i authentication.
Continuity w ekosystemie Apple to Handoff, Universal Clipboard i Wi-Fi Password Sharing działające przez BLE, AWDL i Wi-Fi. Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów. Atakujący może spoofować, relayować albo downgrade'ować discovery i authentication. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 218
## layout
bullet
## slide title
Spoof relay downgrade
## subtitle
Jak działa
## bullets
- Wejście
- Przebieg
- Wynik
## teleprompter:
Spoof relay downgrade zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 219
## layout
bullet
## slide title
Spoof relay downgrade
## subtitle
Jak pęka
## bullets
- Warunek
- Kontrola
- Skutek
## teleprompter:
Spoof relay downgrade przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 220
## layout
bullet
## slide title
Spoof relay downgrade
## subtitle
Jak się bronić
## bullets
- Reguła
- Egzekwowanie
- Test
## teleprompter:
Spoof relay downgrade wymaga konkretnej reguły i miejsca egzekwowania.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 221
## layout
definition
## slide title
Transport and state machine
## subtitle
Co to jest
## term
Transport and state machine
## definition
Structured analysis wymaga obserwacji całego state machine na różnych vantage points macOS.
## teleprompter:
Structured analysis wymaga obserwacji całego state machine na różnych vantage points macOS.
Continuity w ekosystemie Apple to Handoff, Universal Clipboard i Wi-Fi Password Sharing działające przez BLE, AWDL i Wi-Fi. Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów. Structured analysis wymaga obserwacji całego state machine na różnych vantage points macOS. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 222
## layout
bullet
## slide title
Transport and state machine
## subtitle
Jak działa
## bullets
- Wejście
- Przebieg
- Wynik
## teleprompter:
Transport and state machine zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 223
## layout
bullet
## slide title
Transport and state machine
## subtitle
Jak pęka
## bullets
- Warunek
- Kontrola
- Skutek
## teleprompter:
Transport and state machine przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 224
## layout
bullet
## slide title
Transport and state machine
## subtitle
Jak się bronić
## bullets
- Reguła
- Egzekwowanie
- Test
## teleprompter:
Transport and state machine wymaga konkretnej reguły i miejsca egzekwowania.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 225
## layout
definition
## slide title
Packet analysis
## subtitle
Co to jest
## term
Packet analysis
## definition
Packet captures pokazują, które pola są szyfrowane, a które metadata lecą jawnie.
## teleprompter:
Packet captures pokazują, które pola są szyfrowane, a które metadata lecą jawnie.
Continuity w ekosystemie Apple to Handoff, Universal Clipboard i Wi-Fi Password Sharing działające przez BLE, AWDL i Wi-Fi. Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów. Packet captures pokazują, które pola są szyfrowane, a które metadata lecą jawnie. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 226
## layout
bullet
## slide title
Packet analysis
## subtitle
Jak działa
## bullets
- Wejście
- Przebieg
- Wynik
## teleprompter:
Packet analysis zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 227
## layout
bullet
## slide title
Packet analysis
## subtitle
Jak pęka
## bullets
- Warunek
- Kontrola
- Skutek
## teleprompter:
Packet analysis przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 228
## layout
bullet
## slide title
Packet analysis
## subtitle
Jak się bronić
## bullets
- Reguła
- Egzekwowanie
- Test
## teleprompter:
Packet analysis wymaga konkretnej reguły i miejsca egzekwowania.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 229
## layout
definition
## slide title
Mitigations
## subtitle
Co to jest
## term
Mitigations
## definition
PSI, większa ostrożność w contact discovery i twardsza kontrola widoczności ograniczają wyciek.
## teleprompter:
PSI, większa ostrożność w contact discovery i twardsza kontrola widoczności ograniczają wyciek.
Continuity w ekosystemie Apple to Handoff, Universal Clipboard i Wi-Fi Password Sharing działające przez BLE, AWDL i Wi-Fi. Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów. PSI, większa ostrożność w contact discovery i twardsza kontrola widoczności ograniczają wyciek. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 230
## layout
bullet
## slide title
Mitigations
## subtitle
Jak działa
## bullets
- Wejście
- Przebieg
- Wynik
## teleprompter:
Mitigations zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 231
## layout
bullet
## slide title
Mitigations
## subtitle
Jak pęka
## bullets
- Warunek
- Kontrola
- Skutek
## teleprompter:
Mitigations przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 232
## layout
bullet
## slide title
Mitigations
## subtitle
Jak się bronić
## bullets
- Reguła
- Egzekwowanie
- Test
## teleprompter:
Mitigations wymaga konkretnej reguły i miejsca egzekwowania.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 233
## layout
definition
## slide title
Test matrix
## subtitle
Co to jest
## term
Test matrix
## definition
Dobry test matrix zmienia stan urządzenia, odległość i użyty transport.
## teleprompter:
Dobry test matrix zmienia stan urządzenia, odległość i użyty transport.
Continuity w ekosystemie Apple to Handoff, Universal Clipboard i Wi-Fi Password Sharing działające przez BLE, AWDL i Wi-Fi. Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów. Dobry test matrix zmienia stan urządzenia, odległość i użyty transport. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 234
## layout
bullet
## slide title
Test matrix
## subtitle
Jak działa
## bullets
- Wejście
- Przebieg
- Wynik
## teleprompter:
Test matrix zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 235
## layout
bullet
## slide title
Test matrix
## subtitle
Jak pęka
## bullets
- Warunek
- Kontrola
- Skutek
## teleprompter:
Test matrix przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 236
## layout
bullet
## slide title
Test matrix
## subtitle
Jak się bronić
## bullets
- Reguła
- Egzekwowanie
- Test
## teleprompter:
Test matrix wymaga konkretnej reguły i miejsca egzekwowania.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 237
## layout
definition
## slide title
Android comparison
## subtitle
Co to jest
## term
Android comparison
## definition
Android local-network policy daje użyteczny kontrast dla zawsze aktywnych kanałów continuity.
## teleprompter:
Android local-network policy daje użyteczny kontrast dla zawsze aktywnych kanałów continuity.
Continuity w ekosystemie Apple to Handoff, Universal Clipboard i Wi-Fi Password Sharing działające przez BLE, AWDL i Wi-Fi. Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów. Android local-network policy daje użyteczny kontrast dla zawsze aktywnych kanałów continuity. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 238
## layout
bullet
## slide title
Android comparison
## subtitle
Jak działa
## bullets
- Wejście
- Przebieg
- Wynik
## teleprompter:
Android comparison zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 239
## layout
bullet
## slide title
Android comparison
## subtitle
Jak pęka
## bullets
- Warunek
- Kontrola
- Skutek
## teleprompter:
Android comparison przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 240
## layout
bullet
## slide title
Android comparison
## subtitle
Jak się bronić
## bullets
- Reguła
- Egzekwowanie
- Test
## teleprompter:
Android comparison wymaga konkretnej reguły i miejsca egzekwowania.
PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.
