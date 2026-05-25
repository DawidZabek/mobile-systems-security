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
Slajd 193. Continuity overview. Apple continuity i cross-device services.

Apple's Continuity obejmuje Handoff, Universal Clipboard i Wi-Fi Password Sharing.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

#slide 194
## layout
bullet
## slide title
Continuity overview
## subtitle
Jak działa
## bullets
- Krok 1: Apple's Continuity obejmuje Handoff, Universal Clipboard i Wi-Fi Password Sharing.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 194. Continuity overview. Apple continuity i cross-device services.

Przebieg Continuity overview krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 195
## layout
bullet
## slide title
Continuity overview
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Apple's Continuity obejmuje Handoff, Universal Clipboard i Wi-Fi Password Sharing.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 195. Continuity overview. Apple continuity i cross-device services.

Continuity overview przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 196
## layout
bullet
## slide title
Continuity overview
## subtitle
Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 196. Continuity overview. Apple continuity i cross-device services.

Obrona dla Continuity overview wymaga konkretnej reguły i miejsca egzekwowania.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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
Slajd 197. Handoff discovery. Apple continuity i cross-device services.

Handoff zaczyna się od BLE discovery i przenosi activity state w stacku Continuity.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

#slide 198
## layout
bullet
## slide title
Handoff discovery
## subtitle
Jak działa
## bullets
- Krok 1: Handoff zaczyna się od BLE discovery i przenosi activity state w stacku Continuity.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 198. Handoff discovery. Apple continuity i cross-device services.

Przebieg Handoff discovery krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 199
## layout
bullet
## slide title
Handoff discovery
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Handoff zaczyna się od BLE discovery i przenosi activity state w stacku Continuity.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 199. Handoff discovery. Apple continuity i cross-device services.

Handoff discovery przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 200
## layout
bullet
## slide title
Handoff discovery
## subtitle
Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 200. Handoff discovery. Apple continuity i cross-device services.

Obrona dla Handoff discovery wymaga konkretnej reguły i miejsca egzekwowania.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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
Slajd 201. AirDrop discovery. Apple continuity i cross-device services.

AirDrop używa discovery, authentication i transferu na bazie BLE, AWDL i Wi-Fi.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

#slide 202
## layout
bullet
## slide title
AirDrop discovery
## subtitle
Jak działa
## bullets
- Krok 1: AirDrop używa discovery, authentication i transferu na bazie BLE, AWDL i Wi-Fi.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 202. AirDrop discovery. Apple continuity i cross-device services.

Przebieg AirDrop discovery krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 203
## layout
bullet
## slide title
AirDrop discovery
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: AirDrop używa discovery, authentication i transferu na bazie BLE, AWDL i Wi-Fi.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 203. AirDrop discovery. Apple continuity i cross-device services.

AirDrop discovery przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 204
## layout
bullet
## slide title
AirDrop discovery
## subtitle
Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 204. AirDrop discovery. Apple continuity i cross-device services.

Obrona dla AirDrop discovery wymaga konkretnej reguły i miejsca egzekwowania.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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
Slajd 205. PrivateDrop. Apple continuity i cross-device services.

PrivateDrop zastępuje leaked contact checks mechanizmem PSI, żeby nie ujawniać phone number ani email.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

#slide 206
## layout
bullet
## slide title
PrivateDrop
## subtitle
Jak działa
## bullets
- Krok 1: PrivateDrop zastępuje leaked contact checks mechanizmem PSI, żeby nie ujawniać phone number ani email.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 206. PrivateDrop. Apple continuity i cross-device services.

Przebieg PrivateDrop krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 207
## layout
bullet
## slide title
PrivateDrop
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: PrivateDrop zastępuje leaked contact checks mechanizmem PSI, żeby nie ujawniać phone number ani email.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 207. PrivateDrop. Apple continuity i cross-device services.

PrivateDrop przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 208
## layout
bullet
## slide title
PrivateDrop
## subtitle
Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 208. PrivateDrop. Apple continuity i cross-device services.

Obrona dla PrivateDrop wymaga konkretnej reguły i miejsca egzekwowania.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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
Slajd 209. AWDL and BLE. Apple continuity i cross-device services.

AWDL i BLE niosą niskopoziomowy ruch discovery oraz widoczny dla użytkownika stan Continuity.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

#slide 210
## layout
bullet
## slide title
AWDL and BLE
## subtitle
Jak działa
## bullets
- Krok 1: AWDL i BLE niosą niskopoziomowy ruch discovery oraz widoczny dla użytkownika stan Continuity.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 210. AWDL and BLE. Apple continuity i cross-device services.

Przebieg AWDL and BLE krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 211
## layout
bullet
## slide title
AWDL and BLE
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: AWDL i BLE niosą niskopoziomowy ruch discovery oraz widoczny dla użytkownika stan Continuity.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 211. AWDL and BLE. Apple continuity i cross-device services.

AWDL and BLE przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 212
## layout
bullet
## slide title
AWDL and BLE
## subtitle
Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 212. AWDL and BLE. Apple continuity i cross-device services.

Obrona dla AWDL and BLE wymaga konkretnej reguły i miejsca egzekwowania.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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
Slajd 213. Cross-device identity. Apple continuity i cross-device services.

Messagi Continuity mogą ujawniać typ urządzenia, wersję OS i zachowanie pasywnemu obserwatorowi.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

#slide 214
## layout
bullet
## slide title
Cross-device identity
## subtitle
Jak działa
## bullets
- Krok 1: Messagi Continuity mogą ujawniać typ urządzenia, wersję OS i zachowanie pasywnemu obserwatorowi.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 214. Cross-device identity. Apple continuity i cross-device services.

Przebieg Cross-device identity krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 215
## layout
bullet
## slide title
Cross-device identity
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Messagi Continuity mogą ujawniać typ urządzenia, wersję OS i zachowanie pasywnemu obserwatorowi.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 215. Cross-device identity. Apple continuity i cross-device services.

Cross-device identity przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 216
## layout
bullet
## slide title
Cross-device identity
## subtitle
Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 216. Cross-device identity. Apple continuity i cross-device services.

Obrona dla Cross-device identity wymaga konkretnej reguły i miejsca egzekwowania.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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
Slajd 217. Spoof relay downgrade. Apple continuity i cross-device services.

Atakujący może spoofować, relayować albo downgrade'ować discovery i authentication.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

#slide 218
## layout
bullet
## slide title
Spoof relay downgrade
## subtitle
Jak działa
## bullets
- Krok 1: Atakujący może spoofować, relayować albo downgrade'ować discovery i authentication.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 218. Spoof relay downgrade. Apple continuity i cross-device services.

Przebieg Spoof relay downgrade krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 219
## layout
bullet
## slide title
Spoof relay downgrade
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Atakujący może spoofować, relayować albo downgrade'ować discovery i authentication.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 219. Spoof relay downgrade. Apple continuity i cross-device services.

Spoof relay downgrade przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 220
## layout
bullet
## slide title
Spoof relay downgrade
## subtitle
Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 220. Spoof relay downgrade. Apple continuity i cross-device services.

Obrona dla Spoof relay downgrade wymaga konkretnej reguły i miejsca egzekwowania.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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
Slajd 221. Transport and state machine. Apple continuity i cross-device services.

Structured analysis wymaga obserwacji całego state machine na różnych vantage points macOS.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

#slide 222
## layout
bullet
## slide title
Transport and state machine
## subtitle
Jak działa
## bullets
- Krok 1: Structured analysis wymaga obserwacji całego state machine na różnych vantage points macOS.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 222. Transport and state machine. Apple continuity i cross-device services.

Przebieg Transport and state machine krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 223
## layout
bullet
## slide title
Transport and state machine
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Structured analysis wymaga obserwacji całego state machine na różnych vantage points macOS.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 223. Transport and state machine. Apple continuity i cross-device services.

Transport and state machine przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 224
## layout
bullet
## slide title
Transport and state machine
## subtitle
Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 224. Transport and state machine. Apple continuity i cross-device services.

Obrona dla Transport and state machine wymaga konkretnej reguły i miejsca egzekwowania.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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
Slajd 225. Packet analysis. Apple continuity i cross-device services.

Packet captures pokazują, które pola są szyfrowane, a które metadata lecą jawnie.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

#slide 226
## layout
bullet
## slide title
Packet analysis
## subtitle
Jak działa
## bullets
- Krok 1: Packet captures pokazują, które pola są szyfrowane, a które metadata lecą jawnie.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 226. Packet analysis. Apple continuity i cross-device services.

Przebieg Packet analysis krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 227
## layout
bullet
## slide title
Packet analysis
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Packet captures pokazują, które pola są szyfrowane, a które metadata lecą jawnie.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 227. Packet analysis. Apple continuity i cross-device services.

Packet analysis przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 228
## layout
bullet
## slide title
Packet analysis
## subtitle
Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 228. Packet analysis. Apple continuity i cross-device services.

Obrona dla Packet analysis wymaga konkretnej reguły i miejsca egzekwowania.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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
Slajd 229. Mitigations. Apple continuity i cross-device services.

PSI, większa ostrożność w contact discovery i twardsza kontrola widoczności ograniczają wyciek.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

#slide 230
## layout
bullet
## slide title
Mitigations
## subtitle
Jak działa
## bullets
- Krok 1: PSI, większa ostrożność w contact discovery i twardsza kontrola widoczności ograniczają wyciek.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 230. Mitigations. Apple continuity i cross-device services.

Przebieg Mitigations krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 231
## layout
bullet
## slide title
Mitigations
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: PSI, większa ostrożność w contact discovery i twardsza kontrola widoczności ograniczają wyciek.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 231. Mitigations. Apple continuity i cross-device services.

Mitigations przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 232
## layout
bullet
## slide title
Mitigations
## subtitle
Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 232. Mitigations. Apple continuity i cross-device services.

Obrona dla Mitigations wymaga konkretnej reguły i miejsca egzekwowania.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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
Slajd 233. Test matrix. Apple continuity i cross-device services.

Dobry test matrix zmienia stan urządzenia, odległość i użyty transport.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

#slide 234
## layout
bullet
## slide title
Test matrix
## subtitle
Jak działa
## bullets
- Krok 1: Dobry test matrix zmienia stan urządzenia, odległość i użyty transport.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 234. Test matrix. Apple continuity i cross-device services.

Przebieg Test matrix krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 235
## layout
bullet
## slide title
Test matrix
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Dobry test matrix zmienia stan urządzenia, odległość i użyty transport.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 235. Test matrix. Apple continuity i cross-device services.

Test matrix przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 236
## layout
bullet
## slide title
Test matrix
## subtitle
Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 236. Test matrix. Apple continuity i cross-device services.

Obrona dla Test matrix wymaga konkretnej reguły i miejsca egzekwowania.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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
Slajd 237. Android comparison. Apple continuity i cross-device services.

Android local-network policy daje użyteczny kontrast dla zawsze aktywnych kanałów continuity.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

#slide 238
## layout
bullet
## slide title
Android comparison
## subtitle
Jak działa
## bullets
- Krok 1: Android local-network policy daje użyteczny kontrast dla zawsze aktywnych kanałów continuity.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 238. Android comparison. Apple continuity i cross-device services.

Przebieg Android comparison krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.

W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 239
## layout
bullet
## slide title
Android comparison
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Android local-network policy daje użyteczny kontrast dla zawsze aktywnych kanałów continuity.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 239. Android comparison. Apple continuity i cross-device services.

Android comparison przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.

Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 240
## layout
bullet
## slide title
Android comparison
## subtitle
Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 240. Android comparison. Apple continuity i cross-device services.

Obrona dla Android comparison wymaga konkretnej reguły i miejsca egzekwowania.

PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.
