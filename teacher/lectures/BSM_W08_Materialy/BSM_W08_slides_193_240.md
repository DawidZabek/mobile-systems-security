#slide 193
## layout
definition
## slide title
Continuity overview — Co to jest
## term
Continuity overview
## definition
Apple's Continuity obejmuje Handoff, Universal Clipboard i Wi-Fi Password Sharing.
## teleprompter:
Slajd 193. Continuity overview. Apple continuity i cross-device services.

Apple's Continuity obejmuje Handoff, Universal Clipboard i Wi-Fi Password Sharing. To jest punkt startowy do zrozumienia, jak działa cały blok o apple continuity i cross-device services.

Dlaczego to nie jest tylko hasło. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 194
## layout
bullet
## slide title
Continuity overview — Jak działa
## bullets
- Krok 1: Apple's Continuity obejmuje Handoff, Universal Clipboard i Wi-Fi Password Sharing.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 194. Continuity overview. Apple continuity i cross-device services.

Najpierw rozpisz przebieg Continuity overview krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 195
## layout
bullet
## slide title
Continuity overview — Jak pęka
## bullets
- Warunek powodzenia: Apple's Continuity obejmuje Handoff, Universal Clipboard i Wi-Fi Password Sharing.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 195. Continuity overview. Apple continuity i cross-device services.

Tu interesuje nas dokładnie moment, w którym Continuity overview przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 196
## layout
bullet
## slide title
Continuity overview — Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 196. Continuity overview. Apple continuity i cross-device services.

Obrona dla Continuity overview musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 197
## layout
definition
## slide title
Handoff discovery — Co to jest
## term
Handoff discovery
## definition
Handoff zaczyna się od BLE discovery i przenosi activity state w stacku Continuity.
## teleprompter:
Slajd 197. Handoff discovery. Apple continuity i cross-device services.

Handoff zaczyna się od BLE discovery i przenosi activity state w stacku Continuity. To jest punkt startowy do zrozumienia, jak działa cały blok o apple continuity i cross-device services.

Dlaczego to nie jest tylko hasło. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 198
## layout
bullet
## slide title
Handoff discovery — Jak działa
## bullets
- Krok 1: Handoff zaczyna się od BLE discovery i przenosi activity state w stacku Continuity.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 198. Handoff discovery. Apple continuity i cross-device services.

Najpierw rozpisz przebieg Handoff discovery krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 199
## layout
bullet
## slide title
Handoff discovery — Jak pęka
## bullets
- Warunek powodzenia: Handoff zaczyna się od BLE discovery i przenosi activity state w stacku Continuity.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 199. Handoff discovery. Apple continuity i cross-device services.

Tu interesuje nas dokładnie moment, w którym Handoff discovery przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 200
## layout
bullet
## slide title
Handoff discovery — Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 200. Handoff discovery. Apple continuity i cross-device services.

Obrona dla Handoff discovery musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 201
## layout
definition
## slide title
AirDrop discovery — Co to jest
## term
AirDrop discovery
## definition
AirDrop używa discovery, authentication i transferu na bazie BLE, AWDL i Wi-Fi.
## teleprompter:
Slajd 201. AirDrop discovery. Apple continuity i cross-device services.

AirDrop używa discovery, authentication i transferu na bazie BLE, AWDL i Wi-Fi. To jest punkt startowy do zrozumienia, jak działa cały blok o apple continuity i cross-device services.

Dlaczego to nie jest tylko hasło. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 202
## layout
bullet
## slide title
AirDrop discovery — Jak działa
## bullets
- Krok 1: AirDrop używa discovery, authentication i transferu na bazie BLE, AWDL i Wi-Fi.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 202. AirDrop discovery. Apple continuity i cross-device services.

Najpierw rozpisz przebieg AirDrop discovery krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 203
## layout
bullet
## slide title
AirDrop discovery — Jak pęka
## bullets
- Warunek powodzenia: AirDrop używa discovery, authentication i transferu na bazie BLE, AWDL i Wi-Fi.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 203. AirDrop discovery. Apple continuity i cross-device services.

Tu interesuje nas dokładnie moment, w którym AirDrop discovery przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 204
## layout
bullet
## slide title
AirDrop discovery — Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 204. AirDrop discovery. Apple continuity i cross-device services.

Obrona dla AirDrop discovery musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 205
## layout
definition
## slide title
PrivateDrop — Co to jest
## term
PrivateDrop
## definition
PrivateDrop zastępuje leaked contact checks mechanizmem PSI, żeby nie ujawniać phone number ani email.
## teleprompter:
Slajd 205. PrivateDrop. Apple continuity i cross-device services.

PrivateDrop zastępuje leaked contact checks mechanizmem PSI, żeby nie ujawniać phone number ani email. To jest punkt startowy do zrozumienia, jak działa cały blok o apple continuity i cross-device services.

Dlaczego to nie jest tylko hasło. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 206
## layout
bullet
## slide title
PrivateDrop — Jak działa
## bullets
- Krok 1: PrivateDrop zastępuje leaked contact checks mechanizmem PSI, żeby nie ujawniać phone number ani email.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 206. PrivateDrop. Apple continuity i cross-device services.

Najpierw rozpisz przebieg PrivateDrop krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 207
## layout
bullet
## slide title
PrivateDrop — Jak pęka
## bullets
- Warunek powodzenia: PrivateDrop zastępuje leaked contact checks mechanizmem PSI, żeby nie ujawniać phone number ani email.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 207. PrivateDrop. Apple continuity i cross-device services.

Tu interesuje nas dokładnie moment, w którym PrivateDrop przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 208
## layout
bullet
## slide title
PrivateDrop — Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 208. PrivateDrop. Apple continuity i cross-device services.

Obrona dla PrivateDrop musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 209
## layout
definition
## slide title
AWDL and BLE — Co to jest
## term
AWDL and BLE
## definition
AWDL i BLE niosą niskopoziomowy ruch discovery oraz widoczny dla użytkownika stan Continuity.
## teleprompter:
Slajd 209. AWDL and BLE. Apple continuity i cross-device services.

AWDL i BLE niosą niskopoziomowy ruch discovery oraz widoczny dla użytkownika stan Continuity. To jest punkt startowy do zrozumienia, jak działa cały blok o apple continuity i cross-device services.

Dlaczego to nie jest tylko hasło. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 210
## layout
bullet
## slide title
AWDL and BLE — Jak działa
## bullets
- Krok 1: AWDL i BLE niosą niskopoziomowy ruch discovery oraz widoczny dla użytkownika stan Continuity.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 210. AWDL and BLE. Apple continuity i cross-device services.

Najpierw rozpisz przebieg AWDL and BLE krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 211
## layout
bullet
## slide title
AWDL and BLE — Jak pęka
## bullets
- Warunek powodzenia: AWDL i BLE niosą niskopoziomowy ruch discovery oraz widoczny dla użytkownika stan Continuity.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 211. AWDL and BLE. Apple continuity i cross-device services.

Tu interesuje nas dokładnie moment, w którym AWDL and BLE przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 212
## layout
bullet
## slide title
AWDL and BLE — Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 212. AWDL and BLE. Apple continuity i cross-device services.

Obrona dla AWDL and BLE musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 213
## layout
definition
## slide title
Cross-device identity — Co to jest
## term
Cross-device identity
## definition
Messagi Continuity mogą ujawniać typ urządzenia, wersję OS i zachowanie pasywnemu obserwatorowi.
## teleprompter:
Slajd 213. Cross-device identity. Apple continuity i cross-device services.

Messagi Continuity mogą ujawniać typ urządzenia, wersję OS i zachowanie pasywnemu obserwatorowi. To jest punkt startowy do zrozumienia, jak działa cały blok o apple continuity i cross-device services.

Dlaczego to nie jest tylko hasło. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 214
## layout
bullet
## slide title
Cross-device identity — Jak działa
## bullets
- Krok 1: Messagi Continuity mogą ujawniać typ urządzenia, wersję OS i zachowanie pasywnemu obserwatorowi.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 214. Cross-device identity. Apple continuity i cross-device services.

Najpierw rozpisz przebieg Cross-device identity krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 215
## layout
bullet
## slide title
Cross-device identity — Jak pęka
## bullets
- Warunek powodzenia: Messagi Continuity mogą ujawniać typ urządzenia, wersję OS i zachowanie pasywnemu obserwatorowi.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 215. Cross-device identity. Apple continuity i cross-device services.

Tu interesuje nas dokładnie moment, w którym Cross-device identity przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 216
## layout
bullet
## slide title
Cross-device identity — Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 216. Cross-device identity. Apple continuity i cross-device services.

Obrona dla Cross-device identity musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 217
## layout
definition
## slide title
Spoof relay downgrade — Co to jest
## term
Spoof relay downgrade
## definition
Atakujący może spoofować, relayować albo downgrade'ować discovery i authentication.
## teleprompter:
Slajd 217. Spoof relay downgrade. Apple continuity i cross-device services.

Atakujący może spoofować, relayować albo downgrade'ować discovery i authentication. To jest punkt startowy do zrozumienia, jak działa cały blok o apple continuity i cross-device services.

Dlaczego to nie jest tylko hasło. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 218
## layout
bullet
## slide title
Spoof relay downgrade — Jak działa
## bullets
- Krok 1: Atakujący może spoofować, relayować albo downgrade'ować discovery i authentication.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 218. Spoof relay downgrade. Apple continuity i cross-device services.

Najpierw rozpisz przebieg Spoof relay downgrade krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 219
## layout
bullet
## slide title
Spoof relay downgrade — Jak pęka
## bullets
- Warunek powodzenia: Atakujący może spoofować, relayować albo downgrade'ować discovery i authentication.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 219. Spoof relay downgrade. Apple continuity i cross-device services.

Tu interesuje nas dokładnie moment, w którym Spoof relay downgrade przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 220
## layout
bullet
## slide title
Spoof relay downgrade — Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 220. Spoof relay downgrade. Apple continuity i cross-device services.

Obrona dla Spoof relay downgrade musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 221
## layout
definition
## slide title
Transport and state machine — Co to jest
## term
Transport and state machine
## definition
Structured analysis wymaga obserwacji całego state machine na różnych vantage points macOS.
## teleprompter:
Slajd 221. Transport and state machine. Apple continuity i cross-device services.

Structured analysis wymaga obserwacji całego state machine na różnych vantage points macOS. To jest punkt startowy do zrozumienia, jak działa cały blok o apple continuity i cross-device services.

Dlaczego to nie jest tylko hasło. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 222
## layout
bullet
## slide title
Transport and state machine — Jak działa
## bullets
- Krok 1: Structured analysis wymaga obserwacji całego state machine na różnych vantage points macOS.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 222. Transport and state machine. Apple continuity i cross-device services.

Najpierw rozpisz przebieg Transport and state machine krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 223
## layout
bullet
## slide title
Transport and state machine — Jak pęka
## bullets
- Warunek powodzenia: Structured analysis wymaga obserwacji całego state machine na różnych vantage points macOS.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 223. Transport and state machine. Apple continuity i cross-device services.

Tu interesuje nas dokładnie moment, w którym Transport and state machine przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 224
## layout
bullet
## slide title
Transport and state machine — Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 224. Transport and state machine. Apple continuity i cross-device services.

Obrona dla Transport and state machine musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 225
## layout
definition
## slide title
Packet analysis — Co to jest
## term
Packet analysis
## definition
Packet captures pokazują, które pola są szyfrowane, a które metadata lecą jawnie.
## teleprompter:
Slajd 225. Packet analysis. Apple continuity i cross-device services.

Packet captures pokazują, które pola są szyfrowane, a które metadata lecą jawnie. To jest punkt startowy do zrozumienia, jak działa cały blok o apple continuity i cross-device services.

Dlaczego to nie jest tylko hasło. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 226
## layout
bullet
## slide title
Packet analysis — Jak działa
## bullets
- Krok 1: Packet captures pokazują, które pola są szyfrowane, a które metadata lecą jawnie.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 226. Packet analysis. Apple continuity i cross-device services.

Najpierw rozpisz przebieg Packet analysis krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 227
## layout
bullet
## slide title
Packet analysis — Jak pęka
## bullets
- Warunek powodzenia: Packet captures pokazują, które pola są szyfrowane, a które metadata lecą jawnie.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 227. Packet analysis. Apple continuity i cross-device services.

Tu interesuje nas dokładnie moment, w którym Packet analysis przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 228
## layout
bullet
## slide title
Packet analysis — Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 228. Packet analysis. Apple continuity i cross-device services.

Obrona dla Packet analysis musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 229
## layout
definition
## slide title
Mitigations — Co to jest
## term
Mitigations
## definition
PSI, większa ostrożność w contact discovery i twardsza kontrola widoczności ograniczają wyciek.
## teleprompter:
Slajd 229. Mitigations. Apple continuity i cross-device services.

PSI, większa ostrożność w contact discovery i twardsza kontrola widoczności ograniczają wyciek. To jest punkt startowy do zrozumienia, jak działa cały blok o apple continuity i cross-device services.

Dlaczego to nie jest tylko hasło. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 230
## layout
bullet
## slide title
Mitigations — Jak działa
## bullets
- Krok 1: PSI, większa ostrożność w contact discovery i twardsza kontrola widoczności ograniczają wyciek.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 230. Mitigations. Apple continuity i cross-device services.

Najpierw rozpisz przebieg Mitigations krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 231
## layout
bullet
## slide title
Mitigations — Jak pęka
## bullets
- Warunek powodzenia: PSI, większa ostrożność w contact discovery i twardsza kontrola widoczności ograniczają wyciek.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 231. Mitigations. Apple continuity i cross-device services.

Tu interesuje nas dokładnie moment, w którym Mitigations przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 232
## layout
bullet
## slide title
Mitigations — Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 232. Mitigations. Apple continuity i cross-device services.

Obrona dla Mitigations musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 233
## layout
definition
## slide title
Test matrix — Co to jest
## term
Test matrix
## definition
Dobry test matrix zmienia stan urządzenia, odległość i użyty transport.
## teleprompter:
Slajd 233. Test matrix. Apple continuity i cross-device services.

Dobry test matrix zmienia stan urządzenia, odległość i użyty transport. To jest punkt startowy do zrozumienia, jak działa cały blok o apple continuity i cross-device services.

Dlaczego to nie jest tylko hasło. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 234
## layout
bullet
## slide title
Test matrix — Jak działa
## bullets
- Krok 1: Dobry test matrix zmienia stan urządzenia, odległość i użyty transport.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 234. Test matrix. Apple continuity i cross-device services.

Najpierw rozpisz przebieg Test matrix krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 235
## layout
bullet
## slide title
Test matrix — Jak pęka
## bullets
- Warunek powodzenia: Dobry test matrix zmienia stan urządzenia, odległość i użyty transport.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 235. Test matrix. Apple continuity i cross-device services.

Tu interesuje nas dokładnie moment, w którym Test matrix przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 236
## layout
bullet
## slide title
Test matrix — Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 236. Test matrix. Apple continuity i cross-device services.

Obrona dla Test matrix musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 237
## layout
definition
## slide title
Android comparison — Co to jest
## term
Android comparison
## definition
Android local-network policy daje użyteczny kontrast dla zawsze aktywnych kanałów continuity.
## teleprompter:
Slajd 237. Android comparison. Apple continuity i cross-device services.

Android local-network policy daje użyteczny kontrast dla zawsze aktywnych kanałów continuity. To jest punkt startowy do zrozumienia, jak działa cały blok o apple continuity i cross-device services.

Dlaczego to nie jest tylko hasło. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 238
## layout
bullet
## slide title
Android comparison — Jak działa
## bullets
- Krok 1: Android local-network policy daje użyteczny kontrast dla zawsze aktywnych kanałów continuity.
- Krok 2: W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 238. Android comparison. Apple continuity i cross-device services.

Najpierw rozpisz przebieg Android comparison krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 239
## layout
bullet
## slide title
Android comparison — Jak pęka
## bullets
- Warunek powodzenia: Android local-network policy daje użyteczny kontrast dla zawsze aktywnych kanałów continuity.
- Kontrola atakującego: Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 239. Android comparison. Apple continuity i cross-device services.

Tu interesuje nas dokładnie moment, w którym Android comparison przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 240
## layout
bullet
## slide title
Android comparison — Jak się bronić
## bullets
- Reguła: PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 240. Android comparison. Apple continuity i cross-device services.

Obrona dla Android comparison musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.
