#slide 145
## layout
definition
## slide title
Retention vs disposal — Co to jest
## term
Retention vs disposal
## definition
Retencja decyduje o czasie życia danych, a disposal o ich fizycznym zniknięciu.
## teleprompter:
Slajd 145. Retention vs disposal. Retencja i secure deletion.

Definicja i granica pojęcia. Retention vs disposal w tym miejscu oznacza dokładnie: Retencja decyduje o czasie życia danych, a disposal o ich fizycznym zniknięciu. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Dlaczego to nie jest tylko hasło. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 146
## layout
bullet
## slide title
Retention vs disposal — Jak działa
## bullets
- Krok 1: Retencja decyduje o czasie życia danych, a disposal o ich fizycznym zniknięciu.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 146. Retention vs disposal. Retencja i secure deletion.

Wejście i stan początkowy. Retention vs disposal w tym miejscu oznacza dokładnie: Retencja decyduje o czasie życia danych, a disposal o ich fizycznym zniknięciu. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Krok po kroku przez przepływ. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 147
## layout
bullet
## slide title
Retention vs disposal — Jak pęka
## bullets
- Warunek powodzenia: Retencja decyduje o czasie życia danych, a disposal o ich fizycznym zniknięciu.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 147. Retention vs disposal. Retencja i secure deletion.

Warunek powodzenia ataku. Retention vs disposal w tym miejscu oznacza dokładnie: Retencja decyduje o czasie życia danych, a disposal o ich fizycznym zniknięciu. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Co kontroluje atakujący. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 148
## layout
bullet
## slide title
Retention vs disposal — Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 148. Retention vs disposal. Retencja i secure deletion.

Reguła i miejsce egzekwowania. Retention vs disposal w tym miejscu oznacza dokładnie: Retencja decyduje o czasie życia danych, a disposal o ich fizycznym zniknięciu. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Minimalny zakres dostępu. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 149
## layout
definition
## slide title
Why delete fails — Co to jest
## term
Why delete fails
## definition
Delete zawodzi przez remanencję danych i metadanych.
## teleprompter:
Slajd 149. Why delete fails. Retencja i secure deletion.

Definicja i granica pojęcia. Why delete fails w tym miejscu oznacza dokładnie: Delete zawodzi przez remanencję danych i metadanych. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Dlaczego to nie jest tylko hasło. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 150
## layout
bullet
## slide title
Why delete fails — Jak działa
## bullets
- Krok 1: Delete zawodzi przez remanencję danych i metadanych.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 150. Why delete fails. Retencja i secure deletion.

Wejście i stan początkowy. Why delete fails w tym miejscu oznacza dokładnie: Delete zawodzi przez remanencję danych i metadanych. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Krok po kroku przez przepływ. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 151
## layout
bullet
## slide title
Why delete fails — Jak pęka
## bullets
- Warunek powodzenia: Delete zawodzi przez remanencję danych i metadanych.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 151. Why delete fails. Retencja i secure deletion.

Warunek powodzenia ataku. Why delete fails w tym miejscu oznacza dokładnie: Delete zawodzi przez remanencję danych i metadanych. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Co kontroluje atakujący. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 152
## layout
bullet
## slide title
Why delete fails — Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 152. Why delete fails. Retencja i secure deletion.

Reguła i miejsce egzekwowania. Why delete fails w tym miejscu oznacza dokładnie: Delete zawodzi przez remanencję danych i metadanych. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Minimalny zakres dostępu. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 153
## layout
definition
## slide title
Log-structured storage — Co to jest
## term
Log-structured storage
## definition
Log-structured filesystems dopisują nowe bloki i czyszczą stare dopiero później.
## teleprompter:
Slajd 153. Log-structured storage. Retencja i secure deletion.

Definicja i granica pojęcia. Log-structured storage w tym miejscu oznacza dokładnie: Log-structured filesystems dopisują nowe bloki i czyszczą stare dopiero później. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Dlaczego to nie jest tylko hasło. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 154
## layout
bullet
## slide title
Log-structured storage — Jak działa
## bullets
- Krok 1: Log-structured filesystems dopisują nowe bloki i czyszczą stare dopiero później.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 154. Log-structured storage. Retencja i secure deletion.

Wejście i stan początkowy. Log-structured storage w tym miejscu oznacza dokładnie: Log-structured filesystems dopisują nowe bloki i czyszczą stare dopiero później. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Krok po kroku przez przepływ. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 155
## layout
bullet
## slide title
Log-structured storage — Jak pęka
## bullets
- Warunek powodzenia: Log-structured filesystems dopisują nowe bloki i czyszczą stare dopiero później.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 155. Log-structured storage. Retencja i secure deletion.

Warunek powodzenia ataku. Log-structured storage w tym miejscu oznacza dokładnie: Log-structured filesystems dopisują nowe bloki i czyszczą stare dopiero później. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Co kontroluje atakujący. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 156
## layout
bullet
## slide title
Log-structured storage — Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 156. Log-structured storage. Retencja i secure deletion.

Reguła i miejsce egzekwowania. Log-structured storage w tym miejscu oznacza dokładnie: Log-structured filesystems dopisują nowe bloki i czyszczą stare dopiero później. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Minimalny zakres dostępu. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 157
## layout
definition
## slide title
YAFFS example — Co to jest
## term
YAFFS example
## definition
YAFFS na flashu zostawia stare wersje, bo garbage collection nie kasuje wszystkiego od razu.
## teleprompter:
Slajd 157. YAFFS example. Retencja i secure deletion.

Definicja i granica pojęcia. YAFFS example w tym miejscu oznacza dokładnie: YAFFS na flashu zostawia stare wersje, bo garbage collection nie kasuje wszystkiego od razu. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Dlaczego to nie jest tylko hasło. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 158
## layout
bullet
## slide title
YAFFS example — Jak działa
## bullets
- Krok 1: YAFFS na flashu zostawia stare wersje, bo garbage collection nie kasuje wszystkiego od razu.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 158. YAFFS example. Retencja i secure deletion.

Wejście i stan początkowy. YAFFS example w tym miejscu oznacza dokładnie: YAFFS na flashu zostawia stare wersje, bo garbage collection nie kasuje wszystkiego od razu. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Krok po kroku przez przepływ. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 159
## layout
bullet
## slide title
YAFFS example — Jak pęka
## bullets
- Warunek powodzenia: YAFFS na flashu zostawia stare wersje, bo garbage collection nie kasuje wszystkiego od razu.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 159. YAFFS example. Retencja i secure deletion.

Warunek powodzenia ataku. YAFFS example w tym miejscu oznacza dokładnie: YAFFS na flashu zostawia stare wersje, bo garbage collection nie kasuje wszystkiego od razu. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Co kontroluje atakujący. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 160
## layout
bullet
## slide title
YAFFS example — Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 160. YAFFS example. Retencja i secure deletion.

Reguła i miejsce egzekwowania. YAFFS example w tym miejscu oznacza dokładnie: YAFFS na flashu zostawia stare wersje, bo garbage collection nie kasuje wszystkiego od razu. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Minimalny zakres dostępu. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 161
## layout
definition
## slide title
FTL mapping — Co to jest
## term
FTL mapping
## definition
FTL mapuje logiczne bloki na fizyczne bloki poza kontrolą filesystemu.
## teleprompter:
Slajd 161. FTL mapping. Retencja i secure deletion.

Definicja i granica pojęcia. FTL mapping w tym miejscu oznacza dokładnie: FTL mapuje logiczne bloki na fizyczne bloki poza kontrolą filesystemu. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Dlaczego to nie jest tylko hasło. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 162
## layout
bullet
## slide title
FTL mapping — Jak działa
## bullets
- Krok 1: FTL mapuje logiczne bloki na fizyczne bloki poza kontrolą filesystemu.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 162. FTL mapping. Retencja i secure deletion.

Wejście i stan początkowy. FTL mapping w tym miejscu oznacza dokładnie: FTL mapuje logiczne bloki na fizyczne bloki poza kontrolą filesystemu. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Krok po kroku przez przepływ. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 163
## layout
bullet
## slide title
FTL mapping — Jak pęka
## bullets
- Warunek powodzenia: FTL mapuje logiczne bloki na fizyczne bloki poza kontrolą filesystemu.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 163. FTL mapping. Retencja i secure deletion.

Warunek powodzenia ataku. FTL mapping w tym miejscu oznacza dokładnie: FTL mapuje logiczne bloki na fizyczne bloki poza kontrolą filesystemu. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Co kontroluje atakujący. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 164
## layout
bullet
## slide title
FTL mapping — Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 164. FTL mapping. Retencja i secure deletion.

Reguła i miejsce egzekwowania. FTL mapping w tym miejscu oznacza dokładnie: FTL mapuje logiczne bloki na fizyczne bloki poza kontrolą filesystemu. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Minimalny zakres dostępu. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 165
## layout
definition
## slide title
Overwrite problem — Co to jest
## term
Overwrite problem
## definition
Overwrite nie daje gwarancji, że nadpiszesz dokładnie ten fizyczny blok, który chcesz usunąć.
## teleprompter:
Slajd 165. Overwrite problem. Retencja i secure deletion.

Definicja i granica pojęcia. Overwrite problem w tym miejscu oznacza dokładnie: Overwrite nie daje gwarancji, że nadpiszesz dokładnie ten fizyczny blok, który chcesz usunąć. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Dlaczego to nie jest tylko hasło. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 166
## layout
bullet
## slide title
Overwrite problem — Jak działa
## bullets
- Krok 1: Overwrite nie daje gwarancji, że nadpiszesz dokładnie ten fizyczny blok, który chcesz usunąć.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 166. Overwrite problem. Retencja i secure deletion.

Wejście i stan początkowy. Overwrite problem w tym miejscu oznacza dokładnie: Overwrite nie daje gwarancji, że nadpiszesz dokładnie ten fizyczny blok, który chcesz usunąć. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Krok po kroku przez przepływ. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 167
## layout
bullet
## slide title
Overwrite problem — Jak pęka
## bullets
- Warunek powodzenia: Overwrite nie daje gwarancji, że nadpiszesz dokładnie ten fizyczny blok, który chcesz usunąć.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 167. Overwrite problem. Retencja i secure deletion.

Warunek powodzenia ataku. Overwrite problem w tym miejscu oznacza dokładnie: Overwrite nie daje gwarancji, że nadpiszesz dokładnie ten fizyczny blok, który chcesz usunąć. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Co kontroluje atakujący. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 168
## layout
bullet
## slide title
Overwrite problem — Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 168. Overwrite problem. Retencja i secure deletion.

Reguła i miejsce egzekwowania. Overwrite problem w tym miejscu oznacza dokładnie: Overwrite nie daje gwarancji, że nadpiszesz dokładnie ten fizyczny blok, który chcesz usunąć. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Minimalny zakres dostępu. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 169
## layout
definition
## slide title
Encryption limitation — Co to jest
## term
Encryption limitation
## definition
Sama kryptografia nie pomaga, jeśli stare kopie lub klucze nadal są dostępne.
## teleprompter:
Slajd 169. Encryption limitation. Retencja i secure deletion.

Definicja i granica pojęcia. Encryption limitation w tym miejscu oznacza dokładnie: Sama kryptografia nie pomaga, jeśli stare kopie lub klucze nadal są dostępne. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Dlaczego to nie jest tylko hasło. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 170
## layout
bullet
## slide title
Encryption limitation — Jak działa
## bullets
- Krok 1: Sama kryptografia nie pomaga, jeśli stare kopie lub klucze nadal są dostępne.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 170. Encryption limitation. Retencja i secure deletion.

Wejście i stan początkowy. Encryption limitation w tym miejscu oznacza dokładnie: Sama kryptografia nie pomaga, jeśli stare kopie lub klucze nadal są dostępne. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Krok po kroku przez przepływ. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 171
## layout
bullet
## slide title
Encryption limitation — Jak pęka
## bullets
- Warunek powodzenia: Sama kryptografia nie pomaga, jeśli stare kopie lub klucze nadal są dostępne.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 171. Encryption limitation. Retencja i secure deletion.

Warunek powodzenia ataku. Encryption limitation w tym miejscu oznacza dokładnie: Sama kryptografia nie pomaga, jeśli stare kopie lub klucze nadal są dostępne. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Co kontroluje atakujący. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 172
## layout
bullet
## slide title
Encryption limitation — Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 172. Encryption limitation. Retencja i secure deletion.

Reguła i miejsce egzekwowania. Encryption limitation w tym miejscu oznacza dokładnie: Sama kryptografia nie pomaga, jeśli stare kopie lub klucze nadal są dostępne. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Minimalny zakres dostępu. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 173
## layout
definition
## slide title
Purge algorithm — Co to jest
## term
Purge algorithm
## definition
Purge chce realnie zniszczyć lub przenieść dane aż recovery przestaje być praktyczne.
## teleprompter:
Slajd 173. Purge algorithm. Retencja i secure deletion.

Definicja i granica pojęcia. Purge algorithm w tym miejscu oznacza dokładnie: Purge chce realnie zniszczyć lub przenieść dane aż recovery przestaje być praktyczne. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Dlaczego to nie jest tylko hasło. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 174
## layout
bullet
## slide title
Purge algorithm — Jak działa
## bullets
- Krok 1: Purge chce realnie zniszczyć lub przenieść dane aż recovery przestaje być praktyczne.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 174. Purge algorithm. Retencja i secure deletion.

Wejście i stan początkowy. Purge algorithm w tym miejscu oznacza dokładnie: Purge chce realnie zniszczyć lub przenieść dane aż recovery przestaje być praktyczne. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Krok po kroku przez przepływ. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 175
## layout
bullet
## slide title
Purge algorithm — Jak pęka
## bullets
- Warunek powodzenia: Purge chce realnie zniszczyć lub przenieść dane aż recovery przestaje być praktyczne.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 175. Purge algorithm. Retencja i secure deletion.

Warunek powodzenia ataku. Purge algorithm w tym miejscu oznacza dokładnie: Purge chce realnie zniszczyć lub przenieść dane aż recovery przestaje być praktyczne. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Co kontroluje atakujący. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 176
## layout
bullet
## slide title
Purge algorithm — Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 176. Purge algorithm. Retencja i secure deletion.

Reguła i miejsce egzekwowania. Purge algorithm w tym miejscu oznacza dokładnie: Purge chce realnie zniszczyć lub przenieść dane aż recovery przestaje być praktyczne. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Minimalny zakres dostępu. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 177
## layout
definition
## slide title
Ballooning algorithm — Co to jest
## term
Ballooning algorithm
## definition
Ballooning zjada wolne miejsce, by wymusić wypchnięcie bloku celu.
## teleprompter:
Slajd 177. Ballooning algorithm. Retencja i secure deletion.

Definicja i granica pojęcia. Ballooning algorithm w tym miejscu oznacza dokładnie: Ballooning zjada wolne miejsce, by wymusić wypchnięcie bloku celu. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Dlaczego to nie jest tylko hasło. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 178
## layout
bullet
## slide title
Ballooning algorithm — Jak działa
## bullets
- Krok 1: Ballooning zjada wolne miejsce, by wymusić wypchnięcie bloku celu.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 178. Ballooning algorithm. Retencja i secure deletion.

Wejście i stan początkowy. Ballooning algorithm w tym miejscu oznacza dokładnie: Ballooning zjada wolne miejsce, by wymusić wypchnięcie bloku celu. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Krok po kroku przez przepływ. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 179
## layout
bullet
## slide title
Ballooning algorithm — Jak pęka
## bullets
- Warunek powodzenia: Ballooning zjada wolne miejsce, by wymusić wypchnięcie bloku celu.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 179. Ballooning algorithm. Retencja i secure deletion.

Warunek powodzenia ataku. Ballooning algorithm w tym miejscu oznacza dokładnie: Ballooning zjada wolne miejsce, by wymusić wypchnięcie bloku celu. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Co kontroluje atakujący. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 180
## layout
bullet
## slide title
Ballooning algorithm — Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 180. Ballooning algorithm. Retencja i secure deletion.

Reguła i miejsce egzekwowania. Ballooning algorithm w tym miejscu oznacza dokładnie: Ballooning zjada wolne miejsce, by wymusić wypchnięcie bloku celu. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Minimalny zakres dostępu. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 181
## layout
definition
## slide title
Zero overwriting — Co to jest
## term
Zero overwriting
## definition
Zero overwriting wypełnia obszar i potem vacuumuje resztki.
## teleprompter:
Slajd 181. Zero overwriting. Retencja i secure deletion.

Definicja i granica pojęcia. Zero overwriting w tym miejscu oznacza dokładnie: Zero overwriting wypełnia obszar i potem vacuumuje resztki. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Dlaczego to nie jest tylko hasło. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 182
## layout
bullet
## slide title
Zero overwriting — Jak działa
## bullets
- Krok 1: Zero overwriting wypełnia obszar i potem vacuumuje resztki.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 182. Zero overwriting. Retencja i secure deletion.

Wejście i stan początkowy. Zero overwriting w tym miejscu oznacza dokładnie: Zero overwriting wypełnia obszar i potem vacuumuje resztki. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Krok po kroku przez przepływ. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 183
## layout
bullet
## slide title
Zero overwriting — Jak pęka
## bullets
- Warunek powodzenia: Zero overwriting wypełnia obszar i potem vacuumuje resztki.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 183. Zero overwriting. Retencja i secure deletion.

Warunek powodzenia ataku. Zero overwriting w tym miejscu oznacza dokładnie: Zero overwriting wypełnia obszar i potem vacuumuje resztki. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Co kontroluje atakujący. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 184
## layout
bullet
## slide title
Zero overwriting — Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 184. Zero overwriting. Retencja i secure deletion.

Reguła i miejsce egzekwowania. Zero overwriting w tym miejscu oznacza dokładnie: Zero overwriting wypełnia obszar i potem vacuumuje resztki. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Minimalny zakres dostępu. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 185
## layout
definition
## slide title
Versioned file system — Co to jest
## term
Versioned file system
## definition
Snapshoty i historia wersji komplikują kasowanie, bo stare stany nadal istnieją.
## teleprompter:
Slajd 185. Versioned file system. Retencja i secure deletion.

Definicja i granica pojęcia. Versioned file system w tym miejscu oznacza dokładnie: Snapshoty i historia wersji komplikują kasowanie, bo stare stany nadal istnieją. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Dlaczego to nie jest tylko hasło. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 186
## layout
bullet
## slide title
Versioned file system — Jak działa
## bullets
- Krok 1: Snapshoty i historia wersji komplikują kasowanie, bo stare stany nadal istnieją.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 186. Versioned file system. Retencja i secure deletion.

Wejście i stan początkowy. Versioned file system w tym miejscu oznacza dokładnie: Snapshoty i historia wersji komplikują kasowanie, bo stare stany nadal istnieją. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Krok po kroku przez przepływ. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 187
## layout
bullet
## slide title
Versioned file system — Jak pęka
## bullets
- Warunek powodzenia: Snapshoty i historia wersji komplikują kasowanie, bo stare stany nadal istnieją.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 187. Versioned file system. Retencja i secure deletion.

Warunek powodzenia ataku. Versioned file system w tym miejscu oznacza dokładnie: Snapshoty i historia wersji komplikują kasowanie, bo stare stany nadal istnieją. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Co kontroluje atakujący. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 188
## layout
bullet
## slide title
Versioned file system — Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 188. Versioned file system. Retencja i secure deletion.

Reguła i miejsce egzekwowania. Versioned file system w tym miejscu oznacza dokładnie: Snapshoty i historia wersji komplikują kasowanie, bo stare stany nadal istnieją. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Minimalny zakres dostępu. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 189
## layout
definition
## slide title
Forensic verification — Co to jest
## term
Forensic verification
## definition
Forensic verification sprawdza, czy po usunięciu da się jeszcze odzyskać treść lub jej ślady.
## teleprompter:
Slajd 189. Forensic verification. Retencja i secure deletion.

Definicja i granica pojęcia. Forensic verification w tym miejscu oznacza dokładnie: Forensic verification sprawdza, czy po usunięciu da się jeszcze odzyskać treść lub jej ślady. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Dlaczego to nie jest tylko hasło. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 190
## layout
bullet
## slide title
Forensic verification — Jak działa
## bullets
- Krok 1: Forensic verification sprawdza, czy po usunięciu da się jeszcze odzyskać treść lub jej ślady.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 190. Forensic verification. Retencja i secure deletion.

Wejście i stan początkowy. Forensic verification w tym miejscu oznacza dokładnie: Forensic verification sprawdza, czy po usunięciu da się jeszcze odzyskać treść lub jej ślady. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Krok po kroku przez przepływ. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 191
## layout
bullet
## slide title
Forensic verification — Jak pęka
## bullets
- Warunek powodzenia: Forensic verification sprawdza, czy po usunięciu da się jeszcze odzyskać treść lub jej ślady.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 191. Forensic verification. Retencja i secure deletion.

Warunek powodzenia ataku. Forensic verification w tym miejscu oznacza dokładnie: Forensic verification sprawdza, czy po usunięciu da się jeszcze odzyskać treść lub jej ślady. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Co kontroluje atakujący. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 192
## layout
bullet
## slide title
Forensic verification — Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 192. Forensic verification. Retencja i secure deletion.

Reguła i miejsce egzekwowania. Forensic verification w tym miejscu oznacza dokładnie: Forensic verification sprawdza, czy po usunięciu da się jeszcze odzyskać treść lub jej ślady. Na tle tego bloku chodzi o: Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.

Minimalny zakres dostępu. Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.
