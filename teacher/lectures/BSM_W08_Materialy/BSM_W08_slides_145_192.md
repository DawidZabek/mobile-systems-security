#slide 145
## layout
definition
## slide title
Retention vs disposal
## subtitle
Co to jest
## term
Retention vs disposal
## definition
Retencja decyduje o czasie życia danych, a disposal o ich fizycznym zniknięciu.
## teleprompter:
Slajd 145. Retention vs disposal. Retencja i secure deletion.

Retencja decyduje o czasie życia danych, a disposal o ich fizycznym zniknięciu.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. To właśnie tutaj widać, jak ten mechanizm wchodzi w realny przepływ systemu i aplikacji.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Atak zaczyna się tam, gdzie ktoś traktuje lokalny sygnał, wybrane URI albo rekord protokołu jak już zweryfikowany.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. To oznacza, że w obronie trzeba wskazać dokładny punkt egzekwowania i test, który potwierdzi odmowę albo ograniczenie.

#slide 146
## layout
bullet
## slide title
Retention vs disposal
## subtitle
Jak działa
## bullets
- Krok 1: Retencja decyduje o czasie życia danych, a disposal o ich fizycznym zniknięciu.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 146. Retention vs disposal. Retencja i secure deletion.

Najpierw rozpisz przebieg Retention vs disposal krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. W tej części trzeba pokazać kolejność zdarzeń, bo właśnie kolejność zdradza, gdzie system przejmuje kontrolę, a gdzie zostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu tej sekwencji masz konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 147
## layout
bullet
## slide title
Retention vs disposal
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Retencja decyduje o czasie życia danych, a disposal o ich fizycznym zniknięciu.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 147. Retention vs disposal. Retencja i secure deletion.

Tu interesuje nas dokładnie moment, w którym Retention vs disposal przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu interesuje nas dokładnie punkt, w którym przeciwnik zaczyna sterować danymi, które potem system bierze za prawdziwe.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 148
## layout
bullet
## slide title
Retention vs disposal
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 148. Retention vs disposal. Retencja i secure deletion.

Obrona dla Retention vs disposal musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Obrona ma znaczyć więcej niż 'zablokować'. Trzeba podać warunek, wersję systemu, flagę albo mechanizm, który faktycznie zmienia wynik.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 149
## layout
definition
## slide title
Why delete fails
## subtitle
Co to jest
## term
Why delete fails
## definition
Delete zawodzi przez remanencję danych i metadanych.
## teleprompter:
Slajd 149. Why delete fails. Retencja i secure deletion.

Delete zawodzi przez remanencję danych i metadanych.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. To właśnie tutaj widać, jak ten mechanizm wchodzi w realny przepływ systemu i aplikacji.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Atak zaczyna się tam, gdzie ktoś traktuje lokalny sygnał, wybrane URI albo rekord protokołu jak już zweryfikowany.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. To oznacza, że w obronie trzeba wskazać dokładny punkt egzekwowania i test, który potwierdzi odmowę albo ograniczenie.

#slide 150
## layout
bullet
## slide title
Why delete fails
## subtitle
Jak działa
## bullets
- Krok 1: Delete zawodzi przez remanencję danych i metadanych.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 150. Why delete fails. Retencja i secure deletion.

Najpierw rozpisz przebieg Why delete fails krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. W tej części trzeba pokazać kolejność zdarzeń, bo właśnie kolejność zdradza, gdzie system przejmuje kontrolę, a gdzie zostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu tej sekwencji masz konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 151
## layout
bullet
## slide title
Why delete fails
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Delete zawodzi przez remanencję danych i metadanych.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 151. Why delete fails. Retencja i secure deletion.

Tu interesuje nas dokładnie moment, w którym Why delete fails przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu interesuje nas dokładnie punkt, w którym przeciwnik zaczyna sterować danymi, które potem system bierze za prawdziwe.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 152
## layout
bullet
## slide title
Why delete fails
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 152. Why delete fails. Retencja i secure deletion.

Obrona dla Why delete fails musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Obrona ma znaczyć więcej niż 'zablokować'. Trzeba podać warunek, wersję systemu, flagę albo mechanizm, który faktycznie zmienia wynik.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 153
## layout
definition
## slide title
Log-structured storage
## subtitle
Co to jest
## term
Log-structured storage
## definition
Log-structured filesystems dopisują nowe bloki i czyszczą stare dopiero później.
## teleprompter:
Slajd 153. Log-structured storage. Retencja i secure deletion.

Log-structured filesystems dopisują nowe bloki i czyszczą stare dopiero później.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. To właśnie tutaj widać, jak ten mechanizm wchodzi w realny przepływ systemu i aplikacji.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Atak zaczyna się tam, gdzie ktoś traktuje lokalny sygnał, wybrane URI albo rekord protokołu jak już zweryfikowany.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. To oznacza, że w obronie trzeba wskazać dokładny punkt egzekwowania i test, który potwierdzi odmowę albo ograniczenie.

#slide 154
## layout
bullet
## slide title
Log-structured storage
## subtitle
Jak działa
## bullets
- Krok 1: Log-structured filesystems dopisują nowe bloki i czyszczą stare dopiero później.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 154. Log-structured storage. Retencja i secure deletion.

Najpierw rozpisz przebieg Log-structured storage krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. W tej części trzeba pokazać kolejność zdarzeń, bo właśnie kolejność zdradza, gdzie system przejmuje kontrolę, a gdzie zostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu tej sekwencji masz konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 155
## layout
bullet
## slide title
Log-structured storage
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Log-structured filesystems dopisują nowe bloki i czyszczą stare dopiero później.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 155. Log-structured storage. Retencja i secure deletion.

Tu interesuje nas dokładnie moment, w którym Log-structured storage przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu interesuje nas dokładnie punkt, w którym przeciwnik zaczyna sterować danymi, które potem system bierze za prawdziwe.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 156
## layout
bullet
## slide title
Log-structured storage
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 156. Log-structured storage. Retencja i secure deletion.

Obrona dla Log-structured storage musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Obrona ma znaczyć więcej niż 'zablokować'. Trzeba podać warunek, wersję systemu, flagę albo mechanizm, który faktycznie zmienia wynik.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 157
## layout
definition
## slide title
YAFFS example
## subtitle
Co to jest
## term
YAFFS example
## definition
YAFFS na flashu zostawia stare wersje, bo garbage collection nie kasuje wszystkiego od razu.
## teleprompter:
Slajd 157. YAFFS example. Retencja i secure deletion.

YAFFS na flashu zostawia stare wersje, bo garbage collection nie kasuje wszystkiego od razu.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. To właśnie tutaj widać, jak ten mechanizm wchodzi w realny przepływ systemu i aplikacji.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Atak zaczyna się tam, gdzie ktoś traktuje lokalny sygnał, wybrane URI albo rekord protokołu jak już zweryfikowany.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. To oznacza, że w obronie trzeba wskazać dokładny punkt egzekwowania i test, który potwierdzi odmowę albo ograniczenie.

#slide 158
## layout
bullet
## slide title
YAFFS example
## subtitle
Jak działa
## bullets
- Krok 1: YAFFS na flashu zostawia stare wersje, bo garbage collection nie kasuje wszystkiego od razu.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 158. YAFFS example. Retencja i secure deletion.

Najpierw rozpisz przebieg YAFFS example krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. W tej części trzeba pokazać kolejność zdarzeń, bo właśnie kolejność zdradza, gdzie system przejmuje kontrolę, a gdzie zostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu tej sekwencji masz konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 159
## layout
bullet
## slide title
YAFFS example
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: YAFFS na flashu zostawia stare wersje, bo garbage collection nie kasuje wszystkiego od razu.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 159. YAFFS example. Retencja i secure deletion.

Tu interesuje nas dokładnie moment, w którym YAFFS example przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu interesuje nas dokładnie punkt, w którym przeciwnik zaczyna sterować danymi, które potem system bierze za prawdziwe.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 160
## layout
bullet
## slide title
YAFFS example
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 160. YAFFS example. Retencja i secure deletion.

Obrona dla YAFFS example musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Obrona ma znaczyć więcej niż 'zablokować'. Trzeba podać warunek, wersję systemu, flagę albo mechanizm, który faktycznie zmienia wynik.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 161
## layout
definition
## slide title
FTL mapping
## subtitle
Co to jest
## term
FTL mapping
## definition
FTL mapuje logiczne bloki na fizyczne bloki poza kontrolą filesystemu.
## teleprompter:
Slajd 161. FTL mapping. Retencja i secure deletion.

FTL mapuje logiczne bloki na fizyczne bloki poza kontrolą filesystemu.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. To właśnie tutaj widać, jak ten mechanizm wchodzi w realny przepływ systemu i aplikacji.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Atak zaczyna się tam, gdzie ktoś traktuje lokalny sygnał, wybrane URI albo rekord protokołu jak już zweryfikowany.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. To oznacza, że w obronie trzeba wskazać dokładny punkt egzekwowania i test, który potwierdzi odmowę albo ograniczenie.

#slide 162
## layout
bullet
## slide title
FTL mapping
## subtitle
Jak działa
## bullets
- Krok 1: FTL mapuje logiczne bloki na fizyczne bloki poza kontrolą filesystemu.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 162. FTL mapping. Retencja i secure deletion.

Najpierw rozpisz przebieg FTL mapping krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. W tej części trzeba pokazać kolejność zdarzeń, bo właśnie kolejność zdradza, gdzie system przejmuje kontrolę, a gdzie zostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu tej sekwencji masz konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 163
## layout
bullet
## slide title
FTL mapping
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: FTL mapuje logiczne bloki na fizyczne bloki poza kontrolą filesystemu.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 163. FTL mapping. Retencja i secure deletion.

Tu interesuje nas dokładnie moment, w którym FTL mapping przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu interesuje nas dokładnie punkt, w którym przeciwnik zaczyna sterować danymi, które potem system bierze za prawdziwe.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 164
## layout
bullet
## slide title
FTL mapping
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 164. FTL mapping. Retencja i secure deletion.

Obrona dla FTL mapping musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Obrona ma znaczyć więcej niż 'zablokować'. Trzeba podać warunek, wersję systemu, flagę albo mechanizm, który faktycznie zmienia wynik.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 165
## layout
definition
## slide title
Overwrite problem
## subtitle
Co to jest
## term
Overwrite problem
## definition
Overwrite nie daje gwarancji, że nadpiszesz dokładnie ten fizyczny blok, który chcesz usunąć.
## teleprompter:
Slajd 165. Overwrite problem. Retencja i secure deletion.

Overwrite nie daje gwarancji, że nadpiszesz dokładnie ten fizyczny blok, który chcesz usunąć.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. To właśnie tutaj widać, jak ten mechanizm wchodzi w realny przepływ systemu i aplikacji.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Atak zaczyna się tam, gdzie ktoś traktuje lokalny sygnał, wybrane URI albo rekord protokołu jak już zweryfikowany.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. To oznacza, że w obronie trzeba wskazać dokładny punkt egzekwowania i test, który potwierdzi odmowę albo ograniczenie.

#slide 166
## layout
bullet
## slide title
Overwrite problem
## subtitle
Jak działa
## bullets
- Krok 1: Overwrite nie daje gwarancji, że nadpiszesz dokładnie ten fizyczny blok, który chcesz usunąć.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 166. Overwrite problem. Retencja i secure deletion.

Najpierw rozpisz przebieg Overwrite problem krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. W tej części trzeba pokazać kolejność zdarzeń, bo właśnie kolejność zdradza, gdzie system przejmuje kontrolę, a gdzie zostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu tej sekwencji masz konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 167
## layout
bullet
## slide title
Overwrite problem
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Overwrite nie daje gwarancji, że nadpiszesz dokładnie ten fizyczny blok, który chcesz usunąć.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 167. Overwrite problem. Retencja i secure deletion.

Tu interesuje nas dokładnie moment, w którym Overwrite problem przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu interesuje nas dokładnie punkt, w którym przeciwnik zaczyna sterować danymi, które potem system bierze za prawdziwe.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 168
## layout
bullet
## slide title
Overwrite problem
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 168. Overwrite problem. Retencja i secure deletion.

Obrona dla Overwrite problem musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Obrona ma znaczyć więcej niż 'zablokować'. Trzeba podać warunek, wersję systemu, flagę albo mechanizm, który faktycznie zmienia wynik.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 169
## layout
definition
## slide title
Encryption limitation
## subtitle
Co to jest
## term
Encryption limitation
## definition
Sama kryptografia nie pomaga, jeśli stare kopie lub klucze nadal są dostępne.
## teleprompter:
Slajd 169. Encryption limitation. Retencja i secure deletion.

Sama kryptografia nie pomaga, jeśli stare kopie lub klucze nadal są dostępne.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. To właśnie tutaj widać, jak ten mechanizm wchodzi w realny przepływ systemu i aplikacji.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Atak zaczyna się tam, gdzie ktoś traktuje lokalny sygnał, wybrane URI albo rekord protokołu jak już zweryfikowany.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. To oznacza, że w obronie trzeba wskazać dokładny punkt egzekwowania i test, który potwierdzi odmowę albo ograniczenie.

#slide 170
## layout
bullet
## slide title
Encryption limitation
## subtitle
Jak działa
## bullets
- Krok 1: Sama kryptografia nie pomaga, jeśli stare kopie lub klucze nadal są dostępne.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 170. Encryption limitation. Retencja i secure deletion.

Najpierw rozpisz przebieg Encryption limitation krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. W tej części trzeba pokazać kolejność zdarzeń, bo właśnie kolejność zdradza, gdzie system przejmuje kontrolę, a gdzie zostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu tej sekwencji masz konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 171
## layout
bullet
## slide title
Encryption limitation
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Sama kryptografia nie pomaga, jeśli stare kopie lub klucze nadal są dostępne.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 171. Encryption limitation. Retencja i secure deletion.

Tu interesuje nas dokładnie moment, w którym Encryption limitation przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu interesuje nas dokładnie punkt, w którym przeciwnik zaczyna sterować danymi, które potem system bierze za prawdziwe.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 172
## layout
bullet
## slide title
Encryption limitation
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 172. Encryption limitation. Retencja i secure deletion.

Obrona dla Encryption limitation musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Obrona ma znaczyć więcej niż 'zablokować'. Trzeba podać warunek, wersję systemu, flagę albo mechanizm, który faktycznie zmienia wynik.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 173
## layout
definition
## slide title
Purge algorithm
## subtitle
Co to jest
## term
Purge algorithm
## definition
Purge chce realnie zniszczyć lub przenieść dane aż recovery przestaje być praktyczne.
## teleprompter:
Slajd 173. Purge algorithm. Retencja i secure deletion.

Purge chce realnie zniszczyć lub przenieść dane aż recovery przestaje być praktyczne.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. To właśnie tutaj widać, jak ten mechanizm wchodzi w realny przepływ systemu i aplikacji.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Atak zaczyna się tam, gdzie ktoś traktuje lokalny sygnał, wybrane URI albo rekord protokołu jak już zweryfikowany.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. To oznacza, że w obronie trzeba wskazać dokładny punkt egzekwowania i test, który potwierdzi odmowę albo ograniczenie.

#slide 174
## layout
bullet
## slide title
Purge algorithm
## subtitle
Jak działa
## bullets
- Krok 1: Purge chce realnie zniszczyć lub przenieść dane aż recovery przestaje być praktyczne.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 174. Purge algorithm. Retencja i secure deletion.

Najpierw rozpisz przebieg Purge algorithm krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. W tej części trzeba pokazać kolejność zdarzeń, bo właśnie kolejność zdradza, gdzie system przejmuje kontrolę, a gdzie zostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu tej sekwencji masz konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 175
## layout
bullet
## slide title
Purge algorithm
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Purge chce realnie zniszczyć lub przenieść dane aż recovery przestaje być praktyczne.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 175. Purge algorithm. Retencja i secure deletion.

Tu interesuje nas dokładnie moment, w którym Purge algorithm przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu interesuje nas dokładnie punkt, w którym przeciwnik zaczyna sterować danymi, które potem system bierze za prawdziwe.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 176
## layout
bullet
## slide title
Purge algorithm
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 176. Purge algorithm. Retencja i secure deletion.

Obrona dla Purge algorithm musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Obrona ma znaczyć więcej niż 'zablokować'. Trzeba podać warunek, wersję systemu, flagę albo mechanizm, który faktycznie zmienia wynik.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 177
## layout
definition
## slide title
Ballooning algorithm
## subtitle
Co to jest
## term
Ballooning algorithm
## definition
Ballooning zjada wolne miejsce, by wymusić wypchnięcie bloku celu.
## teleprompter:
Slajd 177. Ballooning algorithm. Retencja i secure deletion.

Ballooning zjada wolne miejsce, by wymusić wypchnięcie bloku celu.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. To właśnie tutaj widać, jak ten mechanizm wchodzi w realny przepływ systemu i aplikacji.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Atak zaczyna się tam, gdzie ktoś traktuje lokalny sygnał, wybrane URI albo rekord protokołu jak już zweryfikowany.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. To oznacza, że w obronie trzeba wskazać dokładny punkt egzekwowania i test, który potwierdzi odmowę albo ograniczenie.

#slide 178
## layout
bullet
## slide title
Ballooning algorithm
## subtitle
Jak działa
## bullets
- Krok 1: Ballooning zjada wolne miejsce, by wymusić wypchnięcie bloku celu.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 178. Ballooning algorithm. Retencja i secure deletion.

Najpierw rozpisz przebieg Ballooning algorithm krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. W tej części trzeba pokazać kolejność zdarzeń, bo właśnie kolejność zdradza, gdzie system przejmuje kontrolę, a gdzie zostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu tej sekwencji masz konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 179
## layout
bullet
## slide title
Ballooning algorithm
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Ballooning zjada wolne miejsce, by wymusić wypchnięcie bloku celu.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 179. Ballooning algorithm. Retencja i secure deletion.

Tu interesuje nas dokładnie moment, w którym Ballooning algorithm przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu interesuje nas dokładnie punkt, w którym przeciwnik zaczyna sterować danymi, które potem system bierze za prawdziwe.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 180
## layout
bullet
## slide title
Ballooning algorithm
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 180. Ballooning algorithm. Retencja i secure deletion.

Obrona dla Ballooning algorithm musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Obrona ma znaczyć więcej niż 'zablokować'. Trzeba podać warunek, wersję systemu, flagę albo mechanizm, który faktycznie zmienia wynik.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 181
## layout
definition
## slide title
Zero overwriting
## subtitle
Co to jest
## term
Zero overwriting
## definition
Zero overwriting wypełnia obszar i potem vacuumuje resztki.
## teleprompter:
Slajd 181. Zero overwriting. Retencja i secure deletion.

Zero overwriting wypełnia obszar i potem vacuumuje resztki.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. To właśnie tutaj widać, jak ten mechanizm wchodzi w realny przepływ systemu i aplikacji.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Atak zaczyna się tam, gdzie ktoś traktuje lokalny sygnał, wybrane URI albo rekord protokołu jak już zweryfikowany.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. To oznacza, że w obronie trzeba wskazać dokładny punkt egzekwowania i test, który potwierdzi odmowę albo ograniczenie.

#slide 182
## layout
bullet
## slide title
Zero overwriting
## subtitle
Jak działa
## bullets
- Krok 1: Zero overwriting wypełnia obszar i potem vacuumuje resztki.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 182. Zero overwriting. Retencja i secure deletion.

Najpierw rozpisz przebieg Zero overwriting krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. W tej części trzeba pokazać kolejność zdarzeń, bo właśnie kolejność zdradza, gdzie system przejmuje kontrolę, a gdzie zostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu tej sekwencji masz konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 183
## layout
bullet
## slide title
Zero overwriting
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Zero overwriting wypełnia obszar i potem vacuumuje resztki.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 183. Zero overwriting. Retencja i secure deletion.

Tu interesuje nas dokładnie moment, w którym Zero overwriting przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu interesuje nas dokładnie punkt, w którym przeciwnik zaczyna sterować danymi, które potem system bierze za prawdziwe.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 184
## layout
bullet
## slide title
Zero overwriting
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 184. Zero overwriting. Retencja i secure deletion.

Obrona dla Zero overwriting musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Obrona ma znaczyć więcej niż 'zablokować'. Trzeba podać warunek, wersję systemu, flagę albo mechanizm, który faktycznie zmienia wynik.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 185
## layout
definition
## slide title
Versioned file system
## subtitle
Co to jest
## term
Versioned file system
## definition
Snapshoty i historia wersji komplikują kasowanie, bo stare stany nadal istnieją.
## teleprompter:
Slajd 185. Versioned file system. Retencja i secure deletion.

Snapshoty i historia wersji komplikują kasowanie, bo stare stany nadal istnieją.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. To właśnie tutaj widać, jak ten mechanizm wchodzi w realny przepływ systemu i aplikacji.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Atak zaczyna się tam, gdzie ktoś traktuje lokalny sygnał, wybrane URI albo rekord protokołu jak już zweryfikowany.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. To oznacza, że w obronie trzeba wskazać dokładny punkt egzekwowania i test, który potwierdzi odmowę albo ograniczenie.

#slide 186
## layout
bullet
## slide title
Versioned file system
## subtitle
Jak działa
## bullets
- Krok 1: Snapshoty i historia wersji komplikują kasowanie, bo stare stany nadal istnieją.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 186. Versioned file system. Retencja i secure deletion.

Najpierw rozpisz przebieg Versioned file system krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. W tej części trzeba pokazać kolejność zdarzeń, bo właśnie kolejność zdradza, gdzie system przejmuje kontrolę, a gdzie zostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu tej sekwencji masz konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 187
## layout
bullet
## slide title
Versioned file system
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Snapshoty i historia wersji komplikują kasowanie, bo stare stany nadal istnieją.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 187. Versioned file system. Retencja i secure deletion.

Tu interesuje nas dokładnie moment, w którym Versioned file system przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu interesuje nas dokładnie punkt, w którym przeciwnik zaczyna sterować danymi, które potem system bierze za prawdziwe.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 188
## layout
bullet
## slide title
Versioned file system
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 188. Versioned file system. Retencja i secure deletion.

Obrona dla Versioned file system musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Obrona ma znaczyć więcej niż 'zablokować'. Trzeba podać warunek, wersję systemu, flagę albo mechanizm, który faktycznie zmienia wynik.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 189
## layout
definition
## slide title
Forensic verification
## subtitle
Co to jest
## term
Forensic verification
## definition
Forensic verification sprawdza, czy po usunięciu da się jeszcze odzyskać treść lub jej ślady.
## teleprompter:
Slajd 189. Forensic verification. Retencja i secure deletion.

Forensic verification sprawdza, czy po usunięciu da się jeszcze odzyskać treść lub jej ślady.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. To właśnie tutaj widać, jak ten mechanizm wchodzi w realny przepływ systemu i aplikacji.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Atak zaczyna się tam, gdzie ktoś traktuje lokalny sygnał, wybrane URI albo rekord protokołu jak już zweryfikowany.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. To oznacza, że w obronie trzeba wskazać dokładny punkt egzekwowania i test, który potwierdzi odmowę albo ograniczenie.

#slide 190
## layout
bullet
## slide title
Forensic verification
## subtitle
Jak działa
## bullets
- Krok 1: Forensic verification sprawdza, czy po usunięciu da się jeszcze odzyskać treść lub jej ślady.
- Krok 2: Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 190. Forensic verification. Retencja i secure deletion.

Najpierw rozpisz przebieg Forensic verification krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting. W tej części trzeba pokazać kolejność zdarzeń, bo właśnie kolejność zdradza, gdzie system przejmuje kontrolę, a gdzie zostawia decyzję aplikacji.

Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.

Na końcu tej sekwencji masz konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 191
## layout
bullet
## slide title
Forensic verification
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Forensic verification sprawdza, czy po usunięciu da się jeszcze odzyskać treść lub jej ślady.
- Kontrola atakującego: Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 191. Forensic verification. Retencja i secure deletion.

Tu interesuje nas dokładnie moment, w którym Forensic verification przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history. Tu interesuje nas dokładnie punkt, w którym przeciwnik zaczyna sterować danymi, które potem system bierze za prawdziwe.

Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.

Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 192
## layout
bullet
## slide title
Forensic verification
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 192. Forensic verification. Retencja i secure deletion.

Obrona dla Forensic verification musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem. Obrona ma znaczyć więcej niż 'zablokować'. Trzeba podać warunek, wersję systemu, flagę albo mechanizm, który faktycznie zmienia wynik.

Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.

Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.
