#slide 97
## layout
definition
## slide title
Why DCL exists — Co to jest
## term
Why DCL exists
## definition
DCL istnieje po to, by obsłużyć modularność, pluginy i runtime updates.
## teleprompter:
Slajd 97. Why DCL exists. Dynamic code loading.

Definicja i granica pojęcia. Why DCL exists w tym miejscu oznacza dokładnie: DCL istnieje po to, by obsłużyć modularność, pluginy i runtime updates. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Dlaczego to nie jest tylko hasło. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 98
## layout
bullet
## slide title
Why DCL exists — Jak działa
## bullets
- Krok 1: DCL istnieje po to, by obsłużyć modularność, pluginy i runtime updates.
- Krok 2: W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 98. Why DCL exists. Dynamic code loading.

Wejście i stan początkowy. Why DCL exists w tym miejscu oznacza dokładnie: DCL istnieje po to, by obsłużyć modularność, pluginy i runtime updates. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Krok po kroku przez przepływ. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 99
## layout
bullet
## slide title
Why DCL exists — Jak pęka
## bullets
- Warunek powodzenia: DCL istnieje po to, by obsłużyć modularność, pluginy i runtime updates.
- Kontrola atakującego: Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 99. Why DCL exists. Dynamic code loading.

Warunek powodzenia ataku. Why DCL exists w tym miejscu oznacza dokładnie: DCL istnieje po to, by obsłużyć modularność, pluginy i runtime updates. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Co kontroluje atakujący. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 100
## layout
bullet
## slide title
Why DCL exists — Jak się bronić
## bullets
- Reguła: Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 100. Why DCL exists. Dynamic code loading.

Reguła i miejsce egzekwowania. Why DCL exists w tym miejscu oznacza dokładnie: DCL istnieje po to, by obsłużyć modularność, pluginy i runtime updates. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Minimalny zakres dostępu. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 101
## layout
definition
## slide title
Attack surface — Co to jest
## term
Attack surface
## definition
Powierzchnia ataku rośnie w chwili, gdy ładowany kod da się podmienić lub uszkodzić.
## teleprompter:
Slajd 101. Attack surface. Dynamic code loading.

Definicja i granica pojęcia. Attack surface w tym miejscu oznacza dokładnie: Powierzchnia ataku rośnie w chwili, gdy ładowany kod da się podmienić lub uszkodzić. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Dlaczego to nie jest tylko hasło. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 102
## layout
bullet
## slide title
Attack surface — Jak działa
## bullets
- Krok 1: Powierzchnia ataku rośnie w chwili, gdy ładowany kod da się podmienić lub uszkodzić.
- Krok 2: W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 102. Attack surface. Dynamic code loading.

Wejście i stan początkowy. Attack surface w tym miejscu oznacza dokładnie: Powierzchnia ataku rośnie w chwili, gdy ładowany kod da się podmienić lub uszkodzić. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Krok po kroku przez przepływ. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 103
## layout
bullet
## slide title
Attack surface — Jak pęka
## bullets
- Warunek powodzenia: Powierzchnia ataku rośnie w chwili, gdy ładowany kod da się podmienić lub uszkodzić.
- Kontrola atakującego: Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 103. Attack surface. Dynamic code loading.

Warunek powodzenia ataku. Attack surface w tym miejscu oznacza dokładnie: Powierzchnia ataku rośnie w chwili, gdy ładowany kod da się podmienić lub uszkodzić. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Co kontroluje atakujący. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 104
## layout
bullet
## slide title
Attack surface — Jak się bronić
## bullets
- Reguła: Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 104. Attack surface. Dynamic code loading.

Reguła i miejsce egzekwowania. Attack surface w tym miejscu oznacza dokładnie: Powierzchnia ataku rośnie w chwili, gdy ładowany kod da się podmienić lub uszkodzić. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Minimalny zakres dostępu. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 105
## layout
definition
## slide title
Remote source risk — Co to jest
## term
Remote source risk
## definition
Remote code loading jest najdroższe z punktu widzenia ryzyka i może łamać Google Play policy.
## teleprompter:
Slajd 105. Remote source risk. Dynamic code loading.

Definicja i granica pojęcia. Remote source risk w tym miejscu oznacza dokładnie: Remote code loading jest najdroższe z punktu widzenia ryzyka i może łamać Google Play policy. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Dlaczego to nie jest tylko hasło. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 106
## layout
bullet
## slide title
Remote source risk — Jak działa
## bullets
- Krok 1: Remote code loading jest najdroższe z punktu widzenia ryzyka i może łamać Google Play policy.
- Krok 2: W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 106. Remote source risk. Dynamic code loading.

Wejście i stan początkowy. Remote source risk w tym miejscu oznacza dokładnie: Remote code loading jest najdroższe z punktu widzenia ryzyka i może łamać Google Play policy. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Krok po kroku przez przepływ. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 107
## layout
bullet
## slide title
Remote source risk — Jak pęka
## bullets
- Warunek powodzenia: Remote code loading jest najdroższe z punktu widzenia ryzyka i może łamać Google Play policy.
- Kontrola atakującego: Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 107. Remote source risk. Dynamic code loading.

Warunek powodzenia ataku. Remote source risk w tym miejscu oznacza dokładnie: Remote code loading jest najdroższe z punktu widzenia ryzyka i może łamać Google Play policy. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Co kontroluje atakujący. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 108
## layout
bullet
## slide title
Remote source risk — Jak się bronić
## bullets
- Reguła: Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 108. Remote source risk. Dynamic code loading.

Reguła i miejsce egzekwowania. Remote source risk w tym miejscu oznacza dokładnie: Remote code loading jest najdroższe z punktu widzenia ryzyka i może łamać Google Play policy. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Minimalny zakres dostępu. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 109
## layout
definition
## slide title
Trusted storage — Co to jest
## term
Trusted storage
## definition
Kod, który ma być później ładowany, powinien lądować w internal storage albo w scoped storage.
## teleprompter:
Slajd 109. Trusted storage. Dynamic code loading.

Definicja i granica pojęcia. Trusted storage w tym miejscu oznacza dokładnie: Kod, który ma być później ładowany, powinien lądować w internal storage albo w scoped storage. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Dlaczego to nie jest tylko hasło. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 110
## layout
bullet
## slide title
Trusted storage — Jak działa
## bullets
- Krok 1: Kod, który ma być później ładowany, powinien lądować w internal storage albo w scoped storage.
- Krok 2: W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 110. Trusted storage. Dynamic code loading.

Wejście i stan początkowy. Trusted storage w tym miejscu oznacza dokładnie: Kod, który ma być później ładowany, powinien lądować w internal storage albo w scoped storage. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Krok po kroku przez przepływ. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 111
## layout
bullet
## slide title
Trusted storage — Jak pęka
## bullets
- Warunek powodzenia: Kod, który ma być później ładowany, powinien lądować w internal storage albo w scoped storage.
- Kontrola atakującego: Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 111. Trusted storage. Dynamic code loading.

Warunek powodzenia ataku. Trusted storage w tym miejscu oznacza dokładnie: Kod, który ma być później ładowany, powinien lądować w internal storage albo w scoped storage. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Co kontroluje atakujący. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 112
## layout
bullet
## slide title
Trusted storage — Jak się bronić
## bullets
- Reguła: Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 112. Trusted storage. Dynamic code loading.

Reguła i miejsce egzekwowania. Trusted storage w tym miejscu oznacza dokładnie: Kod, który ma być później ładowany, powinien lądować w internal storage albo w scoped storage. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Minimalny zakres dostępu. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 113
## layout
definition
## slide title
External storage risk — Co to jest
## term
External storage risk
## definition
Shared external storage jest mutowalny, więc nie nadaje się na artefakt wykonywalny.
## teleprompter:
Slajd 113. External storage risk. Dynamic code loading.

Definicja i granica pojęcia. External storage risk w tym miejscu oznacza dokładnie: Shared external storage jest mutowalny, więc nie nadaje się na artefakt wykonywalny. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Dlaczego to nie jest tylko hasło. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 114
## layout
bullet
## slide title
External storage risk — Jak działa
## bullets
- Krok 1: Shared external storage jest mutowalny, więc nie nadaje się na artefakt wykonywalny.
- Krok 2: W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 114. External storage risk. Dynamic code loading.

Wejście i stan początkowy. External storage risk w tym miejscu oznacza dokładnie: Shared external storage jest mutowalny, więc nie nadaje się na artefakt wykonywalny. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Krok po kroku przez przepływ. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 115
## layout
bullet
## slide title
External storage risk — Jak pęka
## bullets
- Warunek powodzenia: Shared external storage jest mutowalny, więc nie nadaje się na artefakt wykonywalny.
- Kontrola atakującego: Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 115. External storage risk. Dynamic code loading.

Warunek powodzenia ataku. External storage risk w tym miejscu oznacza dokładnie: Shared external storage jest mutowalny, więc nie nadaje się na artefakt wykonywalny. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Co kontroluje atakujący. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 116
## layout
bullet
## slide title
External storage risk — Jak się bronić
## bullets
- Reguła: Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 116. External storage risk. Dynamic code loading.

Reguła i miejsce egzekwowania. External storage risk w tym miejscu oznacza dokładnie: Shared external storage jest mutowalny, więc nie nadaje się na artefakt wykonywalny. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Minimalny zakres dostępu. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 117
## layout
definition
## slide title
Integrity before load — Co to jest
## term
Integrity before load
## definition
Bezpieczny wzorzec to verify-before-load, a nie load-first.
## teleprompter:
Slajd 117. Integrity before load. Dynamic code loading.

Definicja i granica pojęcia. Integrity before load w tym miejscu oznacza dokładnie: Bezpieczny wzorzec to verify-before-load, a nie load-first. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Dlaczego to nie jest tylko hasło. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 118
## layout
bullet
## slide title
Integrity before load — Jak działa
## bullets
- Krok 1: Bezpieczny wzorzec to verify-before-load, a nie load-first.
- Krok 2: W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 118. Integrity before load. Dynamic code loading.

Wejście i stan początkowy. Integrity before load w tym miejscu oznacza dokładnie: Bezpieczny wzorzec to verify-before-load, a nie load-first. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Krok po kroku przez przepływ. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 119
## layout
bullet
## slide title
Integrity before load — Jak pęka
## bullets
- Warunek powodzenia: Bezpieczny wzorzec to verify-before-load, a nie load-first.
- Kontrola atakującego: Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 119. Integrity before load. Dynamic code loading.

Warunek powodzenia ataku. Integrity before load w tym miejscu oznacza dokładnie: Bezpieczny wzorzec to verify-before-load, a nie load-first. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Co kontroluje atakujący. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 120
## layout
bullet
## slide title
Integrity before load — Jak się bronić
## bullets
- Reguła: Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 120. Integrity before load. Dynamic code loading.

Reguła i miejsce egzekwowania. Integrity before load w tym miejscu oznacza dokładnie: Bezpieczny wzorzec to verify-before-load, a nie load-first. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Minimalny zakres dostępu. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 121
## layout
definition
## slide title
SHA-256 checker — Co to jest
## term
SHA-256 checker
## definition
SHA-256 checker liczy digest i porównuje go z referencją zaufaną przez aplikację.
## teleprompter:
Slajd 121. SHA-256 checker. Dynamic code loading.

Definicja i granica pojęcia. SHA-256 checker w tym miejscu oznacza dokładnie: SHA-256 checker liczy digest i porównuje go z referencją zaufaną przez aplikację. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Dlaczego to nie jest tylko hasło. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 122
## layout
bullet
## slide title
SHA-256 checker — Jak działa
## bullets
- Krok 1: SHA-256 checker liczy digest i porównuje go z referencją zaufaną przez aplikację.
- Krok 2: W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 122. SHA-256 checker. Dynamic code loading.

Wejście i stan początkowy. SHA-256 checker w tym miejscu oznacza dokładnie: SHA-256 checker liczy digest i porównuje go z referencją zaufaną przez aplikację. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Krok po kroku przez przepływ. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 123
## layout
bullet
## slide title
SHA-256 checker — Jak pęka
## bullets
- Warunek powodzenia: SHA-256 checker liczy digest i porównuje go z referencją zaufaną przez aplikację.
- Kontrola atakującego: Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 123. SHA-256 checker. Dynamic code loading.

Warunek powodzenia ataku. SHA-256 checker w tym miejscu oznacza dokładnie: SHA-256 checker liczy digest i porównuje go z referencją zaufaną przez aplikację. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Co kontroluje atakujący. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 124
## layout
bullet
## slide title
SHA-256 checker — Jak się bronić
## bullets
- Reguła: Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 124. SHA-256 checker. Dynamic code loading.

Reguła i miejsce egzekwowania. SHA-256 checker w tym miejscu oznacza dokładnie: SHA-256 checker liczy digest i porównuje go z referencją zaufaną przez aplikację. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Minimalny zakres dostępu. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 125
## layout
definition
## slide title
Code signing — Co to jest
## term
Code signing
## definition
Podpis kodu dodaje podpis kryptograficzny i zaufany public key.
## teleprompter:
Slajd 125. Code signing. Dynamic code loading.

Definicja i granica pojęcia. Code signing w tym miejscu oznacza dokładnie: Podpis kodu dodaje podpis kryptograficzny i zaufany public key. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Dlaczego to nie jest tylko hasło. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 126
## layout
bullet
## slide title
Code signing — Jak działa
## bullets
- Krok 1: Podpis kodu dodaje podpis kryptograficzny i zaufany public key.
- Krok 2: W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 126. Code signing. Dynamic code loading.

Wejście i stan początkowy. Code signing w tym miejscu oznacza dokładnie: Podpis kodu dodaje podpis kryptograficzny i zaufany public key. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Krok po kroku przez przepływ. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 127
## layout
bullet
## slide title
Code signing — Jak pęka
## bullets
- Warunek powodzenia: Podpis kodu dodaje podpis kryptograficzny i zaufany public key.
- Kontrola atakującego: Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 127. Code signing. Dynamic code loading.

Warunek powodzenia ataku. Code signing w tym miejscu oznacza dokładnie: Podpis kodu dodaje podpis kryptograficzny i zaufany public key. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Co kontroluje atakujący. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 128
## layout
bullet
## slide title
Code signing — Jak się bronić
## bullets
- Reguła: Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 128. Code signing. Dynamic code loading.

Reguła i miejsce egzekwowania. Code signing w tym miejscu oznacza dokładnie: Podpis kodu dodaje podpis kryptograficzny i zaufany public key. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Minimalny zakres dostępu. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 129
## layout
definition
## slide title
Hash storage — Co to jest
## term
Hash storage
## definition
Referencja hash lub signature musi leżeć w chronionym miejscu, a nie obok samego payloadu.
## teleprompter:
Slajd 129. Hash storage. Dynamic code loading.

Definicja i granica pojęcia. Hash storage w tym miejscu oznacza dokładnie: Referencja hash lub signature musi leżeć w chronionym miejscu, a nie obok samego payloadu. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Dlaczego to nie jest tylko hasło. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 130
## layout
bullet
## slide title
Hash storage — Jak działa
## bullets
- Krok 1: Referencja hash lub signature musi leżeć w chronionym miejscu, a nie obok samego payloadu.
- Krok 2: W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 130. Hash storage. Dynamic code loading.

Wejście i stan początkowy. Hash storage w tym miejscu oznacza dokładnie: Referencja hash lub signature musi leżeć w chronionym miejscu, a nie obok samego payloadu. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Krok po kroku przez przepływ. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 131
## layout
bullet
## slide title
Hash storage — Jak pęka
## bullets
- Warunek powodzenia: Referencja hash lub signature musi leżeć w chronionym miejscu, a nie obok samego payloadu.
- Kontrola atakującego: Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 131. Hash storage. Dynamic code loading.

Warunek powodzenia ataku. Hash storage w tym miejscu oznacza dokładnie: Referencja hash lub signature musi leżeć w chronionym miejscu, a nie obok samego payloadu. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Co kontroluje atakujący. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 132
## layout
bullet
## slide title
Hash storage — Jak się bronić
## bullets
- Reguła: Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 132. Hash storage. Dynamic code loading.

Reguła i miejsce egzekwowania. Hash storage w tym miejscu oznacza dokładnie: Referencja hash lub signature musi leżeć w chronionym miejscu, a nie obok samego payloadu. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Minimalny zakres dostępu. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 133
## layout
definition
## slide title
Path to execution — Co to jest
## term
Path to execution
## definition
Niebezpieczna ścieżka to download, write, verify, load i execute.
## teleprompter:
Slajd 133. Path to execution. Dynamic code loading.

Definicja i granica pojęcia. Path to execution w tym miejscu oznacza dokładnie: Niebezpieczna ścieżka to download, write, verify, load i execute. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Dlaczego to nie jest tylko hasło. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 134
## layout
bullet
## slide title
Path to execution — Jak działa
## bullets
- Krok 1: Niebezpieczna ścieżka to download, write, verify, load i execute.
- Krok 2: W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 134. Path to execution. Dynamic code loading.

Wejście i stan początkowy. Path to execution w tym miejscu oznacza dokładnie: Niebezpieczna ścieżka to download, write, verify, load i execute. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Krok po kroku przez przepływ. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 135
## layout
bullet
## slide title
Path to execution — Jak pęka
## bullets
- Warunek powodzenia: Niebezpieczna ścieżka to download, write, verify, load i execute.
- Kontrola atakującego: Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 135. Path to execution. Dynamic code loading.

Warunek powodzenia ataku. Path to execution w tym miejscu oznacza dokładnie: Niebezpieczna ścieżka to download, write, verify, load i execute. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Co kontroluje atakujący. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 136
## layout
bullet
## slide title
Path to execution — Jak się bronić
## bullets
- Reguła: Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 136. Path to execution. Dynamic code loading.

Reguła i miejsce egzekwowania. Path to execution w tym miejscu oznacza dokładnie: Niebezpieczna ścieżka to download, write, verify, load i execute. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Minimalny zakres dostępu. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 137
## layout
definition
## slide title
Class loader choices — Co to jest
## term
Class loader choices
## definition
DexClassLoader, PathClassLoader i InMemoryDexClassLoader różnią się tym, skąd biorą kod i jak długo go trzymają.
## teleprompter:
Slajd 137. Class loader choices. Dynamic code loading.

Definicja i granica pojęcia. Class loader choices w tym miejscu oznacza dokładnie: DexClassLoader, PathClassLoader i InMemoryDexClassLoader różnią się tym, skąd biorą kod i jak długo go trzymają. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Dlaczego to nie jest tylko hasło. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 138
## layout
bullet
## slide title
Class loader choices — Jak działa
## bullets
- Krok 1: DexClassLoader, PathClassLoader i InMemoryDexClassLoader różnią się tym, skąd biorą kod i jak długo go trzymają.
- Krok 2: W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 138. Class loader choices. Dynamic code loading.

Wejście i stan początkowy. Class loader choices w tym miejscu oznacza dokładnie: DexClassLoader, PathClassLoader i InMemoryDexClassLoader różnią się tym, skąd biorą kod i jak długo go trzymają. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Krok po kroku przez przepływ. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 139
## layout
bullet
## slide title
Class loader choices — Jak pęka
## bullets
- Warunek powodzenia: DexClassLoader, PathClassLoader i InMemoryDexClassLoader różnią się tym, skąd biorą kod i jak długo go trzymają.
- Kontrola atakującego: Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 139. Class loader choices. Dynamic code loading.

Warunek powodzenia ataku. Class loader choices w tym miejscu oznacza dokładnie: DexClassLoader, PathClassLoader i InMemoryDexClassLoader różnią się tym, skąd biorą kod i jak długo go trzymają. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Co kontroluje atakujący. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 140
## layout
bullet
## slide title
Class loader choices — Jak się bronić
## bullets
- Reguła: Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 140. Class loader choices. Dynamic code loading.

Reguła i miejsce egzekwowania. Class loader choices w tym miejscu oznacza dokładnie: DexClassLoader, PathClassLoader i InMemoryDexClassLoader różnią się tym, skąd biorą kod i jak długo go trzymają. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Minimalny zakres dostępu. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 141
## layout
definition
## slide title
Native versus Java — Co to jest
## term
Native versus Java
## definition
Natywne dlopen i dlsym mają ten sam problem z podmianą co loading pliku dex.
## teleprompter:
Slajd 141. Native versus Java. Dynamic code loading.

Definicja i granica pojęcia. Native versus Java w tym miejscu oznacza dokładnie: Natywne dlopen i dlsym mają ten sam problem z podmianą co loading pliku dex. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Dlaczego to nie jest tylko hasło. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 142
## layout
bullet
## slide title
Native versus Java — Jak działa
## bullets
- Krok 1: Natywne dlopen i dlsym mają ten sam problem z podmianą co loading pliku dex.
- Krok 2: W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 142. Native versus Java. Dynamic code loading.

Wejście i stan początkowy. Native versus Java w tym miejscu oznacza dokładnie: Natywne dlopen i dlsym mają ten sam problem z podmianą co loading pliku dex. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Krok po kroku przez przepływ. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 143
## layout
bullet
## slide title
Native versus Java — Jak pęka
## bullets
- Warunek powodzenia: Natywne dlopen i dlsym mają ten sam problem z podmianą co loading pliku dex.
- Kontrola atakującego: Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 143. Native versus Java. Dynamic code loading.

Warunek powodzenia ataku. Native versus Java w tym miejscu oznacza dokładnie: Natywne dlopen i dlsym mają ten sam problem z podmianą co loading pliku dex. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Co kontroluje atakujący. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 144
## layout
bullet
## slide title
Native versus Java — Jak się bronić
## bullets
- Reguła: Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 144. Native versus Java. Dynamic code loading.

Reguła i miejsce egzekwowania. Native versus Java w tym miejscu oznacza dokładnie: Natywne dlopen i dlsym mają ten sam problem z podmianą co loading pliku dex. Na tle tego bloku chodzi o: Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.

Minimalny zakres dostępu. W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.
