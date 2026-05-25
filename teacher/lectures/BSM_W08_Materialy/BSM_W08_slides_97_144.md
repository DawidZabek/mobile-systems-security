#slide 97
## layout
definition
## slide title
Why DCL exists
## subtitle
Co to jest
## term
Why DCL exists
## definition
DCL istnieje po to, by obsłużyć modularność, pluginy i runtime updates.
## teleprompter:
Slajd 97. Why DCL exists. Dynamic code loading.

DCL istnieje po to, by obsłużyć modularność, pluginy i runtime updates.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.

#slide 98
## layout
bullet
## slide title
Why DCL exists
## subtitle
Jak działa
## bullets
- Krok 1: DCL istnieje po to, by obsłużyć modularność, pluginy i runtime updates.
- Krok 2: Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 98. Why DCL exists. Dynamic code loading.

Przebieg Why DCL exists krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 99
## layout
bullet
## slide title
Why DCL exists
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: DCL istnieje po to, by obsłużyć modularność, pluginy i runtime updates.
- Kontrola atakującego: Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 99. Why DCL exists. Dynamic code loading.

Why DCL exists przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 100
## layout
bullet
## slide title
Why DCL exists
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 100. Why DCL exists. Dynamic code loading.

Obrona dla Why DCL exists wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 101
## layout
definition
## slide title
Attack surface
## subtitle
Co to jest
## term
Attack surface
## definition
Powierzchnia ataku rośnie w chwili, gdy ładowany kod da się podmienić lub uszkodzić.
## teleprompter:
Slajd 101. Attack surface. Dynamic code loading.

Powierzchnia ataku rośnie w chwili, gdy ładowany kod da się podmienić lub uszkodzić.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.

#slide 102
## layout
bullet
## slide title
Attack surface
## subtitle
Jak działa
## bullets
- Krok 1: Powierzchnia ataku rośnie w chwili, gdy ładowany kod da się podmienić lub uszkodzić.
- Krok 2: Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 102. Attack surface. Dynamic code loading.

Przebieg Attack surface krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 103
## layout
bullet
## slide title
Attack surface
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Powierzchnia ataku rośnie w chwili, gdy ładowany kod da się podmienić lub uszkodzić.
- Kontrola atakującego: Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 103. Attack surface. Dynamic code loading.

Attack surface przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 104
## layout
bullet
## slide title
Attack surface
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 104. Attack surface. Dynamic code loading.

Obrona dla Attack surface wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 105
## layout
definition
## slide title
Remote source risk
## subtitle
Co to jest
## term
Remote source risk
## definition
Remote code loading jest najdroższe z punktu widzenia ryzyka i może łamać Google Play policy.
## teleprompter:
Slajd 105. Remote source risk. Dynamic code loading.

Remote code loading jest najdroższe z punktu widzenia ryzyka i może łamać Google Play policy.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.

#slide 106
## layout
bullet
## slide title
Remote source risk
## subtitle
Jak działa
## bullets
- Krok 1: Remote code loading jest najdroższe z punktu widzenia ryzyka i może łamać Google Play policy.
- Krok 2: Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 106. Remote source risk. Dynamic code loading.

Przebieg Remote source risk krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 107
## layout
bullet
## slide title
Remote source risk
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Remote code loading jest najdroższe z punktu widzenia ryzyka i może łamać Google Play policy.
- Kontrola atakującego: Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 107. Remote source risk. Dynamic code loading.

Remote source risk przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 108
## layout
bullet
## slide title
Remote source risk
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 108. Remote source risk. Dynamic code loading.

Obrona dla Remote source risk wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 109
## layout
definition
## slide title
Trusted storage
## subtitle
Co to jest
## term
Trusted storage
## definition
Kod, który ma być później ładowany, powinien lądować w internal storage albo w scoped storage.
## teleprompter:
Slajd 109. Trusted storage. Dynamic code loading.

Kod, który ma być później ładowany, powinien lądować w internal storage albo w scoped storage.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.

#slide 110
## layout
bullet
## slide title
Trusted storage
## subtitle
Jak działa
## bullets
- Krok 1: Kod, który ma być później ładowany, powinien lądować w internal storage albo w scoped storage.
- Krok 2: Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 110. Trusted storage. Dynamic code loading.

Przebieg Trusted storage krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 111
## layout
bullet
## slide title
Trusted storage
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Kod, który ma być później ładowany, powinien lądować w internal storage albo w scoped storage.
- Kontrola atakującego: Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 111. Trusted storage. Dynamic code loading.

Trusted storage przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 112
## layout
bullet
## slide title
Trusted storage
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 112. Trusted storage. Dynamic code loading.

Obrona dla Trusted storage wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 113
## layout
definition
## slide title
External storage risk
## subtitle
Co to jest
## term
External storage risk
## definition
Shared external storage jest mutowalny, więc nie nadaje się na artefakt wykonywalny.
## teleprompter:
Slajd 113. External storage risk. Dynamic code loading.

Shared external storage jest mutowalny, więc nie nadaje się na artefakt wykonywalny.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.

#slide 114
## layout
bullet
## slide title
External storage risk
## subtitle
Jak działa
## bullets
- Krok 1: Shared external storage jest mutowalny, więc nie nadaje się na artefakt wykonywalny.
- Krok 2: Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 114. External storage risk. Dynamic code loading.

Przebieg External storage risk krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 115
## layout
bullet
## slide title
External storage risk
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Shared external storage jest mutowalny, więc nie nadaje się na artefakt wykonywalny.
- Kontrola atakującego: Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 115. External storage risk. Dynamic code loading.

External storage risk przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 116
## layout
bullet
## slide title
External storage risk
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 116. External storage risk. Dynamic code loading.

Obrona dla External storage risk wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 117
## layout
definition
## slide title
Integrity before load
## subtitle
Co to jest
## term
Integrity before load
## definition
Bezpieczny wzorzec to verify-before-load, a nie load-first.
## teleprompter:
Slajd 117. Integrity before load. Dynamic code loading.

Bezpieczny wzorzec to verify-before-load, a nie load-first.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.

#slide 118
## layout
bullet
## slide title
Integrity before load
## subtitle
Jak działa
## bullets
- Krok 1: Bezpieczny wzorzec to verify-before-load, a nie load-first.
- Krok 2: Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 118. Integrity before load. Dynamic code loading.

Przebieg Integrity before load krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 119
## layout
bullet
## slide title
Integrity before load
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Bezpieczny wzorzec to verify-before-load, a nie load-first.
- Kontrola atakującego: Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 119. Integrity before load. Dynamic code loading.

Integrity before load przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 120
## layout
bullet
## slide title
Integrity before load
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 120. Integrity before load. Dynamic code loading.

Obrona dla Integrity before load wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 121
## layout
definition
## slide title
SHA-256 checker
## subtitle
Co to jest
## term
SHA-256 checker
## definition
SHA-256 checker liczy digest i porównuje go z referencją zaufaną przez aplikację.
## teleprompter:
Slajd 121. SHA-256 checker. Dynamic code loading.

SHA-256 checker liczy digest i porównuje go z referencją zaufaną przez aplikację.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.

#slide 122
## layout
bullet
## slide title
SHA-256 checker
## subtitle
Jak działa
## bullets
- Krok 1: SHA-256 checker liczy digest i porównuje go z referencją zaufaną przez aplikację.
- Krok 2: Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 122. SHA-256 checker. Dynamic code loading.

Przebieg SHA-256 checker krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 123
## layout
bullet
## slide title
SHA-256 checker
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: SHA-256 checker liczy digest i porównuje go z referencją zaufaną przez aplikację.
- Kontrola atakującego: Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 123. SHA-256 checker. Dynamic code loading.

SHA-256 checker przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 124
## layout
bullet
## slide title
SHA-256 checker
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 124. SHA-256 checker. Dynamic code loading.

Obrona dla SHA-256 checker wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 125
## layout
definition
## slide title
Code signing
## subtitle
Co to jest
## term
Code signing
## definition
Podpis kodu dodaje podpis kryptograficzny i zaufany public key.
## teleprompter:
Slajd 125. Code signing. Dynamic code loading.

Podpis kodu dodaje podpis kryptograficzny i zaufany public key.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.

#slide 126
## layout
bullet
## slide title
Code signing
## subtitle
Jak działa
## bullets
- Krok 1: Podpis kodu dodaje podpis kryptograficzny i zaufany public key.
- Krok 2: Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 126. Code signing. Dynamic code loading.

Przebieg Code signing krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 127
## layout
bullet
## slide title
Code signing
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Podpis kodu dodaje podpis kryptograficzny i zaufany public key.
- Kontrola atakującego: Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 127. Code signing. Dynamic code loading.

Code signing przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 128
## layout
bullet
## slide title
Code signing
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 128. Code signing. Dynamic code loading.

Obrona dla Code signing wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 129
## layout
definition
## slide title
Hash storage
## subtitle
Co to jest
## term
Hash storage
## definition
Referencja hash lub signature musi leżeć w chronionym miejscu, a nie obok samego payloadu.
## teleprompter:
Slajd 129. Hash storage. Dynamic code loading.

Referencja hash lub signature musi leżeć w chronionym miejscu, a nie obok samego payloadu.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.

#slide 130
## layout
bullet
## slide title
Hash storage
## subtitle
Jak działa
## bullets
- Krok 1: Referencja hash lub signature musi leżeć w chronionym miejscu, a nie obok samego payloadu.
- Krok 2: Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 130. Hash storage. Dynamic code loading.

Przebieg Hash storage krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 131
## layout
bullet
## slide title
Hash storage
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Referencja hash lub signature musi leżeć w chronionym miejscu, a nie obok samego payloadu.
- Kontrola atakującego: Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 131. Hash storage. Dynamic code loading.

Hash storage przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 132
## layout
bullet
## slide title
Hash storage
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 132. Hash storage. Dynamic code loading.

Obrona dla Hash storage wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 133
## layout
definition
## slide title
Path to execution
## subtitle
Co to jest
## term
Path to execution
## definition
Niebezpieczna ścieżka to download, write, verify, load i execute.
## teleprompter:
Slajd 133. Path to execution. Dynamic code loading.

Niebezpieczna ścieżka to download, write, verify, load i execute.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.

#slide 134
## layout
bullet
## slide title
Path to execution
## subtitle
Jak działa
## bullets
- Krok 1: Niebezpieczna ścieżka to download, write, verify, load i execute.
- Krok 2: Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 134. Path to execution. Dynamic code loading.

Przebieg Path to execution krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 135
## layout
bullet
## slide title
Path to execution
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Niebezpieczna ścieżka to download, write, verify, load i execute.
- Kontrola atakującego: Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 135. Path to execution. Dynamic code loading.

Path to execution przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 136
## layout
bullet
## slide title
Path to execution
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 136. Path to execution. Dynamic code loading.

Obrona dla Path to execution wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 137
## layout
definition
## slide title
Class loader choices
## subtitle
Co to jest
## term
Class loader choices
## definition
DexClassLoader, PathClassLoader i InMemoryDexClassLoader różnią się tym, skąd biorą kod i jak długo go trzymają.
## teleprompter:
Slajd 137. Class loader choices. Dynamic code loading.

DexClassLoader, PathClassLoader i InMemoryDexClassLoader różnią się tym, skąd biorą kod i jak długo go trzymają.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.

#slide 138
## layout
bullet
## slide title
Class loader choices
## subtitle
Jak działa
## bullets
- Krok 1: DexClassLoader, PathClassLoader i InMemoryDexClassLoader różnią się tym, skąd biorą kod i jak długo go trzymają.
- Krok 2: Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 138. Class loader choices. Dynamic code loading.

Przebieg Class loader choices krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 139
## layout
bullet
## slide title
Class loader choices
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: DexClassLoader, PathClassLoader i InMemoryDexClassLoader różnią się tym, skąd biorą kod i jak długo go trzymają.
- Kontrola atakującego: Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 139. Class loader choices. Dynamic code loading.

Class loader choices przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 140
## layout
bullet
## slide title
Class loader choices
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 140. Class loader choices. Dynamic code loading.

Obrona dla Class loader choices wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

#slide 141
## layout
definition
## slide title
Native versus Java
## subtitle
Co to jest
## term
Native versus Java
## definition
Natywne dlopen i dlsym mają ten sam problem z podmianą co loading pliku dex.
## teleprompter:
Slajd 141. Native versus Java. Dynamic code loading.

Natywne dlopen i dlsym mają ten sam problem z podmianą co loading pliku dex.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.

#slide 142
## layout
bullet
## slide title
Native versus Java
## subtitle
Jak działa
## bullets
- Krok 1: Natywne dlopen i dlsym mają ten sam problem z podmianą co loading pliku dex.
- Krok 2: Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 142. Native versus Java. Dynamic code loading.

Przebieg Native versus Java krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 143
## layout
bullet
## slide title
Native versus Java
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Natywne dlopen i dlsym mają ten sam problem z podmianą co loading pliku dex.
- Kontrola atakującego: Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 143. Native versus Java. Dynamic code loading.

Native versus Java przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 144
## layout
bullet
## slide title
Native versus Java
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 144. Native versus Java. Dynamic code loading.

Obrona dla Native versus Java wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.
