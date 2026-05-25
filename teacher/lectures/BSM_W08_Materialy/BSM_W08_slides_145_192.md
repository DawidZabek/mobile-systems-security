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
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.

#slide 146
## layout
bullet
## slide title
Retention vs disposal
## subtitle
Jak działa
## bullets
- Krok 1: Retencja decyduje o czasie życia danych, a disposal o ich fizycznym zniknięciu.
- Krok 2: W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 146. Retention vs disposal. Retencja i secure deletion.

Przebieg Retention vs disposal krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 147
## layout
bullet
## slide title
Retention vs disposal
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Retencja decyduje o czasie życia danych, a disposal o ich fizycznym zniknięciu.
- Kontrola atakującego: Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 147. Retention vs disposal. Retencja i secure deletion.

Retention vs disposal przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
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
- Reguła: Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 148. Retention vs disposal. Retencja i secure deletion.

Obrona dla Retention vs disposal wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
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
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.

#slide 150
## layout
bullet
## slide title
Why delete fails
## subtitle
Jak działa
## bullets
- Krok 1: Delete zawodzi przez remanencję danych i metadanych.
- Krok 2: W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 150. Why delete fails. Retencja i secure deletion.

Przebieg Why delete fails krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 151
## layout
bullet
## slide title
Why delete fails
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Delete zawodzi przez remanencję danych i metadanych.
- Kontrola atakującego: Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 151. Why delete fails. Retencja i secure deletion.

Why delete fails przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
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
- Reguła: Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 152. Why delete fails. Retencja i secure deletion.

Obrona dla Why delete fails wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
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
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.

#slide 154
## layout
bullet
## slide title
Log-structured storage
## subtitle
Jak działa
## bullets
- Krok 1: Log-structured filesystems dopisują nowe bloki i czyszczą stare dopiero później.
- Krok 2: W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 154. Log-structured storage. Retencja i secure deletion.

Przebieg Log-structured storage krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 155
## layout
bullet
## slide title
Log-structured storage
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Log-structured filesystems dopisują nowe bloki i czyszczą stare dopiero później.
- Kontrola atakującego: Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 155. Log-structured storage. Retencja i secure deletion.

Log-structured storage przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
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
- Reguła: Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 156. Log-structured storage. Retencja i secure deletion.

Obrona dla Log-structured storage wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
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
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.

#slide 158
## layout
bullet
## slide title
YAFFS example
## subtitle
Jak działa
## bullets
- Krok 1: YAFFS na flashu zostawia stare wersje, bo garbage collection nie kasuje wszystkiego od razu.
- Krok 2: W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 158. YAFFS example. Retencja i secure deletion.

Przebieg YAFFS example krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 159
## layout
bullet
## slide title
YAFFS example
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: YAFFS na flashu zostawia stare wersje, bo garbage collection nie kasuje wszystkiego od razu.
- Kontrola atakującego: Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 159. YAFFS example. Retencja i secure deletion.

YAFFS example przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
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
- Reguła: Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 160. YAFFS example. Retencja i secure deletion.

Obrona dla YAFFS example wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
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
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.

#slide 162
## layout
bullet
## slide title
FTL mapping
## subtitle
Jak działa
## bullets
- Krok 1: FTL mapuje logiczne bloki na fizyczne bloki poza kontrolą filesystemu.
- Krok 2: W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 162. FTL mapping. Retencja i secure deletion.

Przebieg FTL mapping krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 163
## layout
bullet
## slide title
FTL mapping
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: FTL mapuje logiczne bloki na fizyczne bloki poza kontrolą filesystemu.
- Kontrola atakującego: Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 163. FTL mapping. Retencja i secure deletion.

FTL mapping przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
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
- Reguła: Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 164. FTL mapping. Retencja i secure deletion.

Obrona dla FTL mapping wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
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
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.

#slide 166
## layout
bullet
## slide title
Overwrite problem
## subtitle
Jak działa
## bullets
- Krok 1: Overwrite nie daje gwarancji, że nadpiszesz dokładnie ten fizyczny blok, który chcesz usunąć.
- Krok 2: W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 166. Overwrite problem. Retencja i secure deletion.

Przebieg Overwrite problem krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 167
## layout
bullet
## slide title
Overwrite problem
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Overwrite nie daje gwarancji, że nadpiszesz dokładnie ten fizyczny blok, który chcesz usunąć.
- Kontrola atakującego: Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 167. Overwrite problem. Retencja i secure deletion.

Overwrite problem przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
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
- Reguła: Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 168. Overwrite problem. Retencja i secure deletion.

Obrona dla Overwrite problem wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
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
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.

#slide 170
## layout
bullet
## slide title
Encryption limitation
## subtitle
Jak działa
## bullets
- Krok 1: Sama kryptografia nie pomaga, jeśli stare kopie lub klucze nadal są dostępne.
- Krok 2: W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 170. Encryption limitation. Retencja i secure deletion.

Przebieg Encryption limitation krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 171
## layout
bullet
## slide title
Encryption limitation
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Sama kryptografia nie pomaga, jeśli stare kopie lub klucze nadal są dostępne.
- Kontrola atakującego: Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 171. Encryption limitation. Retencja i secure deletion.

Encryption limitation przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
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
- Reguła: Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 172. Encryption limitation. Retencja i secure deletion.

Obrona dla Encryption limitation wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
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
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.

#slide 174
## layout
bullet
## slide title
Purge algorithm
## subtitle
Jak działa
## bullets
- Krok 1: Purge chce realnie zniszczyć lub przenieść dane aż recovery przestaje być praktyczne.
- Krok 2: W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 174. Purge algorithm. Retencja i secure deletion.

Przebieg Purge algorithm krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 175
## layout
bullet
## slide title
Purge algorithm
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Purge chce realnie zniszczyć lub przenieść dane aż recovery przestaje być praktyczne.
- Kontrola atakującego: Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 175. Purge algorithm. Retencja i secure deletion.

Purge algorithm przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
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
- Reguła: Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 176. Purge algorithm. Retencja i secure deletion.

Obrona dla Purge algorithm wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
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
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.

#slide 178
## layout
bullet
## slide title
Ballooning algorithm
## subtitle
Jak działa
## bullets
- Krok 1: Ballooning zjada wolne miejsce, by wymusić wypchnięcie bloku celu.
- Krok 2: W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 178. Ballooning algorithm. Retencja i secure deletion.

Przebieg Ballooning algorithm krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 179
## layout
bullet
## slide title
Ballooning algorithm
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Ballooning zjada wolne miejsce, by wymusić wypchnięcie bloku celu.
- Kontrola atakującego: Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 179. Ballooning algorithm. Retencja i secure deletion.

Ballooning algorithm przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
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
- Reguła: Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 180. Ballooning algorithm. Retencja i secure deletion.

Obrona dla Ballooning algorithm wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
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
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.

#slide 182
## layout
bullet
## slide title
Zero overwriting
## subtitle
Jak działa
## bullets
- Krok 1: Zero overwriting wypełnia obszar i potem vacuumuje resztki.
- Krok 2: W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 182. Zero overwriting. Retencja i secure deletion.

Przebieg Zero overwriting krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 183
## layout
bullet
## slide title
Zero overwriting
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Zero overwriting wypełnia obszar i potem vacuumuje resztki.
- Kontrola atakującego: Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 183. Zero overwriting. Retencja i secure deletion.

Zero overwriting przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
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
- Reguła: Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 184. Zero overwriting. Retencja i secure deletion.

Obrona dla Zero overwriting wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
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
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.

#slide 186
## layout
bullet
## slide title
Versioned file system
## subtitle
Jak działa
## bullets
- Krok 1: Snapshoty i historia wersji komplikują kasowanie, bo stare stany nadal istnieją.
- Krok 2: W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 186. Versioned file system. Retencja i secure deletion.

Przebieg Versioned file system krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 187
## layout
bullet
## slide title
Versioned file system
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Snapshoty i historia wersji komplikują kasowanie, bo stare stany nadal istnieją.
- Kontrola atakującego: Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 187. Versioned file system. Retencja i secure deletion.

Versioned file system przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
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
- Reguła: Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 188. Versioned file system. Retencja i secure deletion.

Obrona dla Versioned file system wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
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
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.

#slide 190
## layout
bullet
## slide title
Forensic verification
## subtitle
Jak działa
## bullets
- Krok 1: Forensic verification sprawdza, czy po usunięciu da się jeszcze odzyskać treść lub jej ślady.
- Krok 2: W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 190. Forensic verification. Retencja i secure deletion.

Przebieg Forensic verification krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 191
## layout
bullet
## slide title
Forensic verification
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Forensic verification sprawdza, czy po usunięciu da się jeszcze odzyskać treść lub jej ślady.
- Kontrola atakującego: Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 191. Forensic verification. Retencja i secure deletion.

Forensic verification przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
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
- Reguła: Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 192. Forensic verification. Retencja i secure deletion.

Obrona dla Forensic verification wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.
