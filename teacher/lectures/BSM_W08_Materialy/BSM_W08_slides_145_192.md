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
Retencja decyduje o czasie życia danych, a disposal o ich fizycznym zniknięciu.
Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika. W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki. Retencja decyduje o czasie życia danych, a disposal o ich fizycznym zniknięciu. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 146
## layout
bullet
## slide title
Retention vs disposal
## subtitle
Jak działa
## bullets
- Retention vs disposal: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Retention vs disposal: Retencja mówi jak długo dane wolno trzymać a…
- Retention vs disposal: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
Retention vs disposal zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 147
## layout
bullet
## slide title
Retention vs disposal
## subtitle
Jak pęka
## bullets
- Retention vs disposal: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- Retention vs disposal: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Retention vs disposal: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Retention vs disposal przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 148
## layout
bullet
## slide title
Retention vs disposal
## subtitle
Jak się bronić
## bullets
- Retention vs disposal: Obrona wymaga polityki retention oddzielonej od disposal testów…
- Retention vs disposal: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Retention vs disposal: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Retention vs disposal wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Delete zawodzi przez remanencję danych i metadanych.
Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika. W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki. Delete zawodzi przez remanencję danych i metadanych. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 150
## layout
bullet
## slide title
Why delete fails
## subtitle
Jak działa
## bullets
- Why delete fails: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Why delete fails: Retencja mówi jak długo dane wolno trzymać a…
- Why delete fails: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
Why delete fails zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 151
## layout
bullet
## slide title
Why delete fails
## subtitle
Jak pęka
## bullets
- Why delete fails: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- Why delete fails: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Why delete fails: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Why delete fails przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 152
## layout
bullet
## slide title
Why delete fails
## subtitle
Jak się bronić
## bullets
- Why delete fails: Obrona wymaga polityki retention oddzielonej od disposal testów…
- Why delete fails: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Why delete fails: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Why delete fails wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Log-structured filesystems dopisują nowe bloki i czyszczą stare dopiero później.
Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika. W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki. Log-structured filesystems dopisują nowe bloki i czyszczą stare dopiero później. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 154
## layout
bullet
## slide title
Log-structured storage
## subtitle
Jak działa
## bullets
- Log-structured storage: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Log-structured storage: Retencja mówi jak długo dane wolno trzymać a…
- Log-structured storage: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
Log-structured storage zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 155
## layout
bullet
## slide title
Log-structured storage
## subtitle
Jak pęka
## bullets
- Log-structured storage: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- Log-structured storage: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Log-structured storage: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Log-structured storage przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 156
## layout
bullet
## slide title
Log-structured storage
## subtitle
Jak się bronić
## bullets
- Log-structured storage: Obrona wymaga polityki retention oddzielonej od disposal testów…
- Log-structured storage: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Log-structured storage: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Log-structured storage wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
YAFFS na flashu zostawia stare wersje, bo garbage collection nie kasuje wszystkiego od razu.
Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika. W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki. YAFFS na flashu zostawia stare wersje, bo garbage collection nie kasuje wszystkiego od razu. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 158
## layout
bullet
## slide title
YAFFS example
## subtitle
Jak działa
## bullets
- YAFFS example: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- YAFFS example: Retencja mówi jak długo dane wolno trzymać a…
- YAFFS example: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
YAFFS example zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 159
## layout
bullet
## slide title
YAFFS example
## subtitle
Jak pęka
## bullets
- YAFFS example: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- YAFFS example: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- YAFFS example: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
YAFFS example przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 160
## layout
bullet
## slide title
YAFFS example
## subtitle
Jak się bronić
## bullets
- YAFFS example: Obrona wymaga polityki retention oddzielonej od disposal testów…
- YAFFS example: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- YAFFS example: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
YAFFS example wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
FTL mapuje logiczne bloki na fizyczne bloki poza kontrolą filesystemu.
Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika. W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki. FTL mapuje logiczne bloki na fizyczne bloki poza kontrolą filesystemu. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 162
## layout
bullet
## slide title
FTL mapping
## subtitle
Jak działa
## bullets
- FTL mapping: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- FTL mapping: Retencja mówi jak długo dane wolno trzymać a…
- FTL mapping: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
FTL mapping zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 163
## layout
bullet
## slide title
FTL mapping
## subtitle
Jak pęka
## bullets
- FTL mapping: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- FTL mapping: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- FTL mapping: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
FTL mapping przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 164
## layout
bullet
## slide title
FTL mapping
## subtitle
Jak się bronić
## bullets
- FTL mapping: Obrona wymaga polityki retention oddzielonej od disposal testów…
- FTL mapping: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- FTL mapping: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
FTL mapping wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Overwrite nie daje gwarancji, że nadpiszesz dokładnie ten fizyczny blok, który chcesz usunąć.
Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika. W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki. Overwrite nie daje gwarancji, że nadpiszesz dokładnie ten fizyczny blok, który chcesz usunąć. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 166
## layout
bullet
## slide title
Overwrite problem
## subtitle
Jak działa
## bullets
- Overwrite problem: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Overwrite problem: Retencja mówi jak długo dane wolno trzymać a…
- Overwrite problem: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
Overwrite problem zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 167
## layout
bullet
## slide title
Overwrite problem
## subtitle
Jak pęka
## bullets
- Overwrite problem: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- Overwrite problem: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Overwrite problem: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Overwrite problem przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 168
## layout
bullet
## slide title
Overwrite problem
## subtitle
Jak się bronić
## bullets
- Overwrite problem: Obrona wymaga polityki retention oddzielonej od disposal testów…
- Overwrite problem: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Overwrite problem: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Overwrite problem wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Sama kryptografia nie pomaga, jeśli stare kopie lub klucze nadal są dostępne.
Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika. W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki. Sama kryptografia nie pomaga, jeśli stare kopie lub klucze nadal są dostępne. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 170
## layout
bullet
## slide title
Encryption limitation
## subtitle
Jak działa
## bullets
- Encryption limitation: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Encryption limitation: Retencja mówi jak długo dane wolno trzymać a…
- Encryption limitation: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
Encryption limitation zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 171
## layout
bullet
## slide title
Encryption limitation
## subtitle
Jak pęka
## bullets
- Encryption limitation: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- Encryption limitation: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Encryption limitation: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Encryption limitation przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 172
## layout
bullet
## slide title
Encryption limitation
## subtitle
Jak się bronić
## bullets
- Encryption limitation: Obrona wymaga polityki retention oddzielonej od disposal testów…
- Encryption limitation: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Encryption limitation: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Encryption limitation wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Purge chce realnie zniszczyć lub przenieść dane aż recovery przestaje być praktyczne.
Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika. W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki. Purge chce realnie zniszczyć lub przenieść dane aż recovery przestaje być praktyczne. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 174
## layout
bullet
## slide title
Purge algorithm
## subtitle
Jak działa
## bullets
- Purge algorithm: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Purge algorithm: Retencja mówi jak długo dane wolno trzymać a…
- Purge algorithm: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
Purge algorithm zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 175
## layout
bullet
## slide title
Purge algorithm
## subtitle
Jak pęka
## bullets
- Purge algorithm: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- Purge algorithm: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Purge algorithm: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Purge algorithm przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 176
## layout
bullet
## slide title
Purge algorithm
## subtitle
Jak się bronić
## bullets
- Purge algorithm: Obrona wymaga polityki retention oddzielonej od disposal testów…
- Purge algorithm: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Purge algorithm: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Purge algorithm wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Ballooning zjada wolne miejsce, by wymusić wypchnięcie bloku celu.
Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika. W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki. Ballooning zjada wolne miejsce, by wymusić wypchnięcie bloku celu. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 178
## layout
bullet
## slide title
Ballooning algorithm
## subtitle
Jak działa
## bullets
- Ballooning algorithm: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Ballooning algorithm: Retencja mówi jak długo dane wolno trzymać a…
- Ballooning algorithm: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
Ballooning algorithm zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 179
## layout
bullet
## slide title
Ballooning algorithm
## subtitle
Jak pęka
## bullets
- Ballooning algorithm: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- Ballooning algorithm: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Ballooning algorithm: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Ballooning algorithm przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 180
## layout
bullet
## slide title
Ballooning algorithm
## subtitle
Jak się bronić
## bullets
- Ballooning algorithm: Obrona wymaga polityki retention oddzielonej od disposal testów…
- Ballooning algorithm: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Ballooning algorithm: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Ballooning algorithm wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Zero overwriting wypełnia obszar i potem vacuumuje resztki.
Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika. W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki. Zero overwriting wypełnia obszar i potem vacuumuje resztki. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 182
## layout
bullet
## slide title
Zero overwriting
## subtitle
Jak działa
## bullets
- Zero overwriting: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Zero overwriting: Retencja mówi jak długo dane wolno trzymać a…
- Zero overwriting: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
Zero overwriting zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 183
## layout
bullet
## slide title
Zero overwriting
## subtitle
Jak pęka
## bullets
- Zero overwriting: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- Zero overwriting: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Zero overwriting: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Zero overwriting przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 184
## layout
bullet
## slide title
Zero overwriting
## subtitle
Jak się bronić
## bullets
- Zero overwriting: Obrona wymaga polityki retention oddzielonej od disposal testów…
- Zero overwriting: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Zero overwriting: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Zero overwriting wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Snapshoty i historia wersji komplikują kasowanie, bo stare stany nadal istnieją.
Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika. W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki. Snapshoty i historia wersji komplikują kasowanie, bo stare stany nadal istnieją. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 186
## layout
bullet
## slide title
Versioned file system
## subtitle
Jak działa
## bullets
- Versioned file system: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Versioned file system: Retencja mówi jak długo dane wolno trzymać a…
- Versioned file system: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
Versioned file system zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 187
## layout
bullet
## slide title
Versioned file system
## subtitle
Jak pęka
## bullets
- Versioned file system: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- Versioned file system: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Versioned file system: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Versioned file system przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 188
## layout
bullet
## slide title
Versioned file system
## subtitle
Jak się bronić
## bullets
- Versioned file system: Obrona wymaga polityki retention oddzielonej od disposal testów…
- Versioned file system: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Versioned file system: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Versioned file system wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Forensic verification sprawdza, czy po usunięciu da się jeszcze odzyskać treść lub jej ślady.
Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika. W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki. Forensic verification sprawdza, czy po usunięciu da się jeszcze odzyskać treść lub jej ślady. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 190
## layout
bullet
## slide title
Forensic verification
## subtitle
Jak działa
## bullets
- Forensic verification: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Forensic verification: Retencja mówi jak długo dane wolno trzymać a…
- Forensic verification: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
Forensic verification zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 191
## layout
bullet
## slide title
Forensic verification
## subtitle
Jak pęka
## bullets
- Forensic verification: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- Forensic verification: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Forensic verification: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Forensic verification przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 192
## layout
bullet
## slide title
Forensic verification
## subtitle
Jak się bronić
## bullets
- Forensic verification: Obrona wymaga polityki retention oddzielonej od disposal testów…
- Forensic verification: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Forensic verification: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Forensic verification wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.
