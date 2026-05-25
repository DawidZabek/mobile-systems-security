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
Retencja ustala, jak długo dane mogą istnieć w systemie, a disposal opisuje moment ich faktycznego wycofania z nośnika i z kopii pośrednich. W systemach log-structured sam zapis i sam delete nie są tym samym: zmienia się status logiczny, ale stare segmenty, metadane, cache i snapshoty mogą nadal trzymać treść. W flashu ten rozdźwięk rośnie przez wear leveling i translację bloków w FTL.
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
Przepływ zaczyna się od zwykłego usunięcia w API albo w systemie plików, ale to jeszcze nie oznacza usunięcia fizycznego. Na nośniku dane mogą czekać w segmentach nieużytych, w metadanych o poprzednim stanie i w kopiach wykonanych przez synchronizację. Secure deletion musi więc opisać nie tylko delete, lecz także to, co dzieje się z blokami po garbage collection.
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
Atak wykorzystuje to, że system uznaje dane za usunięte z punktu widzenia aplikacji, choć resztki nadal istnieją. Wystarczy odzyskać stary blok, miniaturę, cache albo kopię pośrednią z backupu. Jeśli w grę wchodzi wersjonowanie albo FTL, przeciwnik nie musi obchodzić szyfrowania, tylko musi znaleźć wcześniejszy zapis.
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
Obrona wymaga osobnej polityki retencji i osobnej polityki disposal. Trzeba zdecydować, kiedy dane są jeszcze potrzebne, kiedy mają zniknąć logicznie, a kiedy fizycznie. Potem potrzebny jest test odzysku po kasowaniu, pomiar kosztu w wear i latency oraz sprawdzenie, czy kopie w cache i backupie nie zostają poza zasięgiem tej samej reguły.
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
Delete fails, bo system usuwa nazwę lub wpis katalogowy, a nie zawsze faktyczne bity. Remanencja obejmuje treść, metadane, mapy alokacji, miniatury i ślady w dziennikach. Jeżeli nośnik jest flashowy, stare komórki mogą pozostać osiągalne dla warstwy poniżej filesystemu.
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
Najpierw aplikacja oznacza plik jako usunięty, potem filesystem zwalnia wpis, a dopiero później garbage collector może przenieść lub nadpisać fragmenty danych. W log-structured storage ten krok nie jest natychmiastowy, bo system zapisuje nowe wersje obok starych. To dlatego sam moment delete nie daje jeszcze gwarancji zniknięcia treści.
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
W ataku nie trzeba łamać kryptografii. Wystarczy odzyskać poprzedni blok danych, poprzednią wersję metadanych albo plik tymczasowy, który aplikacja uważała za nietrwały. Jeśli backup albo synchronizacja wykonały dodatkową kopię, usunięcie jednego katalogu niczego nie zmienia poza bieżącym widokiem aplikacji.
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
Obrona polega na tym, że usuwanie jest projektowane tak samo świadomie jak zapis. Trzeba wiedzieć, które kopie istnieją, gdzie są trzymane, jak długo mogą żyć i czy można je odnaleźć po odtworzeniu nośnika. W praktyce potrzebne są testy odzysku, a nie tylko sprawdzenie, czy plik znika z listy.
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
Log-structured storage dopisuje nowe dane zamiast nadpisywać stare miejsce. To daje dobrą wydajność zapisu i prostsze kolejkowanie zmian, ale tworzy historię starych segmentów. Usuwanie nie usuwa natychmiast wszystkich śladów, bo stary zapis pozostaje w blokach, dopóki garbage collection nie uzna ich za zbędne.
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
Sekwencja pracy jest prosta: najpierw powstaje nowa wersja danych, potem stara wersja traci aktualność, a dopiero później system odzyskuje przestrzeń. W międzyczasie mogą istnieć równolegle segment aktywny i segment już niepotrzebny. To właśnie w tym oknie stare treści są nadal odzyskiwalne.
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
Przeciwnik wykorzystuje fakt, że stare segmenty nie znikają w chwili zmiany widoku logicznego. Jeśli do tego dołożysz cache, miniatury, dzienniki i kopie w synchronizacji, to recovery dostaje wiele punktów zaczepienia. Atak staje się prosty: znaleźć nieaktualny, ale nadal zapisany stan.
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
Obrona musi uwzględnić cały cykl życia danych, nie tylko nazwę pliku. Trzeba sprawdzić, które katalogi są cache, które są backupem, które są tymczasowe, a które naprawdę można czyścić agresywnie. W log-structured storage bezpieczeństwo kasowania zależy od tego, czy polityka wie o wszystkich miejscach, w których dane się rozszczepiają.
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
YAFFS pokazuje problem bardzo wprost: system jest projektowany pod flash, więc zapis i kasowanie są rozdzielone przez wear leveling i garbage collection. Stary blok może przeżyć kilka kolejnych zmian widoku logicznego, zanim zostanie fizycznie zwolniony. To czyni każde secure deletion zależnym od zachowania warstwy niższej niż filesystem.
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
W praktyce aplikacja widzi zwykły delete, ale YAFFS może tylko oznaczyć dane jako nieaktualne i przesunąć prawdziwe czyszczenie na później. Jeżeli w międzyczasie nośnik wykona dodatkowe przeniesienia, odzysk może trafić nie w jeden blok, tylko w kilka historycznych kopii. To właśnie dlatego laboratoria secure deletion na YAFFS mierzą skuteczność w czasie, a nie tylko w chwili wywołania API.
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
Atak na YAFFS nie musi wyglądać spektakularnie. Wystarczy zrzut nośnika, analiza poprzednich segmentów i szukanie bloków, które po stronie systemu są już wolne, ale nie zostały jeszcze fizycznie wyczyszczone. Jeśli pojawiają się też backupy lub pliki tymczasowe, odzysk staje się jeszcze prostszy.
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
Obrona dla YAFFS musi liczyć się z ceną kasowania. Im agresywniejsze wymazywanie, tym większy wpływ na wear, czas i stabilność zapisu. Sensowne zabezpieczenie wymaga więc polityki, która wie, kiedy warto usunąć natychmiast, a kiedy lepiej przechować dane szyfrowane do czasu naturalnego wygaszenia.
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
FTL stoi między filesystemem a fizycznymi komórkami pamięci. System plików mówi „usuń ten blok”, ale FTL może przenieść dane w inne miejsce, zostawiając poprzedni zapis jako resztkę do późniejszego garbage collection. To dlatego logiczny adres nie odpowiada jednemu, stałemu fizycznemu blokowi.
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
Gdy aplikacja nadpisuje rekord albo usuwa plik, FTL może zmapować nowy zapis do świeżego miejsca, a stary blok zostawić do sprzątnięcia później. W efekcie w urządzeniu powstają dwie warstwy prawdy: ta widoczna dla systemu i ta istniejąca fizycznie do czasu wewnętrznego porządkowania.
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
Przeciwnik wykorzystuje tę różnicę, gdy szuka starego układu bloków na nośniku. Nadpisanie logiczne nie oznacza nadpisania dokładnie tego samego miejsca na kościach flash. Jeżeli do tego dojdą snapshoty albo cache, to odzysk z poziomu niższego niż filesystem zaczyna być realny.
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
Obrona przeciw FTL nie polega na samym delete. Potrzebne są procedury, które wiedzą, kiedy fizyczne wyczyszczenie jest naprawdę zakończone, a kiedy system tylko oddał blok do ponownego użycia. Bez takiej wiedzy secure deletion jest tylko deklaracją z poziomu API.
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
Overwrite problem polega na tym, że program myśli w kategoriach pliku, a nośnik pracuje w kategoriach bloków i stron. W log-structured lub flashowym systemie plików nadpisanie może trafić w nowy blok, a stary pozostać nienaruszony. Samo „wpisanie zera” nie daje więc gwarancji fizycznego wymazania.
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
Przebieg jest podstępny: system zapisuje nową wersję w nowym miejscu, katalog wskazuje już na świeży rekord, a stary rekord nadal leży w tle. To oznacza, że przy kasowaniu trzeba patrzeć nie tylko na widok logiczny, ale też na ścieżkę migracji danych przez warstwę pośrednią.
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
Atak polega na tym, że ktoś czyta stary blok, do którego filesystem przestał się odwoływać, ale który wciąż istnieje fizycznie. Gdy do tego dołożysz logi, cache, miniatury i kopie synchronizowane, skala resztek rośnie bardzo szybko. Wtedy overwrite okazuje się tylko zmianą referencji, nie czyszczeniem nośnika.
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
Obrona wymaga sprawdzenia, że wymazanie nie kończy się tylko na logicznym update katalogu. Trzeba wykonać test odzysku, porównać zachowanie na różnych nośnikach i odnieść koszt do oczekiwanej skuteczności. Jeśli nośnik jest flashowy, najważniejsze jest to, co dzieje się poniżej warstwy plików.
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
Szyfrowanie nie rozwiązuje problemu kasowania, jeśli stare kopie i stare klucze nadal istnieją. Dane mogą być zaszyfrowane, a mimo to nadal obecne w innych blokach, w snapshotach albo w backupie. Secure deletion musi więc objąć zarówno treść, jak i ślady po niej.
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
W praktyce przebieg wygląda tak: aplikacja usuwa rekord, filesystem zwalnia miejsce logicznie, ale fizyczna kopia zostaje, dopóki system jej nie porzuci. Jeżeli backup albo cache mają własne cykle życia, klucz szyfrujący też nie wystarcza, bo kopia nadal może zostać odtworzona z innego miejsca.
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
Atak na „same encryption” zwykle polega na odzyskaniu starszej wersji zaszyfrowanego pliku albo odtworzeniu klucza z miejsca, które nie zostało wyczyszczone. Jeśli zniknie tylko jedna ścieżka, a zostanie druga, dane pozostają dostępne. To dlatego szyfrowanie jest ochroną poufności, ale nie automatycznie usuwaniem.
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
Obrona musi połączyć usuwanie treści z usuwaniem śladów operacyjnych. Trzeba wiedzieć, gdzie są kopie, jak długo żyją i co robi system po zmianie kluczy. Bez tego szyfrowanie daje fałszywe poczucie zakończenia, mimo że fizyczne resztki nadal są obecne.
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
Purge algorithm ma doprowadzić nośnik do stanu, w którym odzysk przestaje być praktyczny. To oznacza albo fizyczne zniszczenie danych, albo takie przeniesienie i nadpisanie bloków, żeby nie dało się już odtworzyć spójnej treści. W badaniach nad secure deletion purge jest najbliżej twardego wymazywania.
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
Krok purge polega na identyfikacji bloków, ich przeniesieniu lub oznaczeniu do zniszczenia i doprowadzeniu garbage collection do faktycznego oczyszczenia. W log-structured storage ten proces trwa, bo system nie usuwa bloków natychmiast. Dopiero gdy kopie znikną z aktywnego obiegu, można mówić o realnym kasowaniu.
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
Przeciwnik szuka momentu, w którym purge jeszcze nie skończył sprzątania. Jeśli stary blok pozostaje poza aktywnym widokiem, ale nie został fizycznie wymazany, odzysk nadal jest możliwy. Zewnętrzny backup albo cache tylko zwiększa liczbę miejsc, które trzeba oczyścić.
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
Obrona przy purge wymaga sprawdzenia, czy system naprawdę doprowadził sprzątanie do końca. Sama deklaracja usunięcia nie wystarcza, potrzebny jest test po czasie i na różnych warstwach nośnika. To szczególnie ważne tam, gdzie garbage collection działa w tle i nie kończy się w chwili wywołania API.
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
Ballooning to metoda wymuszania sprzątania przez zjadanie wolnego miejsca. System wypełnia pamięć dodatkowymi zapisami, aż nośnik musi wyrzucić wcześniejszy blok albo go przenieść. Dzięki temu można zmusić warstwę pod spodem do pracy nad usunięciem wskazanego fragmentu.
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
Przebieg ballooningu jest pośredni: najpierw pojawiają się sztuczne zapisy, potem rośnie presja na garbage collection, a na końcu blok celu zostaje wypchnięty lub zastąpiony. To nie jest jednorazowe „usuń”, tylko kontrolowane zatkanie przestrzeni, żeby system sam wykonał fizyczne sprzątanie.
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
Atak na ballooning wykorzystuje moment, w którym presja jeszcze nie doprowadziła do pełnego wyczyszczenia. Jeżeli stare segmenty nadal istnieją, a kolejne zapisy tylko przesuwają granicę, odzysk może się udać z wcześniejszej wersji nośnika. Im więcej kopii pośrednich, tym większa szansa, że jedna z nich przetrwa.
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
Obrona musi weryfikować, czy ballooning faktycznie wymusił likwidację celu, a nie tylko zajęcie dodatkowego miejsca. Jeśli test pokazuje stale odzyskiwalne fragmenty, metoda nie spełnia swojej roli. Do sensownego użycia potrzebne są też limity kosztu, bo zbyt agresywne zjadanie miejsca wpływa na wydajność całego urządzenia.
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
Zero overwriting polega na wypełnieniu obszaru kontrolowanym wzorcem, a potem wymuszeniu vacuumingu i usunięcia resztek. Celem jest wypchnięcie starych danych tak, żeby nie zostały w aktywnym obiegu ani w łatwo dostępnej kopii. Ta technika próbuje zbliżyć się do fizycznego wymazania bez prostego nadpisania jednego adresu.
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
Przebieg wymaga zwykle kilku kroków: najpierw zapis wypełniający, potem odczyt i porównanie, potem czyszczenie resztek i sprawdzenie, czy nośnik oddał miejsce do ponownego użycia. W systemie flash liczy się jednak to, czy pod spodem nie zostały nadal stare komórki, które nie weszły jeszcze do obiegu.
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
Atak na zero overwriting wykorzystuje to, że czyszczenie może nie objąć wszystkich warstw naraz. Jeżeli część danych została przeniesiona w trakcie porządkowania, a część czeka jeszcze na garbage collection, odzysk może nastąpić z kilku chwilowych stanów naraz. Wtedy samo wypełnienie nie daje pełnej gwarancji.
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
Obrona wymaga nie tylko techniki, ale i dowodu skuteczności. Trzeba sprawdzić, czy po całym cyklu nie da się już odzyskać sensownej treści, oraz policzyć koszt operacji w zużyciu nośnika i czasie. Jeśli testy pokazują resztki, technika nie jest jeszcze bezpieczna dla tego konkretnego nośnika.
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
Wersjonowany filesystem zachowuje historię zmian, więc stare stany istnieją obok nowego. Snapshoty i gałęzie dają wygodę odtwarzania, ale komplikują kasowanie, bo usunięcie bieżącej wersji nie usuwa automatycznie poprzednich.
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
Przebieg w systemie wersjonowanym jest taki, że nowe dane trafiają do aktualnego widoku, a stare wersje pozostają pod spodem jako punkty przywracania. Jeżeli nie ma osobnego procesu usuwania historii, delete dotyka tylko bieżącej gałęzi. W praktyce trzeba więc czyścić także to, co użytkownik już przestał widzieć.
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
Atak na system wersjonowany jest prosty: odzyskuje się poprzedni snapshot, nieaktualną gałąź albo stare metadane. Jeśli aplikacja lub backup zatrzymały wcześniejszą wersję, osoba atakująca nie potrzebuje łamać bieżącej kopii. Wystarczy sięgnąć po historię, którą system nadal przechowuje.
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
Obrona wymaga polityki, która wie, które wersje są potrzebne, a które muszą zniknąć naprawdę. To oznacza osobne zarządzanie historią, testy odzysku i kontrolę, czy stare wersje nie przetrwają w miejscach pomocniczych. Bez tego wersjonowanie staje się ukrytą kopią zapasową.
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
Forensic verification sprawdza, czy po wymazaniu można jeszcze odzyskać treść albo jej ślady. To nie jest ocena deklaracji, tylko praktyczny test na nośniku, segmentach, metadanych i artefaktach pośrednich. Jeśli odzysk działa, secure deletion nie zadziałało w tej konfiguracji.
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
Przebieg takiego sprawdzenia zwykle obejmuje próbę odczytu pozostałości po delete, analizę metadanych, badanie snapshotów i porównanie wyniku z oczekiwaniem. Na flashu trzeba dodatkowo uwzględnić czas pracy garbage collection, bo resztki nie zawsze znikają od razu. To test, który musi uwzględnić opóźnienie, a nie tylko chwilę wywołania.
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
Atak w tym obszarze polega na tym, że ktoś korzysta z okna, w którym resztki jeszcze istnieją. Nie trzeba łamać szyfrowania, jeśli da się odzyskać blok, kopię pośrednią albo wersję ze snapshotu. Weryfikacja kryminalistyczna właśnie po to istnieje, żeby ten stan wykryć.
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
Obrona wymaga testów po czasie i na realnym nośniku, nie tylko w emulatorze czy na pustym katalogu. Trzeba potwierdzić, że po całym cyklu nie ma już sensownej treści do odzyskania i że koszt takiego usuwania jest akceptowalny. Bez tego każda deklaracja secure deletion pozostaje tylko deklaracją.