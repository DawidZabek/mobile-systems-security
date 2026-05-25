#slide 49
## layout
definition
## slide title
Media as data class — Co to jest
## term
Media as data class
## definition
Zdjęcia i filmy są traktowane jako osobna klasa prywatnych danych.
## teleprompter:
Slajd 49. Media as data class. Selected media i photo picker.

Definicja i granica pojęcia. Media as data class w tym miejscu oznacza dokładnie: Zdjęcia i filmy są traktowane jako osobna klasa prywatnych danych. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 50
## layout
bullet
## slide title
Media as data class — Jak działa
## bullets
- Krok 1: Zdjęcia i filmy są traktowane jako osobna klasa prywatnych danych.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 50. Media as data class. Selected media i photo picker.

Wejście i stan początkowy. Media as data class w tym miejscu oznacza dokładnie: Zdjęcia i filmy są traktowane jako osobna klasa prywatnych danych. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 51
## layout
bullet
## slide title
Media as data class — Jak pęka
## bullets
- Warunek powodzenia: Zdjęcia i filmy są traktowane jako osobna klasa prywatnych danych.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 51. Media as data class. Selected media i photo picker.

Warunek powodzenia ataku. Media as data class w tym miejscu oznacza dokładnie: Zdjęcia i filmy są traktowane jako osobna klasa prywatnych danych. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 52
## layout
bullet
## slide title
Media as data class — Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 52. Media as data class. Selected media i photo picker.

Reguła i miejsce egzekwowania. Media as data class w tym miejscu oznacza dokładnie: Zdjęcia i filmy są traktowane jako osobna klasa prywatnych danych. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 53
## layout
definition
## slide title
Selected Photos Access — Co to jest
## term
Selected Photos Access
## definition
Android 14 może dać dostęp tylko do zdjęć i filmów wybranych przez użytkownika.
## teleprompter:
Slajd 53. Selected Photos Access. Selected media i photo picker.

Definicja i granica pojęcia. Selected Photos Access w tym miejscu oznacza dokładnie: Android 14 może dać dostęp tylko do zdjęć i filmów wybranych przez użytkownika. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 54
## layout
bullet
## slide title
Selected Photos Access — Jak działa
## bullets
- Krok 1: Android 14 może dać dostęp tylko do zdjęć i filmów wybranych przez użytkownika.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 54. Selected Photos Access. Selected media i photo picker.

Wejście i stan początkowy. Selected Photos Access w tym miejscu oznacza dokładnie: Android 14 może dać dostęp tylko do zdjęć i filmów wybranych przez użytkownika. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 55
## layout
bullet
## slide title
Selected Photos Access — Jak pęka
## bullets
- Warunek powodzenia: Android 14 może dać dostęp tylko do zdjęć i filmów wybranych przez użytkownika.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 55. Selected Photos Access. Selected media i photo picker.

Warunek powodzenia ataku. Selected Photos Access w tym miejscu oznacza dokładnie: Android 14 może dać dostęp tylko do zdjęć i filmów wybranych przez użytkownika. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 56
## layout
bullet
## slide title
Selected Photos Access — Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 56. Selected Photos Access. Selected media i photo picker.

Reguła i miejsce egzekwowania. Selected Photos Access w tym miejscu oznacza dokładnie: Android 14 może dać dostęp tylko do zdjęć i filmów wybranych przez użytkownika. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 57
## layout
definition
## slide title
READ_MEDIA_VISUAL_USER_SELECTED — Co to jest
## term
READ_MEDIA_VISUAL_USER_SELECTED
## definition
READ_MEDIA_VISUAL_USER_SELECTED oznacza partial access do wybranych mediów wizualnych.
## teleprompter:
Slajd 57. READ_MEDIA_VISUAL_USER_SELECTED. Selected media i photo picker.

Definicja i granica pojęcia. READ_MEDIA_VISUAL_USER_SELECTED w tym miejscu oznacza dokładnie: READ_MEDIA_VISUAL_USER_SELECTED oznacza partial access do wybranych mediów wizualnych. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 58
## layout
bullet
## slide title
READ_MEDIA_VISUAL_USER_SELECTED — Jak działa
## bullets
- Krok 1: READ_MEDIA_VISUAL_USER_SELECTED oznacza partial access do wybranych mediów wizualnych.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 58. READ_MEDIA_VISUAL_USER_SELECTED. Selected media i photo picker.

Wejście i stan początkowy. READ_MEDIA_VISUAL_USER_SELECTED w tym miejscu oznacza dokładnie: READ_MEDIA_VISUAL_USER_SELECTED oznacza partial access do wybranych mediów wizualnych. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 59
## layout
bullet
## slide title
READ_MEDIA_VISUAL_USER_SELECTED — Jak pęka
## bullets
- Warunek powodzenia: READ_MEDIA_VISUAL_USER_SELECTED oznacza partial access do wybranych mediów wizualnych.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 59. READ_MEDIA_VISUAL_USER_SELECTED. Selected media i photo picker.

Warunek powodzenia ataku. READ_MEDIA_VISUAL_USER_SELECTED w tym miejscu oznacza dokładnie: READ_MEDIA_VISUAL_USER_SELECTED oznacza partial access do wybranych mediów wizualnych. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 60
## layout
bullet
## slide title
READ_MEDIA_VISUAL_USER_SELECTED — Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 60. READ_MEDIA_VISUAL_USER_SELECTED. Selected media i photo picker.

Reguła i miejsce egzekwowania. READ_MEDIA_VISUAL_USER_SELECTED w tym miejscu oznacza dokładnie: READ_MEDIA_VISUAL_USER_SELECTED oznacza partial access do wybranych mediów wizualnych. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 61
## layout
definition
## slide title
Compatibility mode — Co to jest
## term
Compatibility mode
## definition
Legacy app może działać w trybie kompatybilności, w którym system chroni wybrany podzbiór mediów.
## teleprompter:
Slajd 61. Compatibility mode. Selected media i photo picker.

Definicja i granica pojęcia. Compatibility mode w tym miejscu oznacza dokładnie: Legacy app może działać w trybie kompatybilności, w którym system chroni wybrany podzbiór mediów. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 62
## layout
bullet
## slide title
Compatibility mode — Jak działa
## bullets
- Krok 1: Legacy app może działać w trybie kompatybilności, w którym system chroni wybrany podzbiór mediów.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 62. Compatibility mode. Selected media i photo picker.

Wejście i stan początkowy. Compatibility mode w tym miejscu oznacza dokładnie: Legacy app może działać w trybie kompatybilności, w którym system chroni wybrany podzbiór mediów. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 63
## layout
bullet
## slide title
Compatibility mode — Jak pęka
## bullets
- Warunek powodzenia: Legacy app może działać w trybie kompatybilności, w którym system chroni wybrany podzbiór mediów.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 63. Compatibility mode. Selected media i photo picker.

Warunek powodzenia ataku. Compatibility mode w tym miejscu oznacza dokładnie: Legacy app może działać w trybie kompatybilności, w którym system chroni wybrany podzbiór mediów. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 64
## layout
bullet
## slide title
Compatibility mode — Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 64. Compatibility mode. Selected media i photo picker.

Reguła i miejsce egzekwowania. Compatibility mode w tym miejscu oznacza dokładnie: Legacy app może działać w trybie kompatybilności, w którym system chroni wybrany podzbiór mediów. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 65
## layout
definition
## slide title
Permission matrix — Co to jest
## term
Permission matrix
## definition
Obrazy, filmy i metadane lokalizacji mają różne ścieżki uprawnień i ekspozycji.
## teleprompter:
Slajd 65. Permission matrix. Selected media i photo picker.

Definicja i granica pojęcia. Permission matrix w tym miejscu oznacza dokładnie: Obrazy, filmy i metadane lokalizacji mają różne ścieżki uprawnień i ekspozycji. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 66
## layout
bullet
## slide title
Permission matrix — Jak działa
## bullets
- Krok 1: Obrazy, filmy i metadane lokalizacji mają różne ścieżki uprawnień i ekspozycji.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 66. Permission matrix. Selected media i photo picker.

Wejście i stan początkowy. Permission matrix w tym miejscu oznacza dokładnie: Obrazy, filmy i metadane lokalizacji mają różne ścieżki uprawnień i ekspozycji. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 67
## layout
bullet
## slide title
Permission matrix — Jak pęka
## bullets
- Warunek powodzenia: Obrazy, filmy i metadane lokalizacji mają różne ścieżki uprawnień i ekspozycji.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 67. Permission matrix. Selected media i photo picker.

Warunek powodzenia ataku. Permission matrix w tym miejscu oznacza dokładnie: Obrazy, filmy i metadane lokalizacji mają różne ścieżki uprawnień i ekspozycji. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 68
## layout
bullet
## slide title
Permission matrix — Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 68. Permission matrix. Selected media i photo picker.

Reguła i miejsce egzekwowania. Permission matrix w tym miejscu oznacza dokładnie: Obrazy, filmy i metadane lokalizacji mają różne ścieżki uprawnień i ekspozycji. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 69
## layout
definition
## slide title
Latest selection only — Co to jest
## term
Latest selection only
## definition
Latest-selection query zwraca tylko najbardziej aktualny wybrany zestaw URI.
## teleprompter:
Slajd 69. Latest selection only. Selected media i photo picker.

Definicja i granica pojęcia. Latest selection only w tym miejscu oznacza dokładnie: Latest-selection query zwraca tylko najbardziej aktualny wybrany zestaw URI. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 70
## layout
bullet
## slide title
Latest selection only — Jak działa
## bullets
- Krok 1: Latest-selection query zwraca tylko najbardziej aktualny wybrany zestaw URI.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 70. Latest selection only. Selected media i photo picker.

Wejście i stan początkowy. Latest selection only w tym miejscu oznacza dokładnie: Latest-selection query zwraca tylko najbardziej aktualny wybrany zestaw URI. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 71
## layout
bullet
## slide title
Latest selection only — Jak pęka
## bullets
- Warunek powodzenia: Latest-selection query zwraca tylko najbardziej aktualny wybrany zestaw URI.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 71. Latest selection only. Selected media i photo picker.

Warunek powodzenia ataku. Latest selection only w tym miejscu oznacza dokładnie: Latest-selection query zwraca tylko najbardziej aktualny wybrany zestaw URI. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 72
## layout
bullet
## slide title
Latest selection only — Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 72. Latest selection only. Selected media i photo picker.

Reguła i miejsce egzekwowania. Latest selection only w tym miejscu oznacza dokładnie: Latest-selection query zwraca tylko najbardziej aktualny wybrany zestaw URI. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 73
## layout
definition
## slide title
Upgrade behavior — Co to jest
## term
Upgrade behavior
## definition
Upgrade behavior decyduje, czy wcześniej zainstalowana aplikacja zachowa dostęp, czy ma go przeliczyć od nowa.
## teleprompter:
Slajd 73. Upgrade behavior. Selected media i photo picker.

Definicja i granica pojęcia. Upgrade behavior w tym miejscu oznacza dokładnie: Upgrade behavior decyduje, czy wcześniej zainstalowana aplikacja zachowa dostęp, czy ma go przeliczyć od nowa. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 74
## layout
bullet
## slide title
Upgrade behavior — Jak działa
## bullets
- Krok 1: Upgrade behavior decyduje, czy wcześniej zainstalowana aplikacja zachowa dostęp, czy ma go przeliczyć od nowa.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 74. Upgrade behavior. Selected media i photo picker.

Wejście i stan początkowy. Upgrade behavior w tym miejscu oznacza dokładnie: Upgrade behavior decyduje, czy wcześniej zainstalowana aplikacja zachowa dostęp, czy ma go przeliczyć od nowa. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 75
## layout
bullet
## slide title
Upgrade behavior — Jak pęka
## bullets
- Warunek powodzenia: Upgrade behavior decyduje, czy wcześniej zainstalowana aplikacja zachowa dostęp, czy ma go przeliczyć od nowa.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 75. Upgrade behavior. Selected media i photo picker.

Warunek powodzenia ataku. Upgrade behavior w tym miejscu oznacza dokładnie: Upgrade behavior decyduje, czy wcześniej zainstalowana aplikacja zachowa dostęp, czy ma go przeliczyć od nowa. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 76
## layout
bullet
## slide title
Upgrade behavior — Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 76. Upgrade behavior. Selected media i photo picker.

Reguła i miejsce egzekwowania. Upgrade behavior w tym miejscu oznacza dokładnie: Upgrade behavior decyduje, czy wcześniej zainstalowana aplikacja zachowa dostęp, czy ma go przeliczyć od nowa. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 77
## layout
definition
## slide title
Photo picker contract — Co to jest
## term
Photo picker contract
## definition
Systemowy photo picker zwraca content URI bez proszenia o szeroki dostęp do storage.
## teleprompter:
Slajd 77. Photo picker contract. Selected media i photo picker.

Definicja i granica pojęcia. Photo picker contract w tym miejscu oznacza dokładnie: Systemowy photo picker zwraca content URI bez proszenia o szeroki dostęp do storage. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 78
## layout
bullet
## slide title
Photo picker contract — Jak działa
## bullets
- Krok 1: Systemowy photo picker zwraca content URI bez proszenia o szeroki dostęp do storage.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 78. Photo picker contract. Selected media i photo picker.

Wejście i stan początkowy. Photo picker contract w tym miejscu oznacza dokładnie: Systemowy photo picker zwraca content URI bez proszenia o szeroki dostęp do storage. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 79
## layout
bullet
## slide title
Photo picker contract — Jak pęka
## bullets
- Warunek powodzenia: Systemowy photo picker zwraca content URI bez proszenia o szeroki dostęp do storage.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 79. Photo picker contract. Selected media i photo picker.

Warunek powodzenia ataku. Photo picker contract w tym miejscu oznacza dokładnie: Systemowy photo picker zwraca content URI bez proszenia o szeroki dostęp do storage. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 80
## layout
bullet
## slide title
Photo picker contract — Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 80. Photo picker contract. Selected media i photo picker.

Reguła i miejsce egzekwowania. Photo picker contract w tym miejscu oznacza dokładnie: Systemowy photo picker zwraca content URI bez proszenia o szeroki dostęp do storage. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 81
## layout
definition
## slide title
Backport path — Co to jest
## term
Backport path
## definition
Jetpack potrafi zbackportować picker na starsze urządzenia przez jeden kontrakt API.
## teleprompter:
Slajd 81. Backport path. Selected media i photo picker.

Definicja i granica pojęcia. Backport path w tym miejscu oznacza dokładnie: Jetpack potrafi zbackportować picker na starsze urządzenia przez jeden kontrakt API. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 82
## layout
bullet
## slide title
Backport path — Jak działa
## bullets
- Krok 1: Jetpack potrafi zbackportować picker na starsze urządzenia przez jeden kontrakt API.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 82. Backport path. Selected media i photo picker.

Wejście i stan początkowy. Backport path w tym miejscu oznacza dokładnie: Jetpack potrafi zbackportować picker na starsze urządzenia przez jeden kontrakt API. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 83
## layout
bullet
## slide title
Backport path — Jak pęka
## bullets
- Warunek powodzenia: Jetpack potrafi zbackportować picker na starsze urządzenia przez jeden kontrakt API.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 83. Backport path. Selected media i photo picker.

Warunek powodzenia ataku. Backport path w tym miejscu oznacza dokładnie: Jetpack potrafi zbackportować picker na starsze urządzenia przez jeden kontrakt API. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 84
## layout
bullet
## slide title
Backport path — Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 84. Backport path. Selected media i photo picker.

Reguła i miejsce egzekwowania. Backport path w tym miejscu oznacza dokładnie: Jetpack potrafi zbackportować picker na starsze urządzenia przez jeden kontrakt API. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 85
## layout
definition
## slide title
Cloud media providers — Co to jest
## term
Cloud media providers
## definition
Cloud media providers pozwalają widzieć lokalne i zdalne biblioteki w jednym wyborze.
## teleprompter:
Slajd 85. Cloud media providers. Selected media i photo picker.

Definicja i granica pojęcia. Cloud media providers w tym miejscu oznacza dokładnie: Cloud media providers pozwalają widzieć lokalne i zdalne biblioteki w jednym wyborze. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 86
## layout
bullet
## slide title
Cloud media providers — Jak działa
## bullets
- Krok 1: Cloud media providers pozwalają widzieć lokalne i zdalne biblioteki w jednym wyborze.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 86. Cloud media providers. Selected media i photo picker.

Wejście i stan początkowy. Cloud media providers w tym miejscu oznacza dokładnie: Cloud media providers pozwalają widzieć lokalne i zdalne biblioteki w jednym wyborze. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 87
## layout
bullet
## slide title
Cloud media providers — Jak pęka
## bullets
- Warunek powodzenia: Cloud media providers pozwalają widzieć lokalne i zdalne biblioteki w jednym wyborze.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 87. Cloud media providers. Selected media i photo picker.

Warunek powodzenia ataku. Cloud media providers w tym miejscu oznacza dokładnie: Cloud media providers pozwalają widzieć lokalne i zdalne biblioteki w jednym wyborze. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 88
## layout
bullet
## slide title
Cloud media providers — Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 88. Cloud media providers. Selected media i photo picker.

Reguła i miejsce egzekwowania. Cloud media providers w tym miejscu oznacza dokładnie: Cloud media providers pozwalają widzieć lokalne i zdalne biblioteki w jednym wyborze. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 89
## layout
definition
## slide title
MediaStore version lockdown — Co to jest
## term
MediaStore version lockdown
## definition
MediaStore#getVersion() jest przycięty tak, by nie służył jako stabilny fingerprint aplikacji.
## teleprompter:
Slajd 89. MediaStore version lockdown. Selected media i photo picker.

Definicja i granica pojęcia. MediaStore version lockdown w tym miejscu oznacza dokładnie: MediaStore#getVersion() jest przycięty tak, by nie służył jako stabilny fingerprint aplikacji. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 90
## layout
bullet
## slide title
MediaStore version lockdown — Jak działa
## bullets
- Krok 1: MediaStore#getVersion() jest przycięty tak, by nie służył jako stabilny fingerprint aplikacji.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 90. MediaStore version lockdown. Selected media i photo picker.

Wejście i stan początkowy. MediaStore version lockdown w tym miejscu oznacza dokładnie: MediaStore#getVersion() jest przycięty tak, by nie służył jako stabilny fingerprint aplikacji. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 91
## layout
bullet
## slide title
MediaStore version lockdown — Jak pęka
## bullets
- Warunek powodzenia: MediaStore#getVersion() jest przycięty tak, by nie służył jako stabilny fingerprint aplikacji.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 91. MediaStore version lockdown. Selected media i photo picker.

Warunek powodzenia ataku. MediaStore version lockdown w tym miejscu oznacza dokładnie: MediaStore#getVersion() jest przycięty tak, by nie służył jako stabilny fingerprint aplikacji. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 92
## layout
bullet
## slide title
MediaStore version lockdown — Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 92. MediaStore version lockdown. Selected media i photo picker.

Reguła i miejsce egzekwowania. MediaStore version lockdown w tym miejscu oznacza dokładnie: MediaStore#getVersion() jest przycięty tak, by nie służył jako stabilny fingerprint aplikacji. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 93
## layout
definition
## slide title
Embedded photo picker — Co to jest
## term
Embedded photo picker
## definition
Embedded photo picker działa w SurfaceView przez setChildSurfacePackage i trzyma klienta w stanie resumed.
## teleprompter:
Slajd 93. Embedded photo picker. Selected media i photo picker.

Definicja i granica pojęcia. Embedded photo picker w tym miejscu oznacza dokładnie: Embedded photo picker działa w SurfaceView przez setChildSurfacePackage i trzyma klienta w stanie resumed. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 94
## layout
bullet
## slide title
Embedded photo picker — Jak działa
## bullets
- Krok 1: Embedded photo picker działa w SurfaceView przez setChildSurfacePackage i trzyma klienta w stanie resumed.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 94. Embedded photo picker. Selected media i photo picker.

Wejście i stan początkowy. Embedded photo picker w tym miejscu oznacza dokładnie: Embedded photo picker działa w SurfaceView przez setChildSurfacePackage i trzyma klienta w stanie resumed. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 95
## layout
bullet
## slide title
Embedded photo picker — Jak pęka
## bullets
- Warunek powodzenia: Embedded photo picker działa w SurfaceView przez setChildSurfacePackage i trzyma klienta w stanie resumed.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 95. Embedded photo picker. Selected media i photo picker.

Warunek powodzenia ataku. Embedded photo picker w tym miejscu oznacza dokładnie: Embedded photo picker działa w SurfaceView przez setChildSurfacePackage i trzyma klienta w stanie resumed. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 96
## layout
bullet
## slide title
Embedded photo picker — Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 96. Embedded photo picker. Selected media i photo picker.

Reguła i miejsce egzekwowania. Embedded photo picker w tym miejscu oznacza dokładnie: Embedded photo picker działa w SurfaceView przez setChildSurfacePackage i trzyma klienta w stanie resumed. Na tle tego bloku chodzi o: Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.
