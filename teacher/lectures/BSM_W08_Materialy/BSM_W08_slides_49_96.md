#slide 49
## layout
definition
## slide title
Media as data class
## subtitle
Co to jest
## term
Media as data class
## definition
Zdjęcia i filmy są traktowane jako osobna klasa prywatnych danych.
## teleprompter:
Slajd 49. Media as data class. Selected media i photo picker.

Zdjęcia i filmy są traktowane jako osobna klasa prywatnych danych. To jest punkt startowy do zrozumienia, jak działa cały blok o selected media i photo picker.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 50
## layout
bullet
## slide title
Media as data class
## subtitle
Jak działa
## bullets
- Krok 1: Zdjęcia i filmy są traktowane jako osobna klasa prywatnych danych.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 50. Media as data class. Selected media i photo picker.

Najpierw rozpisz przebieg Media as data class krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 51
## layout
bullet
## slide title
Media as data class
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Zdjęcia i filmy są traktowane jako osobna klasa prywatnych danych.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 51. Media as data class. Selected media i photo picker.

Tu interesuje nas dokładnie moment, w którym Media as data class przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 52
## layout
bullet
## slide title
Media as data class
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 52. Media as data class. Selected media i photo picker.

Obrona dla Media as data class musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 53
## layout
definition
## slide title
Selected Photos Access
## subtitle
Co to jest
## term
Selected Photos Access
## definition
Android 14 może dać dostęp tylko do zdjęć i filmów wybranych przez użytkownika.
## teleprompter:
Slajd 53. Selected Photos Access. Selected media i photo picker.

Android 14 może dać dostęp tylko do zdjęć i filmów wybranych przez użytkownika. To jest punkt startowy do zrozumienia, jak działa cały blok o selected media i photo picker.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 54
## layout
bullet
## slide title
Selected Photos Access
## subtitle
Jak działa
## bullets
- Krok 1: Android 14 może dać dostęp tylko do zdjęć i filmów wybranych przez użytkownika.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 54. Selected Photos Access. Selected media i photo picker.

Najpierw rozpisz przebieg Selected Photos Access krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 55
## layout
bullet
## slide title
Selected Photos Access
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Android 14 może dać dostęp tylko do zdjęć i filmów wybranych przez użytkownika.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 55. Selected Photos Access. Selected media i photo picker.

Tu interesuje nas dokładnie moment, w którym Selected Photos Access przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 56
## layout
bullet
## slide title
Selected Photos Access
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 56. Selected Photos Access. Selected media i photo picker.

Obrona dla Selected Photos Access musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 57
## layout
definition
## slide title
READ_MEDIA_VISUAL_USER_SELECTED
## subtitle
Co to jest
## term
READ_MEDIA_VISUAL_USER_SELECTED
## definition
READ_MEDIA_VISUAL_USER_SELECTED oznacza partial access do wybranych mediów wizualnych.
## teleprompter:
Slajd 57. READ_MEDIA_VISUAL_USER_SELECTED. Selected media i photo picker.

READ_MEDIA_VISUAL_USER_SELECTED oznacza partial access do wybranych mediów wizualnych. To jest punkt startowy do zrozumienia, jak działa cały blok o selected media i photo picker.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 58
## layout
bullet
## slide title
READ_MEDIA_VISUAL_USER_SELECTED
## subtitle
Jak działa
## bullets
- Krok 1: READ_MEDIA_VISUAL_USER_SELECTED oznacza partial access do wybranych mediów wizualnych.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 58. READ_MEDIA_VISUAL_USER_SELECTED. Selected media i photo picker.

Najpierw rozpisz przebieg READ_MEDIA_VISUAL_USER_SELECTED krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 59
## layout
bullet
## slide title
READ_MEDIA_VISUAL_USER_SELECTED
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: READ_MEDIA_VISUAL_USER_SELECTED oznacza partial access do wybranych mediów wizualnych.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 59. READ_MEDIA_VISUAL_USER_SELECTED. Selected media i photo picker.

Tu interesuje nas dokładnie moment, w którym READ_MEDIA_VISUAL_USER_SELECTED przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 60
## layout
bullet
## slide title
READ_MEDIA_VISUAL_USER_SELECTED
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 60. READ_MEDIA_VISUAL_USER_SELECTED. Selected media i photo picker.

Obrona dla READ_MEDIA_VISUAL_USER_SELECTED musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 61
## layout
definition
## slide title
Compatibility mode
## subtitle
Co to jest
## term
Compatibility mode
## definition
Legacy app może działać w trybie kompatybilności, w którym system chroni wybrany podzbiór mediów.
## teleprompter:
Slajd 61. Compatibility mode. Selected media i photo picker.

Legacy app może działać w trybie kompatybilności, w którym system chroni wybrany podzbiór mediów. To jest punkt startowy do zrozumienia, jak działa cały blok o selected media i photo picker.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 62
## layout
bullet
## slide title
Compatibility mode
## subtitle
Jak działa
## bullets
- Krok 1: Legacy app może działać w trybie kompatybilności, w którym system chroni wybrany podzbiór mediów.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 62. Compatibility mode. Selected media i photo picker.

Najpierw rozpisz przebieg Compatibility mode krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 63
## layout
bullet
## slide title
Compatibility mode
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Legacy app może działać w trybie kompatybilności, w którym system chroni wybrany podzbiór mediów.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 63. Compatibility mode. Selected media i photo picker.

Tu interesuje nas dokładnie moment, w którym Compatibility mode przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 64
## layout
bullet
## slide title
Compatibility mode
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 64. Compatibility mode. Selected media i photo picker.

Obrona dla Compatibility mode musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 65
## layout
definition
## slide title
Permission matrix
## subtitle
Co to jest
## term
Permission matrix
## definition
Obrazy, filmy i metadane lokalizacji mają różne ścieżki uprawnień i ekspozycji.
## teleprompter:
Slajd 65. Permission matrix. Selected media i photo picker.

Obrazy, filmy i metadane lokalizacji mają różne ścieżki uprawnień i ekspozycji. To jest punkt startowy do zrozumienia, jak działa cały blok o selected media i photo picker.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 66
## layout
bullet
## slide title
Permission matrix
## subtitle
Jak działa
## bullets
- Krok 1: Obrazy, filmy i metadane lokalizacji mają różne ścieżki uprawnień i ekspozycji.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 66. Permission matrix. Selected media i photo picker.

Najpierw rozpisz przebieg Permission matrix krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 67
## layout
bullet
## slide title
Permission matrix
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Obrazy, filmy i metadane lokalizacji mają różne ścieżki uprawnień i ekspozycji.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 67. Permission matrix. Selected media i photo picker.

Tu interesuje nas dokładnie moment, w którym Permission matrix przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 68
## layout
bullet
## slide title
Permission matrix
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 68. Permission matrix. Selected media i photo picker.

Obrona dla Permission matrix musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 69
## layout
definition
## slide title
Latest selection only
## subtitle
Co to jest
## term
Latest selection only
## definition
Latest-selection query zwraca tylko najbardziej aktualny wybrany zestaw URI.
## teleprompter:
Slajd 69. Latest selection only. Selected media i photo picker.

Latest-selection query zwraca tylko najbardziej aktualny wybrany zestaw URI. To jest punkt startowy do zrozumienia, jak działa cały blok o selected media i photo picker.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 70
## layout
bullet
## slide title
Latest selection only
## subtitle
Jak działa
## bullets
- Krok 1: Latest-selection query zwraca tylko najbardziej aktualny wybrany zestaw URI.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 70. Latest selection only. Selected media i photo picker.

Najpierw rozpisz przebieg Latest selection only krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 71
## layout
bullet
## slide title
Latest selection only
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Latest-selection query zwraca tylko najbardziej aktualny wybrany zestaw URI.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 71. Latest selection only. Selected media i photo picker.

Tu interesuje nas dokładnie moment, w którym Latest selection only przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 72
## layout
bullet
## slide title
Latest selection only
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 72. Latest selection only. Selected media i photo picker.

Obrona dla Latest selection only musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 73
## layout
definition
## slide title
Upgrade behavior
## subtitle
Co to jest
## term
Upgrade behavior
## definition
Upgrade behavior decyduje, czy wcześniej zainstalowana aplikacja zachowa dostęp, czy ma go przeliczyć od nowa.
## teleprompter:
Slajd 73. Upgrade behavior. Selected media i photo picker.

Upgrade behavior decyduje, czy wcześniej zainstalowana aplikacja zachowa dostęp, czy ma go przeliczyć od nowa. To jest punkt startowy do zrozumienia, jak działa cały blok o selected media i photo picker.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 74
## layout
bullet
## slide title
Upgrade behavior
## subtitle
Jak działa
## bullets
- Krok 1: Upgrade behavior decyduje, czy wcześniej zainstalowana aplikacja zachowa dostęp, czy ma go przeliczyć od nowa.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 74. Upgrade behavior. Selected media i photo picker.

Najpierw rozpisz przebieg Upgrade behavior krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 75
## layout
bullet
## slide title
Upgrade behavior
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Upgrade behavior decyduje, czy wcześniej zainstalowana aplikacja zachowa dostęp, czy ma go przeliczyć od nowa.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 75. Upgrade behavior. Selected media i photo picker.

Tu interesuje nas dokładnie moment, w którym Upgrade behavior przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 76
## layout
bullet
## slide title
Upgrade behavior
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 76. Upgrade behavior. Selected media i photo picker.

Obrona dla Upgrade behavior musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 77
## layout
definition
## slide title
Photo picker contract
## subtitle
Co to jest
## term
Photo picker contract
## definition
Systemowy photo picker zwraca content URI bez proszenia o szeroki dostęp do storage.
## teleprompter:
Slajd 77. Photo picker contract. Selected media i photo picker.

Systemowy photo picker zwraca content URI bez proszenia o szeroki dostęp do storage. To jest punkt startowy do zrozumienia, jak działa cały blok o selected media i photo picker.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 78
## layout
bullet
## slide title
Photo picker contract
## subtitle
Jak działa
## bullets
- Krok 1: Systemowy photo picker zwraca content URI bez proszenia o szeroki dostęp do storage.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 78. Photo picker contract. Selected media i photo picker.

Najpierw rozpisz przebieg Photo picker contract krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 79
## layout
bullet
## slide title
Photo picker contract
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Systemowy photo picker zwraca content URI bez proszenia o szeroki dostęp do storage.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 79. Photo picker contract. Selected media i photo picker.

Tu interesuje nas dokładnie moment, w którym Photo picker contract przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 80
## layout
bullet
## slide title
Photo picker contract
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 80. Photo picker contract. Selected media i photo picker.

Obrona dla Photo picker contract musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 81
## layout
definition
## slide title
Backport path
## subtitle
Co to jest
## term
Backport path
## definition
Jetpack potrafi zbackportować picker na starsze urządzenia przez jeden kontrakt API.
## teleprompter:
Slajd 81. Backport path. Selected media i photo picker.

Jetpack potrafi zbackportować picker na starsze urządzenia przez jeden kontrakt API. To jest punkt startowy do zrozumienia, jak działa cały blok o selected media i photo picker.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 82
## layout
bullet
## slide title
Backport path
## subtitle
Jak działa
## bullets
- Krok 1: Jetpack potrafi zbackportować picker na starsze urządzenia przez jeden kontrakt API.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 82. Backport path. Selected media i photo picker.

Najpierw rozpisz przebieg Backport path krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 83
## layout
bullet
## slide title
Backport path
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Jetpack potrafi zbackportować picker na starsze urządzenia przez jeden kontrakt API.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 83. Backport path. Selected media i photo picker.

Tu interesuje nas dokładnie moment, w którym Backport path przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 84
## layout
bullet
## slide title
Backport path
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 84. Backport path. Selected media i photo picker.

Obrona dla Backport path musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 85
## layout
definition
## slide title
Cloud media providers
## subtitle
Co to jest
## term
Cloud media providers
## definition
Cloud media providers pozwalają widzieć lokalne i zdalne biblioteki w jednym wyborze.
## teleprompter:
Slajd 85. Cloud media providers. Selected media i photo picker.

Cloud media providers pozwalają widzieć lokalne i zdalne biblioteki w jednym wyborze. To jest punkt startowy do zrozumienia, jak działa cały blok o selected media i photo picker.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 86
## layout
bullet
## slide title
Cloud media providers
## subtitle
Jak działa
## bullets
- Krok 1: Cloud media providers pozwalają widzieć lokalne i zdalne biblioteki w jednym wyborze.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 86. Cloud media providers. Selected media i photo picker.

Najpierw rozpisz przebieg Cloud media providers krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 87
## layout
bullet
## slide title
Cloud media providers
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Cloud media providers pozwalają widzieć lokalne i zdalne biblioteki w jednym wyborze.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 87. Cloud media providers. Selected media i photo picker.

Tu interesuje nas dokładnie moment, w którym Cloud media providers przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 88
## layout
bullet
## slide title
Cloud media providers
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 88. Cloud media providers. Selected media i photo picker.

Obrona dla Cloud media providers musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 89
## layout
definition
## slide title
MediaStore version lockdown
## subtitle
Co to jest
## term
MediaStore version lockdown
## definition
MediaStore#getVersion() jest przycięty tak, by nie służył jako stabilny fingerprint aplikacji.
## teleprompter:
Slajd 89. MediaStore version lockdown. Selected media i photo picker.

MediaStore#getVersion() jest przycięty tak, by nie służył jako stabilny fingerprint aplikacji. To jest punkt startowy do zrozumienia, jak działa cały blok o selected media i photo picker.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 90
## layout
bullet
## slide title
MediaStore version lockdown
## subtitle
Jak działa
## bullets
- Krok 1: MediaStore#getVersion() jest przycięty tak, by nie służył jako stabilny fingerprint aplikacji.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 90. MediaStore version lockdown. Selected media i photo picker.

Najpierw rozpisz przebieg MediaStore version lockdown krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 91
## layout
bullet
## slide title
MediaStore version lockdown
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: MediaStore#getVersion() jest przycięty tak, by nie służył jako stabilny fingerprint aplikacji.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 91. MediaStore version lockdown. Selected media i photo picker.

Tu interesuje nas dokładnie moment, w którym MediaStore version lockdown przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 92
## layout
bullet
## slide title
MediaStore version lockdown
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 92. MediaStore version lockdown. Selected media i photo picker.

Obrona dla MediaStore version lockdown musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 93
## layout
definition
## slide title
Embedded photo picker
## subtitle
Co to jest
## term
Embedded photo picker
## definition
Embedded photo picker działa w SurfaceView przez setChildSurfacePackage i trzyma klienta w stanie resumed.
## teleprompter:
Slajd 93. Embedded photo picker. Selected media i photo picker.

Embedded photo picker działa w SurfaceView przez setChildSurfacePackage i trzyma klienta w stanie resumed. To jest punkt startowy do zrozumienia, jak działa cały blok o selected media i photo picker.

Dlaczego to nie jest tylko hasło. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Jakie miejsce ma w modelu zagrożeń. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Dlaczego ten mechanizm istnieje. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 94
## layout
bullet
## slide title
Embedded photo picker
## subtitle
Jak działa
## bullets
- Krok 1: Embedded photo picker działa w SurfaceView przez setChildSurfacePackage i trzyma klienta w stanie resumed.
- Krok 2: Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 94. Embedded photo picker. Selected media i photo picker.

Najpierw rozpisz przebieg Embedded photo picker krok po kroku. Zacznij od stanu początkowego i pokaż, co robi aplikacja, a co robi system.

Krok po kroku przez przepływ. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Decyzja systemu i stan pośredni. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Wynik oraz konsekwencja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 95
## layout
bullet
## slide title
Embedded photo picker
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Embedded photo picker działa w SurfaceView przez setChildSurfacePackage i trzyma klienta w stanie resumed.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 95. Embedded photo picker. Selected media i photo picker.

Tu interesuje nas dokładnie moment, w którym Embedded photo picker przestaje być bezpieczny. Skup się na tym, co kontroluje przeciwnik i jaki sygnał system błędnie uznaje za zaufany.

Co kontroluje atakujący. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Gdzie system ufa za dużo. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Skutek dla danych lub dostępu. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.

#slide 96
## layout
bullet
## slide title
Embedded photo picker
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 96. Embedded photo picker. Selected media i photo picker.

Obrona dla Embedded photo picker musi być praktyczna, nie deklaratywna. Pokaż, gdzie reguła jest egzekwowana i co musi się nie udać, żeby atak nie przeszedł.

Minimalny zakres dostępu. Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView. Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.

Wersja systemu i kompatybilność. Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne. Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.

Test i regresja. Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii. Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić.
