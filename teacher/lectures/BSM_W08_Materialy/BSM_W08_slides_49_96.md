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

Zdjęcia i filmy są traktowane jako osobna klasa prywatnych danych.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.

#slide 50
## layout
bullet
## slide title
Media as data class
## subtitle
Jak działa
## bullets
- Krok 1: Zdjęcia i filmy są traktowane jako osobna klasa prywatnych danych.
- Krok 2: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 50. Media as data class. Selected media i photo picker.

Przebieg Media as data class krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 51
## layout
bullet
## slide title
Media as data class
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Zdjęcia i filmy są traktowane jako osobna klasa prywatnych danych.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 51. Media as data class. Selected media i photo picker.

Media as data class przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 52
## layout
bullet
## slide title
Media as data class
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 52. Media as data class. Selected media i photo picker.

Obrona dla Media as data class wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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

Android 14 może dać dostęp tylko do zdjęć i filmów wybranych przez użytkownika.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.

#slide 54
## layout
bullet
## slide title
Selected Photos Access
## subtitle
Jak działa
## bullets
- Krok 1: Android 14 może dać dostęp tylko do zdjęć i filmów wybranych przez użytkownika.
- Krok 2: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 54. Selected Photos Access. Selected media i photo picker.

Przebieg Selected Photos Access krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 55
## layout
bullet
## slide title
Selected Photos Access
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Android 14 może dać dostęp tylko do zdjęć i filmów wybranych przez użytkownika.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 55. Selected Photos Access. Selected media i photo picker.

Selected Photos Access przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 56
## layout
bullet
## slide title
Selected Photos Access
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 56. Selected Photos Access. Selected media i photo picker.

Obrona dla Selected Photos Access wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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

READ_MEDIA_VISUAL_USER_SELECTED oznacza partial access do wybranych mediów wizualnych.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.

#slide 58
## layout
bullet
## slide title
READ_MEDIA_VISUAL_USER_SELECTED
## subtitle
Jak działa
## bullets
- Krok 1: READ_MEDIA_VISUAL_USER_SELECTED oznacza partial access do wybranych mediów wizualnych.
- Krok 2: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 58. READ_MEDIA_VISUAL_USER_SELECTED. Selected media i photo picker.

Przebieg READ_MEDIA_VISUAL_USER_SELECTED krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 59
## layout
bullet
## slide title
READ_MEDIA_VISUAL_USER_SELECTED
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: READ_MEDIA_VISUAL_USER_SELECTED oznacza partial access do wybranych mediów wizualnych.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 59. READ_MEDIA_VISUAL_USER_SELECTED. Selected media i photo picker.

READ_MEDIA_VISUAL_USER_SELECTED przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 60
## layout
bullet
## slide title
READ_MEDIA_VISUAL_USER_SELECTED
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 60. READ_MEDIA_VISUAL_USER_SELECTED. Selected media i photo picker.

Obrona dla READ_MEDIA_VISUAL_USER_SELECTED wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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

Legacy app może działać w trybie kompatybilności, w którym system chroni wybrany podzbiór mediów.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.

#slide 62
## layout
bullet
## slide title
Compatibility mode
## subtitle
Jak działa
## bullets
- Krok 1: Legacy app może działać w trybie kompatybilności, w którym system chroni wybrany podzbiór mediów.
- Krok 2: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 62. Compatibility mode. Selected media i photo picker.

Przebieg Compatibility mode krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 63
## layout
bullet
## slide title
Compatibility mode
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Legacy app może działać w trybie kompatybilności, w którym system chroni wybrany podzbiór mediów.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 63. Compatibility mode. Selected media i photo picker.

Compatibility mode przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 64
## layout
bullet
## slide title
Compatibility mode
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 64. Compatibility mode. Selected media i photo picker.

Obrona dla Compatibility mode wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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

Obrazy, filmy i metadane lokalizacji mają różne ścieżki uprawnień i ekspozycji.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.

#slide 66
## layout
bullet
## slide title
Permission matrix
## subtitle
Jak działa
## bullets
- Krok 1: Obrazy, filmy i metadane lokalizacji mają różne ścieżki uprawnień i ekspozycji.
- Krok 2: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 66. Permission matrix. Selected media i photo picker.

Przebieg Permission matrix krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 67
## layout
bullet
## slide title
Permission matrix
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Obrazy, filmy i metadane lokalizacji mają różne ścieżki uprawnień i ekspozycji.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 67. Permission matrix. Selected media i photo picker.

Permission matrix przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 68
## layout
bullet
## slide title
Permission matrix
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 68. Permission matrix. Selected media i photo picker.

Obrona dla Permission matrix wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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

Latest-selection query zwraca tylko najbardziej aktualny wybrany zestaw URI.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.

#slide 70
## layout
bullet
## slide title
Latest selection only
## subtitle
Jak działa
## bullets
- Krok 1: Latest-selection query zwraca tylko najbardziej aktualny wybrany zestaw URI.
- Krok 2: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 70. Latest selection only. Selected media i photo picker.

Przebieg Latest selection only krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 71
## layout
bullet
## slide title
Latest selection only
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Latest-selection query zwraca tylko najbardziej aktualny wybrany zestaw URI.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 71. Latest selection only. Selected media i photo picker.

Latest selection only przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 72
## layout
bullet
## slide title
Latest selection only
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 72. Latest selection only. Selected media i photo picker.

Obrona dla Latest selection only wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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

Upgrade behavior decyduje, czy wcześniej zainstalowana aplikacja zachowa dostęp, czy ma go przeliczyć od nowa.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.

#slide 74
## layout
bullet
## slide title
Upgrade behavior
## subtitle
Jak działa
## bullets
- Krok 1: Upgrade behavior decyduje, czy wcześniej zainstalowana aplikacja zachowa dostęp, czy ma go przeliczyć od nowa.
- Krok 2: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 74. Upgrade behavior. Selected media i photo picker.

Przebieg Upgrade behavior krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 75
## layout
bullet
## slide title
Upgrade behavior
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Upgrade behavior decyduje, czy wcześniej zainstalowana aplikacja zachowa dostęp, czy ma go przeliczyć od nowa.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 75. Upgrade behavior. Selected media i photo picker.

Upgrade behavior przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 76
## layout
bullet
## slide title
Upgrade behavior
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 76. Upgrade behavior. Selected media i photo picker.

Obrona dla Upgrade behavior wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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

Systemowy photo picker zwraca content URI bez proszenia o szeroki dostęp do storage.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.

#slide 78
## layout
bullet
## slide title
Photo picker contract
## subtitle
Jak działa
## bullets
- Krok 1: Systemowy photo picker zwraca content URI bez proszenia o szeroki dostęp do storage.
- Krok 2: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 78. Photo picker contract. Selected media i photo picker.

Przebieg Photo picker contract krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 79
## layout
bullet
## slide title
Photo picker contract
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Systemowy photo picker zwraca content URI bez proszenia o szeroki dostęp do storage.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 79. Photo picker contract. Selected media i photo picker.

Photo picker contract przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 80
## layout
bullet
## slide title
Photo picker contract
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 80. Photo picker contract. Selected media i photo picker.

Obrona dla Photo picker contract wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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

Jetpack potrafi zbackportować picker na starsze urządzenia przez jeden kontrakt API.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.

#slide 82
## layout
bullet
## slide title
Backport path
## subtitle
Jak działa
## bullets
- Krok 1: Jetpack potrafi zbackportować picker na starsze urządzenia przez jeden kontrakt API.
- Krok 2: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 82. Backport path. Selected media i photo picker.

Przebieg Backport path krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 83
## layout
bullet
## slide title
Backport path
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Jetpack potrafi zbackportować picker na starsze urządzenia przez jeden kontrakt API.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 83. Backport path. Selected media i photo picker.

Backport path przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 84
## layout
bullet
## slide title
Backport path
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 84. Backport path. Selected media i photo picker.

Obrona dla Backport path wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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

Cloud media providers pozwalają widzieć lokalne i zdalne biblioteki w jednym wyborze.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.

#slide 86
## layout
bullet
## slide title
Cloud media providers
## subtitle
Jak działa
## bullets
- Krok 1: Cloud media providers pozwalają widzieć lokalne i zdalne biblioteki w jednym wyborze.
- Krok 2: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 86. Cloud media providers. Selected media i photo picker.

Przebieg Cloud media providers krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 87
## layout
bullet
## slide title
Cloud media providers
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Cloud media providers pozwalają widzieć lokalne i zdalne biblioteki w jednym wyborze.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 87. Cloud media providers. Selected media i photo picker.

Cloud media providers przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 88
## layout
bullet
## slide title
Cloud media providers
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 88. Cloud media providers. Selected media i photo picker.

Obrona dla Cloud media providers wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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

MediaStore#getVersion() jest przycięty tak, by nie służył jako stabilny fingerprint aplikacji.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.

#slide 90
## layout
bullet
## slide title
MediaStore version lockdown
## subtitle
Jak działa
## bullets
- Krok 1: MediaStore#getVersion() jest przycięty tak, by nie służył jako stabilny fingerprint aplikacji.
- Krok 2: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 90. MediaStore version lockdown. Selected media i photo picker.

Przebieg MediaStore version lockdown krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 91
## layout
bullet
## slide title
MediaStore version lockdown
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: MediaStore#getVersion() jest przycięty tak, by nie służył jako stabilny fingerprint aplikacji.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 91. MediaStore version lockdown. Selected media i photo picker.

MediaStore version lockdown przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 92
## layout
bullet
## slide title
MediaStore version lockdown
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 92. MediaStore version lockdown. Selected media i photo picker.

Obrona dla MediaStore version lockdown wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.

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

Embedded photo picker działa w SurfaceView przez setChildSurfacePackage i trzyma klienta w stanie resumed.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.

#slide 94
## layout
bullet
## slide title
Embedded photo picker
## subtitle
Jak działa
## bullets
- Krok 1: Embedded photo picker działa w SurfaceView przez setChildSurfacePackage i trzyma klienta w stanie resumed.
- Krok 2: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
- Krok 3: decyzja systemu lub stan pośredni
- Krok 4: wynik i konsekwencja dla aplikacji
## teleprompter:
Slajd 94. Embedded photo picker. Selected media i photo picker.

Przebieg Embedded photo picker krok po kroku zaczyna się od stanu początkowego i kończy na konkretnym wyniku.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać jego pola, kolejność i to, który element decyduje o następnym kroku.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany.

#slide 95
## layout
bullet
## slide title
Embedded photo picker
## subtitle
Jak pęka
## bullets
- Warunek powodzenia: Embedded photo picker działa w SurfaceView przez setChildSurfacePackage i trzyma klienta w stanie resumed.
- Kontrola atakującego: Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
- Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom
- Skutek: wyciek, przejęcie, podmiana lub odmowa usługi
## teleprompter:
Slajd 95. Embedded photo picker. Selected media i photo picker.

Embedded photo picker przestaje być bezpieczny w momencie, gdy przeciwnik przejmuje kontrolę nad sygnałem albo danymi, które system uznaje za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi.

#slide 96
## layout
bullet
## slide title
Embedded photo picker
## subtitle
Jak się bronić
## bullets
- Reguła: Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
- Egzekwowanie: w manifeście, API, pickerze albo parserze
- Zakres: tylko to, co naprawdę potrzebne
- Test: przypadek zły odpada, przypadek dobry przechodzi
## teleprompter:
Slajd 96. Embedded photo picker. Selected media i photo picker.

Obrona dla Embedded photo picker wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne.
