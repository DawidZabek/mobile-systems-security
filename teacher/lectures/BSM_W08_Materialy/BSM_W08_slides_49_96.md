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
Zdjęcia i filmy są traktowane jako osobna klasa prywatnych danych.
Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI. Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem. Zdjęcia i filmy są traktowane jako osobna klasa prywatnych danych. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 50
## layout
bullet
## slide title
Media as data class
## subtitle
Jak działa
## bullets
- Media as data class: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Media as data class: Zdjęcia i filmy są osobną klasą danych a…
- Media as data class: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
## teleprompter:
Media as data class zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 51
## layout
bullet
## slide title
Media as data class
## subtitle
Jak pęka
## bullets
- Media as data class: Breach pojawia się wtedy gdy aplikacja trzyma stare…
- Media as data class: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Media as data class: Zdjęcia i filmy są osobną klasą danych a…
## teleprompter:
Media as data class przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 52
## layout
bullet
## slide title
Media as data class
## subtitle
Jak się bronić
## bullets
- Media as data class: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
- Media as data class: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Media as data class: Breach pojawia się wtedy gdy aplikacja trzyma stare…
## teleprompter:
Media as data class wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Android 14 może dać dostęp tylko do zdjęć i filmów wybranych przez użytkownika.
Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI. Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem. Android 14 może dać dostęp tylko do zdjęć i filmów wybranych przez użytkownika. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 54
## layout
bullet
## slide title
Selected Photos Access
## subtitle
Jak działa
## bullets
- Selected Photos Access: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Selected Photos Access: Zdjęcia i filmy są osobną klasą danych a…
- Selected Photos Access: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
## teleprompter:
Selected Photos Access zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 55
## layout
bullet
## slide title
Selected Photos Access
## subtitle
Jak pęka
## bullets
- Selected Photos Access: Breach pojawia się wtedy gdy aplikacja trzyma stare…
- Selected Photos Access: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Selected Photos Access: Zdjęcia i filmy są osobną klasą danych a…
## teleprompter:
Selected Photos Access przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 56
## layout
bullet
## slide title
Selected Photos Access
## subtitle
Jak się bronić
## bullets
- Selected Photos Access: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
- Selected Photos Access: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Selected Photos Access: Breach pojawia się wtedy gdy aplikacja trzyma stare…
## teleprompter:
Selected Photos Access wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
READ_MEDIA_VISUAL_USER_SELECTED oznacza partial access do wybranych mediów wizualnych.
Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI. Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem. READ_MEDIA_VISUAL_USER_SELECTED oznacza partial access do wybranych mediów wizualnych. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 58
## layout
bullet
## slide title
READ_MEDIA_VISUAL_USER_SELECTED
## subtitle
Jak działa
## bullets
- READ_MEDIA_VISUAL_USER_SELECTED: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- READ_MEDIA_VISUAL_USER_SELECTED: Zdjęcia i filmy są osobną klasą danych a…
- READ_MEDIA_VISUAL_USER_SELECTED: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
## teleprompter:
READ_MEDIA_VISUAL_USER_SELECTED zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 59
## layout
bullet
## slide title
READ_MEDIA_VISUAL_USER_SELECTED
## subtitle
Jak pęka
## bullets
- READ_MEDIA_VISUAL_USER_SELECTED: Breach pojawia się wtedy gdy aplikacja trzyma stare…
- READ_MEDIA_VISUAL_USER_SELECTED: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- READ_MEDIA_VISUAL_USER_SELECTED: Zdjęcia i filmy są osobną klasą danych a…
## teleprompter:
READ_MEDIA_VISUAL_USER_SELECTED przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 60
## layout
bullet
## slide title
READ_MEDIA_VISUAL_USER_SELECTED
## subtitle
Jak się bronić
## bullets
- READ_MEDIA_VISUAL_USER_SELECTED: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
- READ_MEDIA_VISUAL_USER_SELECTED: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- READ_MEDIA_VISUAL_USER_SELECTED: Breach pojawia się wtedy gdy aplikacja trzyma stare…
## teleprompter:
READ_MEDIA_VISUAL_USER_SELECTED wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Legacy app może działać w trybie kompatybilności, w którym system chroni wybrany podzbiór mediów.
Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI. Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem. Legacy app może działać w trybie kompatybilności, w którym system chroni wybrany podzbiór mediów. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 62
## layout
bullet
## slide title
Compatibility mode
## subtitle
Jak działa
## bullets
- Compatibility mode: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Compatibility mode: Zdjęcia i filmy są osobną klasą danych a…
- Compatibility mode: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
## teleprompter:
Compatibility mode zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 63
## layout
bullet
## slide title
Compatibility mode
## subtitle
Jak pęka
## bullets
- Compatibility mode: Breach pojawia się wtedy gdy aplikacja trzyma stare…
- Compatibility mode: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Compatibility mode: Zdjęcia i filmy są osobną klasą danych a…
## teleprompter:
Compatibility mode przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 64
## layout
bullet
## slide title
Compatibility mode
## subtitle
Jak się bronić
## bullets
- Compatibility mode: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
- Compatibility mode: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Compatibility mode: Breach pojawia się wtedy gdy aplikacja trzyma stare…
## teleprompter:
Compatibility mode wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Obrazy, filmy i metadane lokalizacji mają różne ścieżki uprawnień i ekspozycji.
Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI. Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem. Obrazy, filmy i metadane lokalizacji mają różne ścieżki uprawnień i ekspozycji. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 66
## layout
bullet
## slide title
Permission matrix
## subtitle
Jak działa
## bullets
- Permission matrix: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Permission matrix: Zdjęcia i filmy są osobną klasą danych a…
- Permission matrix: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
## teleprompter:
Permission matrix zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 67
## layout
bullet
## slide title
Permission matrix
## subtitle
Jak pęka
## bullets
- Permission matrix: Breach pojawia się wtedy gdy aplikacja trzyma stare…
- Permission matrix: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Permission matrix: Zdjęcia i filmy są osobną klasą danych a…
## teleprompter:
Permission matrix przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 68
## layout
bullet
## slide title
Permission matrix
## subtitle
Jak się bronić
## bullets
- Permission matrix: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
- Permission matrix: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Permission matrix: Breach pojawia się wtedy gdy aplikacja trzyma stare…
## teleprompter:
Permission matrix wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Latest-selection query zwraca tylko najbardziej aktualny wybrany zestaw URI.
Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI. Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem. Latest-selection query zwraca tylko najbardziej aktualny wybrany zestaw URI. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 70
## layout
bullet
## slide title
Latest selection only
## subtitle
Jak działa
## bullets
- Latest selection only: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Latest selection only: Zdjęcia i filmy są osobną klasą danych a…
- Latest selection only: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
## teleprompter:
Latest selection only zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 71
## layout
bullet
## slide title
Latest selection only
## subtitle
Jak pęka
## bullets
- Latest selection only: Breach pojawia się wtedy gdy aplikacja trzyma stare…
- Latest selection only: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Latest selection only: Zdjęcia i filmy są osobną klasą danych a…
## teleprompter:
Latest selection only przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 72
## layout
bullet
## slide title
Latest selection only
## subtitle
Jak się bronić
## bullets
- Latest selection only: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
- Latest selection only: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Latest selection only: Breach pojawia się wtedy gdy aplikacja trzyma stare…
## teleprompter:
Latest selection only wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Upgrade behavior decyduje, czy wcześniej zainstalowana aplikacja zachowa dostęp, czy ma go przeliczyć od nowa.
Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI. Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem. Upgrade behavior decyduje, czy wcześniej zainstalowana aplikacja zachowa dostęp, czy ma go przeliczyć od nowa. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 74
## layout
bullet
## slide title
Upgrade behavior
## subtitle
Jak działa
## bullets
- Upgrade behavior: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Upgrade behavior: Zdjęcia i filmy są osobną klasą danych a…
- Upgrade behavior: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
## teleprompter:
Upgrade behavior zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 75
## layout
bullet
## slide title
Upgrade behavior
## subtitle
Jak pęka
## bullets
- Upgrade behavior: Breach pojawia się wtedy gdy aplikacja trzyma stare…
- Upgrade behavior: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Upgrade behavior: Zdjęcia i filmy są osobną klasą danych a…
## teleprompter:
Upgrade behavior przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 76
## layout
bullet
## slide title
Upgrade behavior
## subtitle
Jak się bronić
## bullets
- Upgrade behavior: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
- Upgrade behavior: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Upgrade behavior: Breach pojawia się wtedy gdy aplikacja trzyma stare…
## teleprompter:
Upgrade behavior wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Systemowy photo picker zwraca content URI bez proszenia o szeroki dostęp do storage.
Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI. Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem. Systemowy photo picker zwraca content URI bez proszenia o szeroki dostęp do storage. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 78
## layout
bullet
## slide title
Photo picker contract
## subtitle
Jak działa
## bullets
- Photo picker contract: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Photo picker contract: Zdjęcia i filmy są osobną klasą danych a…
- Photo picker contract: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
## teleprompter:
Photo picker contract zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 79
## layout
bullet
## slide title
Photo picker contract
## subtitle
Jak pęka
## bullets
- Photo picker contract: Breach pojawia się wtedy gdy aplikacja trzyma stare…
- Photo picker contract: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Photo picker contract: Zdjęcia i filmy są osobną klasą danych a…
## teleprompter:
Photo picker contract przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 80
## layout
bullet
## slide title
Photo picker contract
## subtitle
Jak się bronić
## bullets
- Photo picker contract: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
- Photo picker contract: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Photo picker contract: Breach pojawia się wtedy gdy aplikacja trzyma stare…
## teleprompter:
Photo picker contract wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Jetpack potrafi zbackportować picker na starsze urządzenia przez jeden kontrakt API.
Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI. Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem. Jetpack potrafi zbackportować picker na starsze urządzenia przez jeden kontrakt API. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 82
## layout
bullet
## slide title
Backport path
## subtitle
Jak działa
## bullets
- Backport path: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Backport path: Zdjęcia i filmy są osobną klasą danych a…
- Backport path: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
## teleprompter:
Backport path zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 83
## layout
bullet
## slide title
Backport path
## subtitle
Jak pęka
## bullets
- Backport path: Breach pojawia się wtedy gdy aplikacja trzyma stare…
- Backport path: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Backport path: Zdjęcia i filmy są osobną klasą danych a…
## teleprompter:
Backport path przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 84
## layout
bullet
## slide title
Backport path
## subtitle
Jak się bronić
## bullets
- Backport path: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
- Backport path: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Backport path: Breach pojawia się wtedy gdy aplikacja trzyma stare…
## teleprompter:
Backport path wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Cloud media providers pozwalają widzieć lokalne i zdalne biblioteki w jednym wyborze.
Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI. Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem. Cloud media providers pozwalają widzieć lokalne i zdalne biblioteki w jednym wyborze. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 86
## layout
bullet
## slide title
Cloud media providers
## subtitle
Jak działa
## bullets
- Cloud media providers: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Cloud media providers: Zdjęcia i filmy są osobną klasą danych a…
- Cloud media providers: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
## teleprompter:
Cloud media providers zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 87
## layout
bullet
## slide title
Cloud media providers
## subtitle
Jak pęka
## bullets
- Cloud media providers: Breach pojawia się wtedy gdy aplikacja trzyma stare…
- Cloud media providers: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Cloud media providers: Zdjęcia i filmy są osobną klasą danych a…
## teleprompter:
Cloud media providers przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 88
## layout
bullet
## slide title
Cloud media providers
## subtitle
Jak się bronić
## bullets
- Cloud media providers: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
- Cloud media providers: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Cloud media providers: Breach pojawia się wtedy gdy aplikacja trzyma stare…
## teleprompter:
Cloud media providers wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
MediaStore#getVersion() jest przycięty tak, by nie służył jako stabilny fingerprint aplikacji.
Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI. Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem. MediaStore#getVersion() jest przycięty tak, by nie służył jako stabilny fingerprint aplikacji. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 90
## layout
bullet
## slide title
MediaStore version lockdown
## subtitle
Jak działa
## bullets
- MediaStore version lockdown: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- MediaStore version lockdown: Zdjęcia i filmy są osobną klasą danych a…
- MediaStore version lockdown: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
## teleprompter:
MediaStore version lockdown zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 91
## layout
bullet
## slide title
MediaStore version lockdown
## subtitle
Jak pęka
## bullets
- MediaStore version lockdown: Breach pojawia się wtedy gdy aplikacja trzyma stare…
- MediaStore version lockdown: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- MediaStore version lockdown: Zdjęcia i filmy są osobną klasą danych a…
## teleprompter:
MediaStore version lockdown przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 92
## layout
bullet
## slide title
MediaStore version lockdown
## subtitle
Jak się bronić
## bullets
- MediaStore version lockdown: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
- MediaStore version lockdown: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- MediaStore version lockdown: Breach pojawia się wtedy gdy aplikacja trzyma stare…
## teleprompter:
MediaStore version lockdown wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

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
Embedded photo picker działa w SurfaceView przez setChildSurfacePackage i trzyma klienta w stanie resumed.
Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI. Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage i trzyma klienta w stanie resumed. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 94
## layout
bullet
## slide title
Embedded photo picker
## subtitle
Jak działa
## bullets
- Embedded photo picker: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Embedded photo picker: Zdjęcia i filmy są osobną klasą danych a…
- Embedded photo picker: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
## teleprompter:
Embedded photo picker zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 95
## layout
bullet
## slide title
Embedded photo picker
## subtitle
Jak pęka
## bullets
- Embedded photo picker: Breach pojawia się wtedy gdy aplikacja trzyma stare…
- Embedded photo picker: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Embedded photo picker: Zdjęcia i filmy są osobną klasą danych a…
## teleprompter:
Embedded photo picker przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 96
## layout
bullet
## slide title
Embedded photo picker
## subtitle
Jak się bronić
## bullets
- Embedded photo picker: Obrona wymaga jawnego rozdzielenia permission matrix odświeżania stanu…
- Embedded photo picker: Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych…
- Embedded photo picker: Breach pojawia się wtedy gdy aplikacja trzyma stare…
## teleprompter:
Embedded photo picker wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.
