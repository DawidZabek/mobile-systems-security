# W08 - publikacje i zrodla

Zakres: bezpieczenstwo aplikacji mobilnych i danych lokalnych.

Cel tego pliku: dla kazdego pojęcia masz 3+ zrodla oraz konkretne miejsca do czytania. Dla PDF-ow podaje strony i co z nich brac, a nie ogolne "czytaj abstrakt".

## 1. Tryb kiosku / single-purpose device
1. Bernhard, Stocco, Halderman, "Implementing Attestable Kiosks" - PDF
   - lokalnie: `teacher/lectures/BSM_W08_Materialy/papers/kiosk.pdf`
   - strony: 1-2
   - szukac: definicji kiosku jako urzadzenia o ograniczonym przeznaczeniu, modelu zagrozen i roli attestation
   - brac do slajdow: czym kiosk jest w praktyce, dlaczego samo "lock task" nie wystarcza, jaka jest rola polityki i stanu urzadzenia
2. Android Enterprise - dedicated devices / kiosk mode - WWW
   - https://developers.google.com/android/work/overview
   - sekcje: dedicated devices, single-app kiosk, multi-app kiosk
   - brac do slajdow: jak polityka MDM ogranicza powierzchnie ataku
3. Android lock task mode - WWW
   - https://developer.android.com/work/dpc/dedicated-devices/lock-task-mode
   - sekcje: overview, restrictions, exit paths
   - brac do slajdow: co jest blokowane, a co nadal pozostaje atakiem

## 2. FileProvider
1. AndroidX FileProvider reference - WWW
   - https://developer.android.com/reference/androidx/core/content/FileProvider
   - sekcje: overview, defining a FileProvider, granting temporary permissions
   - brac do slajdow: `content://` zamiast `file://`, tymczasowe uprawnienia i ograniczenie ekspozycji katalogow
2. Android secure file sharing guide - WWW
   - https://developer.android.com/training/secure-file-sharing
   - sekcje: setting up file sharing, sharing files securely with URIs
   - brac do slajdow: dlaczego `FileProvider` jest bezpieczniejszy niz jawne udostepnianie sciezki
3. Improperly Exposed Directories to FileProvider - WWW
   - https://developer.android.com/privacy-and-security/risks/untrustworthy-contentprovider-provided-filename
   - sekcje: risk, impact, mitigations
   - brac do slajdow: typowy blad konfiguracji i skutki zlego `paths`

## 3. Uprawnienia do content URI
1. Content provider basics - WWW
   - https://developer.android.com/guide/topics/providers/content-provider-basics
   - sekcje: URI permissions, grantUriPermissions, grant flags
   - brac do slajdow: uprawnienia dzialaja dla URI, nie dla calego providera
2. `<grant-uri-permission>` - WWW
   - https://developer.android.com/guide/topics/manifest/grant-uri-permission-element
   - sekcje: path, grantUriPermissions
   - brac do slajdow: jak zawęzac dostep po sciezce
3. Create a content provider - WWW
   - https://developer.android.com/guide/topics/providers/content-provider-creating
   - sekcje: temporary permissions, intent flags
   - brac do slajdow: kiedy i jak przyznaje sie dostep przy przekazywaniu URI do innej aplikacji

## 4. Storage Access Framework
1. Android document provider guide - WWW
   - https://developer.android.com/guide/topics/providers/document-provider
   - sekcje: overview, document provider, persistable URI permissions
   - brac do slajdow: SAF jako kontrolowany kanal dostepu do plikow i dokumentow
2. Open files using the Storage Access Framework - WWW
   - https://developer.android.com/guide/topics/providers/document-provider?hl=pl
   - sekcje: wstep, what SAF includes, `DocumentsProvider`
   - brac do slajdow: rola dostawcy dokumentow i standardowego UI wyboru pliku
3. OWASP MASVS-STORAGE-1 - WWW
   - https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/
   - sekcje: storage at rest, reduce exposure
   - brac do slajdow: SAF jako sposob ograniczania kopiowania danych i ich niekontrolowanego eksportu

## 5. Ekspozycja na external storage
1. Data and file storage overview - WWW
   - https://developer.android.com/training/data-storage
   - sekcje: internal storage, external storage, scoped storage
   - brac do slajdow: roznica miedzy storage prywatnym a wspoldzielonym
2. Security checklist - WWW
   - https://developer.android.com/guide/practices/security
   - sekcje: security with dynamically loaded code, insecure storage locations
   - brac do slajdow: dlaczego world-writable/external storage to ryzyko i jak to wspiera injection
3. Dynamic Code Loading - WWW
   - https://developer.android.com/privacy-and-security/risks/dynamic-code-loading
   - sekcje: mitigations, trusted sources, integrity checks
   - brac do slajdow: kod z external storage jako szczegolny wariant ryzyka

## 6. Wyciek przez notyfikacje
1. Patsakis, Alepis, "Knock-Knock: The unbearable lightness of Android Notifications" - PDF
   - lokalnie: `teacher/lectures/BSM_W08_Materialy/papers/notifications.pdf`
   - strony: 1-2
   - szukac: opisu ataku, forged notifications, DoS i manipulacji uwaga uzytkownika
   - brac do slajdow: jak notyfikacje staja sie interfejsem ataku, a nie tylko UI
2. Android notifications docs - WWW
   - https://developer.android.com/develop/ui/views/notifications
   - sekcje: lock screen visibility, sensitive notifications, notification channels
   - brac do slajdow: jak ograniczac widocznosc tresci i metadanych
3. OWASP MASTG - UI disclosure paths - WWW
   - https://mas.owasp.org/MASTG/
   - sekcje: logging, notifications, sensitive data exposure
   - brac do slajdow: notyfikacje jako jeden z kanalow wycieku danych lokalnych

## 7. Screen overlay
1. Android tapjacking / overlay protections - WWW
   - https://developer.android.com/topic/security/risks/tapjacking
   - sekcje: overlay windows, mitigation APIs
   - brac do slajdow: kiedy overlay jest problemem i jak platforma go ogranicza
2. Android window overlay / obscured touches - WWW
   - https://developer.android.com/reference/android/view/View
   - sekcje: `filterTouchesWhenObscured`, obscured touch handling
   - brac do slajdow: mechanizm odrzucania dotykow spod zaslony
3. Lim, "Android Tapjacking Vulnerability" - PDF
   - lokalnie: `teacher/lectures/BSM_W08_Materialy/papers/tapjacking.pdf`
   - strony: 1-2
   - szukac: definicji ataku i roli foreground layer bez mozliwosci klikniecia

## 8. Tapjacking
1. Lim, "Android Tapjacking Vulnerability" - PDF
   - lokalnie: `teacher/lectures/BSM_W08_Materialy/papers/tapjacking.pdf`
   - strony: 1-4
   - szukac: payload selection, flow instalacji aplikacji, ograniczenia aspektu ekranu
   - brac do slajdow: konkretne kroki ataku, nie tylko definicje
2. Android tapjacking / overlay protections - WWW
   - https://developer.android.com/topic/security/risks/tapjacking
   - sekcje: `filterTouchesWhenObscured`, detection of obscured touches
   - brac do slajdow: jedyna sensowna linia obrony w frameworku
3. TapTrap project artifacts - WWW
   - https://zenodo.org/records/16530431
   - sekcje: attack mechanics, evaluation materials
   - brac do slajdow: rozszerzenie problemu na animacje i redressing

## 9. Naduzycie accessibility
1. Xu et al., "AccessiLeaks: Investigating Privacy Leaks Exposed by the Android Accessibility Service" - PDF
   - zrodlo: https://publications.cispa.saarland/2804/
   - strony: wstep + wyniki z pierwszej polowy artykulu
   - szukac: skali wyciekow, eavesdropping na loginy i hasla, danych finansowych
   - brac do slajdow: po co accessibility jest atrakcyjne dla atakujacego
2. "On Malware Leveraging the Android Accessibility Framework" - PDF
   - https://eudl.eu/doi/10.4108/ue.1.4.e1
   - strony: abstract, introduction, attack description, conclusion
   - szukac: przejecia kontroli nad ekranem, kradziezy credentiali i kontrole interfejsu
3. DVa: Extracting Victims and Abuse Vectors from Android Accessibility Malware - PDF
   - https://www.usenix.org/system/files/sec24summer-prepub-136-xu-haichuan.pdf
   - strony: wstep, abuse vectors, evaluation
   - szukac: kto jest celem, jakie wektory naduzyc sa dominujace

## 10. Zlosliwa klawiatura / IME
1. Wang, Lagesse, "KeyGuard: Using Selective Encryption to Mitigate Keylogging in Third-Party IME" - PDF
   - lokalnie: `teacher/lectures/BSM_W08_Materialy/papers/keyguard.pdf`
   - strony: 1-3
   - szukac: threat model, why third-party IME can log sensitive input, selective encryption idea
   - brac do slajdow: jak IME widzi wszystko i czemu to problem
2. Android input method docs - WWW
   - https://developer.android.com/develop/ui/views/touch-and-input/creating-input-method
   - sekcje: IME lifecycle, responsibilities, security implications
   - brac do slajdow: gdzie IME siedzi w architekturze inputu
3. Android `InputMethodManager` reference - WWW
   - https://developer.android.com/reference/android/view/inputmethod/InputMethodManager
   - sekcje: API surface, text input connection
   - brac do slajdow: w ktorym miejscu aplikacja przekazuje tekst do warstwy wejscia

## 11. Dynamiczne ladowanie kodu
1. Qu et al., "DYDROID: Measuring Dynamic Code Loading and Its Security Implications in Android Applications" - PDF
   - lokalnie: `teacher/lectures/BSM_W08_Materialy/papers/dydroid.pdf`
   - strony: 1-6
   - szukac: pytan badawczych, provenance, remote vs local code, code injection, privacy tracking
   - brac do slajdow: dlaczego DCL jest zarazem technika hardeningu i wektorem ataku
2. Android Dynamic Code Loading - WWW
   - https://developer.android.com/privacy-and-security/risks/dynamic-code-loading
   - sekcje: overview, impact, mitigations
   - brac do slajdow: dlaczego kod spoza APK jest zlym pomyslem
3. Security checklist - WWW
   - https://developer.android.com/guide/practices/security
   - sekcje: security with dynamically loaded code
   - brac do slajdow: lokalne/scoped storage, integrity checks, zakaz dynamicznego kodu bez potrzeby

## 12. Wykrywanie roota / stan urzadzenia
1. Bialon, "On Root Detection Strategies for Android Devices" - PDF
   - lokalnie: `teacher/lectures/BSM_W08_Materialy/papers/root-detection.pdf`
   - strony: 1-4
   - szukac: po co wykrywa sie roota, jakie metody wykrywania sa testowane, jakie sa ograniczenia
   - brac do slajdow: root jako sygnal, nie absolutny dowod
2. Android security tips / checklist - WWW
   - https://developer.android.com/privacy-and-security/security-tips
   - sekcje: device integrity, insecure environments, rooted devices
   - brac do slajdow: jakie sygnaly bezpieczenstwa ma aplikacja zanim wykona akcje wraziwe
3. Play Integrity overview - WWW
   - https://developer.android.com/google/play/integrity/overview
   - sekcje: integrity verdicts, tampered apps, trusted devices
   - brac do slajdow: roota nie sprawdza sie jednym if-em, tylko laczy z backendem i verdictem

## 13. Sygnały integralności urzadzenia
1. Play Integrity overview - WWW
   - https://developer.android.com/google/play/integrity/overview
   - sekcje: device integrity, app integrity, requestHash / nonce
   - brac do slajdow: jakie klasy sygnalow daje API i kiedy je pobierac
2. Play Integrity standard requests - WWW
   - https://developer.android.com/google/play/integrity/standard
   - sekcje: request flow, standard vs classic, backend verification
   - brac do slajdow: jak wyslac zapytanie, zeby bylo trudne do podrobienia
3. Key attestation - WWW
   - https://developer.android.com/privacy-and-security/security-key-attestation
   - sekcje: attestation chain, hardware-backed keys
   - brac do slajdow: gdzie konczy sie sygnal urzadzenia, a zaczyna wiarygodna atestacja klucza

## 14. Minimalizacja danych
1. NIST Privacy Framework - WWW
   - https://www.nist.gov/privacy-framework
   - sekcje: identify-p, govern-p, data processing considerations
   - brac do slajdow: data minimization jako zasada projektowa, nie dodatek
2. Android privacy and security overview - WWW
   - https://developer.android.com/privacy-and-security
   - sekcje: minimize collection, local exposure, user control
   - brac do slajdow: minimalizuj co zbierasz, gdzie to trzymasz i komu to pokazujesz
3. OWASP MASVS-STORAGE-1 - WWW
   - https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/
   - sekcje: data at rest, exposure reduction
   - brac do slajdow: jak minimalizacja wyglada w praktyce dla danych lokalnych

## 15. Retencja danych i bezpieczne usuwanie
1. Reardon, Marforio, Capkun, Basin, "Secure Deletion on Log-structured File Systems" - PDF
   - lokalnie: `teacher/lectures/BSM_W08_Materialy/papers/secure-deletion.pdf`
   - strony: 1-4
   - szukac: 44 godziny pozostawania danych, why overwrite/encryption fail on log-structured FS, trzy mechanizmy secure deletion
   - brac do slajdow: sedno problemu retencji na telefonach
2. NIST Privacy Framework - WWW
   - https://www.nist.gov/privacy-framework
   - sekcje: data lifecycle, retention, disposal
   - brac do slajdow: retencja to polityka, a nie jednorazowe kasowanie
3. OWASP MASTG - storage and deletion guidance - WWW
   - https://mas.owasp.org/MASTG/
   - sekcje: backups, caches, deletion, persistence
   - brac do slajdow: gdzie dane nadal pozostaja po "usunieciu" w UI

## Stan prac
- Plik jest juz ograniczony do W08.
- Lokalnie sa PDF-y dla: kiosku, notyfikacji, tapjacking, accessibility, IME, dynamicznego ladowania kodu, roota i secure deletion.
- Najwazniejsze nastepne ulepszenie: dopisac strony po sprawdzeniu calych PDF-ow i ewentualnie podmienic slabe/nieczytelne zrodlo accessibility na lepszy PDF, jesli bedzie potrzebne.
