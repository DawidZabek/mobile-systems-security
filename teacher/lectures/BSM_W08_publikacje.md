# W08 - publikacje i zrodla

Zakres: bezpieczenstwo aplikacji mobilnych i danych lokalnych.

## 1. Tryb kiosku / single-purpose device
1. Bernhard, Stocco, Halderman, "Implementing Attestable Kiosks" - PDF
   - lokalnie: `teacher/lectures/BSM_W08_Materialy/papers/kiosk.pdf`
   - co czytac: abstract, I. Introduction, II. Goals for a Kiosk Platform, III. Background and Related Work
2. Android Enterprise kiosk mode - WWW
   - https://developers.google.com/android/work/overview
   - co czytac: single-app kiosk, managed devices
3. Android lock task mode - WWW
   - https://developer.android.com/work/dpc/dedicated-devices/lock-task-mode
   - co czytac: overview, restrictions, exit paths

## 2. FileProvider
1. Android Developers, "Improperly Exposed Directories to FileProvider" - WWW
   - https://developer.android.com/privacy-and-security/risks/untrustworthy-contentprovider-provided-filename
   - co czytac: risk, impact, mitigations
2. AndroidX FileProvider reference - WWW
   - https://developer.android.com/reference/androidx/core/content/FileProvider
   - co czytac: `content://` URI, grant flags
3. Android secure file sharing guide - WWW
   - https://developer.android.com/training/secure-file-sharing
   - co czytac: secure sharing model and permissions

## 3. Uprawnienia do content URI
1. Android file sharing and URI grants - WWW
   - https://developer.android.com/training/secure-file-sharing/share-file
   - co czytac: URI grant flags and lifecycle
2. Android content providers overview - WWW
   - https://developer.android.com/guide/topics/providers/content-providers
   - co czytac: export, read/write permissions
3. OWASP MASTG - content URI testing - WWW
   - https://mas.owasp.org/MASTG/
   - co czytac: provider exposure and URI permissions

## 4. Storage Access Framework
1. Android documents/files guide - WWW
   - https://developer.android.com/training/data-storage/shared/documents-files
   - co czytac: `ACTION_OPEN_DOCUMENT`, `ACTION_CREATE_DOCUMENT`
2. Android document provider guide - WWW
   - https://developer.android.com/guide/topics/providers/document-provider
   - co czytac: persistable URI permissions
3. OWASP MASVS-STORAGE-1 - WWW
   - https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/
   - co czytac: storage at rest and reduced exposure

## 5. Ekspozycja na external storage
1. Android data storage overview - WWW
   - https://developer.android.com/training/data-storage
   - co czytac: internal vs external vs scoped storage
2. Android scoped storage changes - WWW
   - https://developer.android.com/about/versions/10/privacy/changes#scoped-storage
   - co czytac: migration and access restrictions
3. Android Dynamic Code Loading - WWW
   - https://developer.android.com/privacy-and-security/risks/dynamic-code-loading
   - co czytac: trusted storage and integrity checks

## 6. Wyciek przez notyfikacje
1. Patsakis, Alepis, "Knock-Knock: The unbearable lightness of Android Notifications" - PDF
   - lokalnie: `teacher/lectures/BSM_W08_Materialy/papers/notifications.pdf`
   - co czytac: abstract, I. Introduction, attacks, countermeasures
2. Android notifications docs - WWW
   - https://developer.android.com/develop/ui/views/notifications
   - co czytac: lock screen visibility, sensitive notifications
3. OWASP MASTG - disclosure via UI and notifications - WWW
   - https://mas.owasp.org/MASTG/
   - co czytac: UI disclosure paths, logging, notifications

## 7. Screen overlay
1. Android Developers, Tapjacking - WWW
   - https://developer.android.com/topic/security/risks/tapjacking
   - co czytac: overlay windows, mitigation APIs
2. Lim, "Android Tapjacking Vulnerability" - PDF
   - lokalnie: `teacher/lectures/BSM_W08_Materialy/papers/tapjacking.pdf`
   - co czytac: abstract, Introduction, payload selection, developing the application
3. TapTrap project artifacts - WWW
   - https://zenodo.org/records/16530431
   - co czytac: animation-based UI redressing concept

## 8. Tapjacking
1. Android Developers, Tapjacking - WWW
   - https://developer.android.com/topic/security/risks/tapjacking
   - co czytac: whole page, especially `filterTouchesWhenObscured`
2. Lim, "Android Tapjacking Vulnerability" - PDF
   - lokalnie: `teacher/lectures/BSM_W08_Materialy/papers/tapjacking.pdf`
   - co czytac: attack flow and mitigation
3. TapTrap project artifacts - WWW
   - https://zenodo.org/records/16530431
   - co czytac: attack mechanics and evaluation materials

## 9. Nadużycie accessibility
1. AccesiLeaks - PDF
   - lokalnie: `teacher/lectures/BSM_W08_Materialy/papers/accessibility-leaks.pdf`
   - co czytac: abstract, privacy leaks, eavesdropping, countermeasures
2. "On Malware Leveraging the Android Accessibility Framework" - PDF
   - https://eudl.eu/doi/10.4108/ue.1.4.e1
   - co czytac: malware capabilities and screen control
3. DVa: Android Accessibility Malware - paper page
   - https://papers.cool/venue/xu-haichuan%40usenixsecurity24%40USENIX
   - co czytac: victims and abuse vectors

## 10. Złośliwa klawiatura / IME
1. Android input method docs - WWW
   - https://developer.android.com/develop/ui/views/touch-and-input/creating-input-method
   - co czytac: IME lifecycle, responsibilities
2. Android `InputMethodManager` reference - WWW
   - https://developer.android.com/reference/android/view/inputmethod/InputMethodManager
   - co czytac: API surface and security implications
3. Android keylogging threat - PDF
   - https://eudl.eu/pdf/10.4108/icst.collaboratecom.2013.254209
   - co czytac: keyboard-as-malware idea, threat model, evaluation

## 11. Dynamiczne ładowanie kodu
1. Android Developers, Dynamic Code Loading - WWW
   - https://developer.android.com/privacy-and-security/risks/dynamic-code-loading
   - co czytac: overview, impact, mitigations
2. OWASP MASTG code loading guidance - WWW
   - https://mas.owasp.org/MASTG/
   - co czytac: code integrity and trusted sources
3. Android dynamic linker docs - WWW
   - https://developer.android.com/ndk/reference/group/libdl
   - co czytac: shared objects and loader behavior

## 12. Wykrywanie roota / stan urzadzenia
1. Bialon, "On Root Detection Strategies for Android Devices" - PDF
   - lokalnie: `teacher/lectures/BSM_W08_Materialy/papers/root-detection.pdf`
   - co czytac: abstract, III. Rooting Techniques, IV. Rooting Mitigation
2. "Can Root Detection Be Trusted? A Study of Bypass Techniques on Mobile Platforms" - PDF
   - https://www.sans.org/white-papers/can-root-detection-be-trusted-bypass-techniques-mobile-platforms
   - co czytac: bypass techniques, findings, limitations
3. "Android Rooting: An Arms Race between Evasion and Detection" - paper page
   - https://www.semanticscholar.org/paper/Android-Rooting%3A-An-Arms-Race-between-Evasion-and-Nguyen-Vu-Chau/d38ccc4e80bf78b435da3916b9ecd118561ac472
   - co czytac: detection vs evasion framing

## 13. Sygnały integralności urządzenia
1. Play Integrity overview - WWW
   - https://developer.android.com/google/play/integrity/overview
   - co czytac: verdicts, app/device integrity, device recall
2. Play Integrity standard request - WWW
   - https://developer.android.com/google/play/integrity/standard
   - co czytac: request flow and backend verification
3. Key attestation - WWW
   - https://developer.android.com/privacy-and-security/security-key-attestation
   - co czytac: attestation chain, hardware-backed keys

## 14. Minimalizacja danych
1. OWASP MASVS-STORAGE-1 - WWW
   - https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/
   - co czytac: data at rest, reduce exposure
2. Android privacy and security overview - WWW
   - https://developer.android.com/privacy-and-security
   - co czytac: minimize data collection and local exposure
3. NIST Privacy Framework - WWW
   - https://www.nist.gov/privacy-framework
   - co czytac: data minimization and lifecycle

## 15. Retencja danych i bezpieczne usuwanie
1. NIST Privacy Framework - WWW
   - https://www.nist.gov/privacy-framework
   - co czytac: retention and lifecycle management
2. OWASP MASTG - storage and deletion guidance - WWW
   - https://mas.owasp.org/MASTG/
   - co czytac: backups, caches, deletion
3. Android data storage guidance - WWW
   - https://developer.android.com/training/data-storage
   - co czytac: cache, external storage, cleanup

## Stan prac
- Pobranie PDF-ow rozpoczęte dla: kiosku, notyfikacji, tapjacking, accessibility, root detection.
- Następny krok: dopisać konkretne strony po wyciagnieciu tekstu z PDF i uzupełnić brakujące PDF-y dla tematów 9, 10 i 12.
