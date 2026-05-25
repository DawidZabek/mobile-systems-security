# W08 - publikacje i zrodla

Zakres: bezpieczenstwo aplikacji mobilnych i danych lokalnych.
Cel: zebrac materialy, ktore nie dubluja W03/W04/W05/W07/W09.

Format:
- `WWW` = oficjalna dokumentacja lub standard online
- `PDF` = bezposredni PDF do pobrania
- `co czytac` = fragmenty najbardziej przydatne do budowy slajdow

## 1. Tryb kiosku / single-purpose device
1. Android Enterprise, kiosk mode - `WWW`
   - https://developers.google.com/android/work/overview
   - co czytac: sekcje o single-app kiosk i managed devices
2. Android lock task mode - `WWW`
   - https://developer.android.com/work/dpc/dedicated-devices/lock-task-mode
   - co czytac: `Overview`, `setLockTaskPackages`, ograniczenia i wyjscie z trybu
3. Towards Trustworthy Kiosk Computing - `PDF`
   - https://www.kiskeya.net/ramon/work/pubs/hotmobile07.pdf
   - co czytac: wstep, threat model, architektura zaufanego kiosku

## 2. FileProvider
1. Improperly Exposed Directories to FileProvider - `WWW`
   - https://developer.android.com/privacy-and-security/risks/untrustworthy-contentprovider-provided-filename
   - co czytac: ryzyko, scenariusz nadpisania plikow, mitigacje
2. FileProvider reference - `WWW`
   - https://developer.android.com/reference/androidx/core/content/FileProvider
   - co czytac: jak dzialaja `content://` URI i granty
3. Android file sharing guide - `WWW`
   - https://developer.android.com/training/secure-file-sharing
   - co czytac: secure file sharing i ograniczanie uprawnien

## 3. Uprawnienia do content URI
1. File sharing and URI grants - `WWW`
   - https://developer.android.com/training/secure-file-sharing/share-file
   - co czytac: `FLAG_GRANT_READ_URI_PERMISSION`, `FLAG_GRANT_WRITE_URI_PERMISSION`
2. Content providers overview - `WWW`
   - https://developer.android.com/guide/topics/providers/content-providers
   - co czytac: eksport, permissions, read/write access
3. OWASP MASTG - testing content URI permissions - `WWW`
   - https://mas.owasp.org/MASTG/
   - co czytac: testy dla URI permissions i provider exposure

## 4. Storage Access Framework
1. Open files using the Storage Access Framework - `WWW`
   - https://developer.android.com/training/data-storage/shared/documents-files
   - co czytac: `ACTION_OPEN_DOCUMENT`, `ACTION_CREATE_DOCUMENT`
2. Persistable URI permissions - `WWW`
   - https://developer.android.com/guide/topics/providers/document-provider
   - co czytac: `takePersistableUriPermission`
3. OWASP MASTG storage guidance - `WWW`
   - https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/
   - co czytac: storage at rest i ograniczanie eksportu danych

## 5. Ekspozycja na external storage
1. Android external storage overview - `WWW`
   - https://developer.android.com/training/data-storage
   - co czytac: internal vs external vs scoped storage
2. Android 10 scoped storage - `WWW`
   - https://developer.android.com/about/versions/10/privacy/changes#scoped-storage
   - co czytac: ograniczenia dostepu i migracja
3. Dynamic Code Loading - `WWW`
   - https://developer.android.com/privacy-and-security/risks/dynamic-code-loading
   - co czytac: trusted locations, integrity checks, external storage

## 6. Wyciek przez notyfikacje
1. Knock-Knock: The unbearable lightness of Android Notifications - `PDF`
   - https://arxiv.org/abs/1801.08225
   - co czytac: threat model, leakage channels, countermeasures
2. Android notifications privacy docs - `WWW`
   - https://developer.android.com/develop/ui/views/notifications
   - co czytac: lock screen visibility, sensitive notifications
3. OWASP MASTG privacy logging / disclosure material - `WWW`
   - https://mas.owasp.org/MASTG/
   - co czytac: data disclosure via UI and notification surfaces

## 7. Screen overlay
1. Tapjacking - Android Developers - `WWW`
   - https://developer.android.com/topic/security/risks/tapjacking
   - co czytac: overlay windows, filterTouchesWhenObscured, mitigations
2. Tapjacking attack paper - `PDF`
   - https://arxiv.org/abs/1507.08694
   - co czytac: attack idea, user interaction abuse, defenses
3. TapTrap artifacts - `WWW`
   - https://zenodo.org/records/16530431
   - co czytac: animation-driven tapjacking and evaluation artifacts

## 8. Tapjacking
1. Tapjacking - Android Developers - `WWW`
   - https://developer.android.com/topic/security/risks/tapjacking
   - co czytac: whole page, especially platform mitigations
2. Android Tapjacking Vulnerability - `PDF`
   - https://arxiv.org/abs/1507.08694
   - co czytac: examples and attack flow
3. TapTrap - `PDF/materials`
   - https://zenodo.org/records/16530431
   - co czytac: animation trick, bypass path, evaluation

## 9. Nadużycie accessibility
1. AccessiLeaks - `PDF`
   - https://publications.cispa.saarland/2804/
   - co czytac: privacy leaks, eavesdropping, sensitive info leakage
2. On Malware Leveraging the Android Accessibility Framework - `PDF`
   - https://eudl.eu/doi/10.4108/ue.1.4.e1
   - co czytac: malware capabilities, screen control, credential theft
3. DVa: Extracting Victims and Abuse Vectors from Android Accessibility Malware - `PDF`
   - https://papers.cool/venue/xu-haichuan%40usenixsecurity24%40USENIX
   - co czytac: abuse vectors, victim selection, fraud flow

## 10. Zlosliwa klawiatura / IME
1. Android input methods overview - `WWW`
   - https://developer.android.com/develop/ui/views/touch-and-input/creating-input-method
   - co czytac: InputMethodService lifecycle, responsibilities
2. InputMethodManager reference - `WWW`
   - https://developer.android.com/reference/android/view/inputmethod/InputMethodManager
   - co czytac: API surface and security implications
3. PHP? no direct paper - recommended search term:
   - `android keyboard malware password interception pdf`
   - co czytac: credential interception through IMEs

## 11. Dynamiczne ladowanie kodu
1. Dynamic Code Loading - Android Developers - `WWW`
   - https://developer.android.com/privacy-and-security/risks/dynamic-code-loading
   - co czytac: overview, impact, mitigations
2. Android NDK dynamic linker docs - `WWW`
   - https://developer.android.com/ndk/reference/group/libdl
   - co czytac: shared objects, loader behavior, relocation notes
3. OWASP MASVS-CODE / MASTG code loading guidance - `WWW`
   - https://mas.owasp.org/MASTG/
   - co czytac: code integrity and trusted sources

## 12. Wykrywanie roota / stan urzadzenia
1. On Root Detection Strategies for Android Devices - `PDF`
   - https://arxiv.org/abs/2012.01812
   - co czytac: detection strategies and bypass discussion
2. All your Root Checks are Belong to Us - `PDF`
   - https://www.nortonlifelock.com/content/dam/nortonlifelock/pdfs/research-papers/2015-research-papers/all-your-root-checks-are-belong-to-us-the-sad-state-of-root-detection-en.pdf
   - co czytac: evasion methods and limitations of checks
3. Android rooting arms race - `PDF`
   - https://www.semanticscholar.org/paper/Android-Rooting%3A-An-Arms-Race-between-Evasion-and-Nguyen-Vu-Chau/d38ccc4e80bf78b435da3916b9ecd118561ac472
   - co czytac: detection vs evasion framing

## 13. Sygnaly integralnosci urzadzenia
1. Play Integrity docs - `WWW`
   - https://developer.android.com/google/play/integrity
   - co czytac: verdicts, backend integration, limitations
2. Key attestation docs - `WWW`
   - https://developer.android.com/privacy-and-security/security-key-attestation
   - co czytac: attestation chain, StrongBox, hardware-backed keys
3. BSM W09 Android Bezpieczenstwo - `MD`
   - `teacher/lectures/BSM_W09_Android_Bezpieczenstwo/BSM_W09_Android_Bezpieczenstwo_Slides.md`
   - co czytac: `Play Integrity jako sygnał backendowy`, `Device integrity verdict`

## 14. Minimalizacja danych
1. OWASP MASVS-STORAGE-1 - `WWW`
   - https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/
   - co czytac: data at rest, limit collection, reduce exposure
2. Android privacy and security guidance - `WWW`
   - https://developer.android.com/privacy-and-security
   - co czytac: minimize data collection and local exposure
3. NIST Privacy Framework - `WWW`
   - https://www.nist.gov/privacy-framework
   - co czytac: data minimization, data processing management

## 15. Retencja danych i bezpieczne usuwanie
1. NIST Privacy Framework - `WWW`
   - https://www.nist.gov/privacy-framework
   - co czytac: retention, data processing lifecycle
2. OWASP MASTG / MASVS storage guidance - `WWW`
   - https://mas.owasp.org/MASTG/
   - co czytac: retention, cache, backups, deletion
3. Android secure storage / deletion guidance - `WWW`
   - https://developer.android.com/privacy-and-security
   - co czytac: cache cleanup, backup scope, remove sensitive data

## Uwagi
- To jest bibliografia tylko do W08.
- Tematy W09 zostaly usuniete z tej listy.
- Dalszy krok to pobranie PDF-ow lokalnie i dopisanie konkretnych stron/sekcji po otwarciu plikow.
