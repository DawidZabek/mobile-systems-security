# W08 - publikacje i materialy

Cel: zebrac zrodla do nowego wykładu o bezpieczeństwie aplikacji mobilnych i danych lokalnych, bez powtarzania W03/W04/W05/W07/W09.

Legenda:
- `PDF` = zrodlo do pobrania jako PDF
- `WWW` = zrodlo HTML, z sekcjami do szybkiego czytania
- `co czytac` = gdzie szukac istotnych informacji

## 1. Tryb kiosku / single-purpose device
- Android Device Owner and kiosk mode: Android docs, `WWW`, sekcje o `lock task mode` i device owner.
- Android Enterprise kiosk documentation: Android Enterprise, `WWW`, sekcje o single-app / multi-app kiosk.
- "Kiosk systems security" w literaturze HCI/ubiquitous computing: szukaj hasla `kiosk security` w ACM/IEEE, `PDF`, wstęp + threat model.

## 2. FileProvider
- Android Developers: "Improperly Exposed Directories to FileProvider", `WWW`, sekcje `Overview`, `Impact`, `Mitigations`.
- Android Developers: `androidx.core.content.FileProvider` reference, `WWW`, `Overview` i opis `content://Uri`.
- OWASP MASVS-STORAGE / MASTG-KNOW-0065, `WWW`, sekcje o secure file sharing i URI permissions.

## 3. Uprawnienia do content URI
- Android Developers: "Sharing files", `WWW`, `temporary permissions` i `content URIs`.
- Android Developers: `FileProvider` API reference, `WWW`, fragment o grantach `read/write`.
- OWASP MASWE-0065, `WWW`, opis `URI permission grant flags` i `content provider permissions`.

## 4. Storage Access Framework
- Android Developers: "Open files using the Storage Access Framework", `WWW`, sekcja `Overview` i wybór dokumentu.
- Android Developers: document provider / SAF guide, `WWW`, część o `ACTION_OPEN_DOCUMENT` i persistable URI permissions.
- OWASP MASTG, data storage guidance, `WWW`, sekcje o bezpiecznym otwieraniu i zapisie plikow z zewnętrznych zrodł.

## 5. Ekspozycja na external storage
- OWASP MASTG-KNOW-0042: External Storage, `WWW`, `Overview`, `Scoped Storage`, `Impact`.
- Android Developers: external storage / secure storage guidance, `WWW`, sekcje o data at rest i scoped storage.
- Android security checklist, `WWW`, fragment o nieprzechowywaniu sekretow na external storage.

## 6. Wyciek przez notyfikacje
- Android Developers: "About notifications", `WWW`, sekcje o miejscach wyswietlania i lock screen.
- Android Developers: notification privacy / lock screen visibility, `WWW`, sekcje o prywatnosci i widocznosci.
- "Private by design Android apps" cheat sheet, `PDF`, fragment o notification permission i privacy dashboard.

## 7. Screen overlay
- Android Developers: "Tapjacking", `WWW`, `Overview`, `Impact`, `Mitigations`.
- Android Developers: `Window.setHideOverlayWindows()`, `WWW`, opis obrony przed overlay.
- Android Developers: accessibility-data-sensitive / overlay risks, `WWW`, sekcje o ochronie danych przed nakladkami.

## 8. Tapjacking
- Android Developers: "Tapjacking", `WWW`, sekcje `Full occlusion` i `Partial occlusion`.
- OWASP Mobile Top 10 2023 M6 / platform interaction material, `WWW`, fragment o UI manipulation.
- Android security checklist, `WWW`, punkt o `filterTouchesWhenObscured`.

## 9. Nadużycie accessibility
- Android Developers: `AccessibilityService` API reference, `WWW`, sekcja o tym, że accessibility services moga czytac i sterowac UI.
- Android Developers: "Create your own accessibility service", `WWW`, warunki `canRetrieveWindowContent`.
- Android Developers blog: "Stop malware from snooping on your app data", `WWW`, sekcja o `isAccessibilityTool=true`.

## 10. Złośliwa klawiatura / IME
- Android Developers: "Create an input method", `WWW`, sekcje o IME lifecycle i `InputMethodService`.
- Android Developers: `InputMethodManager` API reference, `WWW`, warning o security issues associated with input methods.
- Android Developers input compatibility docs, `WWW`, sekcje o input device diversity i przechwytywaniu wejscia.

## 11. Dynamiczne ładowanie kodu
- Android Developers: "Dynamic Code Loading", `WWW`, `Overview`, `Impact`, `Mitigations`.
- Android security checklist, `WWW`, punkt o niewczytywaniu kodu z niezweryfikowanych zrodel.
- OWASP MASVS-CODE / mobile top risks, `WWW`, fragmenty o code loading i integrity checks.

## 12. Wykrywanie roota / stan urzadzenia
- Android Developers: "Secure the environment", `WWW`, sekcje o Play Integrity i sygnalach srodowiska.
- Android Developers: "Verify hardware-backed key pairs with key attestation", `WWW`, sekcje o attestation chain i StrongBox.
- BSM W09: Play Integrity / device integrity, `WWW`, slajdy o `Play Integrity as backend signal` i `Device integrity verdict`.

## 13. Sygnaly integralnosci urzadzenia
- Android Developers: Play Integrity docs, `WWW`, `Overview` i verdicts.
- Android Developers: key attestation docs, `WWW`, `attestationSecurityLevel`, `TrustedEnvironment`, `StrongBox`.
- BSM W09: `App integrity i device integrity w jednym flow`, `WWW`, sekcje o backend decision making.

## 14. Minimalizacja danych
- OWASP MASVS / MASTG, `WWW`, sekcje o data minimization i least privilege.
- Android Developers: privacy by design cheat sheet, `PDF`, fragmenty o ograniczaniu zbierania i przechowywania danych.
- NIST Privacy Framework, `PDF/WWW`, sekcje `Data Minimization` i `Retention`.

## 15. Retencja danych i bezpieczne usuwanie
- NIST Privacy Framework, `WWW`, `Data Processing Management` i `Retention`.
- OWASP MASVS-STORAGE, `WWW`, sekcje o data at rest i ograniczaniu czasu zycia danych.
- Android Developers secure storage / external storage guidance, `WWW`, fragmenty o usuwaniu danych, cache i backup.

## Uwagi organizacyjne
- Ten zestaw celowo wycina tematy, ktore juz byly wylozone w kursie: sandbox, UID, hasla, MFA, biometrie, GSM, hardware side-channels oraz podpisy/provenance/attestation jako osobny W09.
- W08 moze byc zbudowany z czterech blokow:
  1. wejscia do aplikacji: `FileProvider`, `content URI`, `Storage Access Framework`, `deep link`, `overlay`, `accessibility`, `IME`
  2. dane lokalne: `external storage`, `notification leakage`, `clipboard`, `retention`, `secure delete`
  3. runtime abuse: `dynamic code loading`, `root/device integrity`
  4. polityki: `kiosk mode`, `data minimization`, `privacy by design`

