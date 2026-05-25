# Propozycja brakujących wykładów

Po przejrzeniu istniejących materiałów najlepszy brakujący blok to:

## W08: Bezpieczeństwo aplikacji mobilnych i danych lokalnych

Zakres:
- sandbox, UID, uprawnienia i komponenty Androida/iOS
- storage lokalny, cache, backup, restore, export
- IPC, intents, deep links, WebView, clipboard
- tokeny sesyjne, keychain/keystore, błędy w przechowywaniu sekretów
- typowe błędy implementacyjne i audyt aplikacji

Dlaczego to pasuje:
- nie powtarza W03/W04, bo nie skupia się na hasłach ani MFA
- nie dubluje W05/W06/W07, bo nie wchodzi w biometrię, GSM ani hardware
- domyka praktyczny poziom ochrony aplikacji przed W09, który naturalnie przechodzi w podpisy i attestation

## W09: Podpisy, provenance i attestation

To jest drugi dobry temat, jeśli chcemy zakończyć kurs warstwą „czy ta aplikacja/artefakt jest tym, za co się podaje”:
- podpis kodu i łańcuch wydania
- provenance, zaufanie do binarki i supply chain
- attestation platformy i aplikacji
- integracja z backendem i polityką bezpieczeństwa

Rekomendacja końcowa:
- jeśli chcemy jeden nowy temat, wybór numer 1 to **Bezpieczeństwo aplikacji mobilnych i danych lokalnych**
- jeśli chcemy dwa nowe tematy, układ powinien być: **W08 Bezpieczeństwo aplikacji mobilnych i danych lokalnych** + **W09 Podpisy, provenance i attestation**
