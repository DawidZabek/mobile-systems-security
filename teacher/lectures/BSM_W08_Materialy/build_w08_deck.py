from __future__ import annotations

from pathlib import Path


OUT_DIR = Path("/Volumes/Macintosh HD2/Downloads/autotasks/bsm/teacher/lectures/BSM_W08_Materialy")


ASPECTS = [
    (
        "Co to jest",
        "definition",
        "Najpierw zdefiniuj mechanizm i jego granicę. Potem pokaż, co dokładnie znaczy w systemie mobilnym i dlaczego w ogóle istnieje.",
    ),
    (
        "Jak działa",
        "bullet",
        "Tu idź po kolei: wejście, decyzja systemu, stan pośredni, wynik. Nie skracaj przepływu do jednego zdania.",
    ),
    (
        "Jak pęka",
        "bullet",
        "To jest slajd o błędzie i exploit path. Pokaż, gdzie atakujący zyskuje kontrolę i który element jest ufany za dużo.",
    ),
    (
        "Jak się bronić",
        "bullet",
        "Obrona musi być konkretna: reguła, miejsce egzekwowania, wyjątki, wersja systemu i test regresyjny.",
    ),
]


BLOCKS = [
    {
        "file": "BSM_W08_slides_01_48.md",
        "title": "Lokalna sieć i discovery",
        "lead": "mDNS, SSDP i link-local IPv6 pokazują, że sama obecność w LAN daje aplikacji bardzo dużo informacji o pobliskich usługach i urządzeniach.",
        "mechanics": "W tym bloku patrzysz na rekordy PTR, SRV i TXT, multicast na UDP 5353, M-SEARCH, NOTIFY oraz na to, kiedy aplikacja prosi system o pomoc, a kiedy sama skanuje sieć.",
        "attack": "Atak zwykle polega na spoofingu odpowiedzi, korelacji broadcastów albo na tym, że aplikacja ufa lokalnym odpowiedziom tak, jakby były już zweryfikowane.",
        "defense": "Obrona to ścisła separacja LAN od Internetu, mediacja przez system, ograniczenie zakresu uprawnień i testy na błędy socketów, revocation i WebView inheritance.",
        "subtopics": {
            "mDNS record anatomy": "mDNS ogłasza usługi w LAN przez rekordy PTR, SRV i TXT wysyłane na UDP 5353.",
            "SSDP discovery": "SSDP wykrywa urządzenia przez M-SEARCH, NOTIFY i nagłówek LOCATION.",
            "IPv6 link-local": "IPv6 link-local działa tylko na jednej karcie sieciowej i używa zakresu fe80::/10.",
            "Raw socket access": "Surowe sockety pozwalają aplikacji próbować mDNS i SSDP nawet wtedy, gdy ma tylko INTERNET.",
            "NsdManager": "NsdManager jest frameworkowym API do discovery, które odciąża aplikację od ręcznego skanowania LAN.",
            "Casting path": "Casting zwykle powinien iść przez systemowy picker lub output switcher zamiast przez własne skanowanie usług.",
            "Android 16 opt-in": "Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby ujawnić ukryte zależności od LAN.",
            "Android 17 enforcement": "Android 17 blokuje LAN domyślnie dla targetSdk 37+ i wprowadza ACCESS_LOCAL_NETWORK.",
            "Permission split": "Przejście zaczyna się jeszcze przez NEARBY_WIFI_DEVICES, a docelowo trafia do NEARBY_DEVICES.",
            "Broad access path": "Broad access path to klasyczny runtime permission request dla lokalnej sieci.",
            "Privacy-preserving picker": "System-mediated discovery pozwala uniknąć szerokiego grantu dla sieci lokalnej.",
            "Host app inheritance": "WebView dziedziczy stan dostępu do lokalnej sieci po aplikacji hosta.",
        },
    },
    {
        "file": "BSM_W08_slides_49_96.md",
        "title": "Selected media i photo picker",
        "lead": "Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.",
        "mechanics": "Tu ważne są selected access, READ_MEDIA_VISUAL_USER_SELECTED, kontrakt photo pickera, cloud media providers, latest-selection queries i embedded picker osadzony w SurfaceView.",
        "attack": "Breach pojawia się wtedy, gdy aplikacja zatrzymuje stare URI, myli selected access z pełnym dostępem albo traktuje metadane zdjęcia jak dane publiczne.",
        "defense": "Obrona to jasny podział permission matrix, odświeżanie stanu przy revocation, ograniczenie metadanych lokalizacji i korzystanie z systemowego pickera zamiast własnej galerii.",
        "subtopics": {
            "Media as data class": "Zdjęcia i filmy są traktowane jako osobna klasa prywatnych danych.",
            "Selected Photos Access": "Android 14 może dać dostęp tylko do zdjęć i filmów wybranych przez użytkownika.",
            "READ_MEDIA_VISUAL_USER_SELECTED": "READ_MEDIA_VISUAL_USER_SELECTED oznacza partial access do wybranych mediów wizualnych.",
            "Compatibility mode": "Legacy app może działać w trybie kompatybilności, w którym system chroni wybrany podzbiór mediów.",
            "Permission matrix": "Obrazy, filmy i metadane lokalizacji mają różne ścieżki uprawnień i ekspozycji.",
            "Latest selection only": "Latest-selection query zwraca tylko najbardziej aktualny wybrany zestaw URI.",
            "Upgrade behavior": "Upgrade behavior decyduje, czy wcześniej zainstalowana aplikacja zachowa dostęp, czy ma go przeliczyć od nowa.",
            "Photo picker contract": "Systemowy photo picker zwraca content URI bez proszenia o szeroki dostęp do storage.",
            "Backport path": "Jetpack potrafi zbackportować picker na starsze urządzenia przez jeden kontrakt API.",
            "Cloud media providers": "Cloud media providers pozwalają widzieć lokalne i zdalne biblioteki w jednym wyborze.",
            "MediaStore version lockdown": "MediaStore#getVersion() jest przycięty tak, by nie służył jako stabilny fingerprint aplikacji.",
            "Embedded photo picker": "Embedded photo picker działa w SurfaceView przez setChildSurfacePackage i trzyma klienta w stanie resumed.",
        },
    },
    {
        "file": "BSM_W08_slides_97_144.md",
        "title": "Dynamic code loading",
        "lead": "Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.",
        "mechanics": "W tym bloku ważny jest cały pipeline: download, write, verify, load i execute, a także różnice między DexClassLoader, PathClassLoader i InMemoryDexClassLoader.",
        "attack": "Atakujący szuka punktu, w którym plik z kodem można podmienić, skłamać o hash, zapisać do shared storage albo przekonać aplikację do uruchomienia cudzej wersji.",
        "defense": "Obrona to internal albo scoped storage, integrity checks przed load, read-only pliki, podpisy kryptograficzne i rollback z pełnym loggingiem.",
        "subtopics": {
            "Why DCL exists": "DCL istnieje po to, by obsłużyć modularność, pluginy i runtime updates.",
            "Attack surface": "Powierzchnia ataku rośnie w chwili, gdy ładowany kod da się podmienić lub uszkodzić.",
            "Remote source risk": "Remote code loading jest najdroższe z punktu widzenia ryzyka i może łamać Google Play policy.",
            "Trusted storage": "Kod, który ma być później ładowany, powinien lądować w internal storage albo w scoped storage.",
            "External storage risk": "Shared external storage jest mutowalny, więc nie nadaje się na artefakt wykonywalny.",
            "Integrity before load": "Bezpieczny wzorzec to verify-before-load, a nie load-first.",
            "SHA-256 checker": "SHA-256 checker liczy digest i porównuje go z referencją zaufaną przez aplikację.",
            "Code signing": "Podpis kodu dodaje podpis kryptograficzny i zaufany public key.",
            "Hash storage": "Referencja hash lub signature musi leżeć w chronionym miejscu, a nie obok samego payloadu.",
            "Path to execution": "Niebezpieczna ścieżka to download, write, verify, load i execute.",
            "Class loader choices": "DexClassLoader, PathClassLoader i InMemoryDexClassLoader różnią się tym, skąd biorą kod i jak długo go trzymają.",
            "Native versus Java": "Natywne dlopen i dlsym mają ten sam problem z podmianą co loading pliku dex.",
        },
    },
    {
        "file": "BSM_W08_slides_145_192.md",
        "title": "Retencja i secure deletion",
        "lead": "Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.",
        "mechanics": "Tu wchodzą log-structured storage, YAFFS, flash translation layer, snapshoty, purge, ballooning i zero overwriting.",
        "attack": "Breach jest banalny: delete nie usuwa tego, co już zostało przesunięte przez garbage collection, wear leveling albo snapshot history.",
        "defense": "Obrona to dobór mechanizmu usuwania do klasy nośnika, testy forensyczne po kasowaniu i polityka retention z audytem.",
        "subtopics": {
            "Retention vs disposal": "Retencja decyduje o czasie życia danych, a disposal o ich fizycznym zniknięciu.",
            "Why delete fails": "Delete zawodzi przez remanencję danych i metadanych.",
            "Log-structured storage": "Log-structured filesystems dopisują nowe bloki i czyszczą stare dopiero później.",
            "YAFFS example": "YAFFS na flashu zostawia stare wersje, bo garbage collection nie kasuje wszystkiego od razu.",
            "FTL mapping": "FTL mapuje logiczne bloki na fizyczne bloki poza kontrolą filesystemu.",
            "Overwrite problem": "Overwrite nie daje gwarancji, że nadpiszesz dokładnie ten fizyczny blok, który chcesz usunąć.",
            "Encryption limitation": "Sama kryptografia nie pomaga, jeśli stare kopie lub klucze nadal są dostępne.",
            "Purge algorithm": "Purge chce realnie zniszczyć lub przenieść dane aż recovery przestaje być praktyczne.",
            "Ballooning algorithm": "Ballooning zjada wolne miejsce, by wymusić wypchnięcie bloku celu.",
            "Zero overwriting": "Zero overwriting wypełnia obszar i potem vacuumuje resztki.",
            "Versioned file system": "Snapshoty i historia wersji komplikują kasowanie, bo stare stany nadal istnieją.",
            "Forensic verification": "Forensic verification sprawdza, czy po usunięciu da się jeszcze odzyskać treść lub jej ślady.",
        },
    },
    {
        "file": "BSM_W08_slides_193_240.md",
        "title": "Apple continuity i cross-device services",
        "lead": "Continuity w ekosystemie Apple to Handoff, Universal Clipboard i Wi-Fi Password Sharing działające przez BLE, AWDL i Wi-Fi.",
        "mechanics": "W źródłach widać, że protokoły Continuity mają własne discovery, transfer i auth state machine oraz że da się je analizować przez reverse engineering i packet capture.",
        "attack": "Problemy pojawiają się przez leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery oraz transportu.",
        "defense": "PrivateDrop zastępuje kruche contact checks przez PSI, a analityka i testy powinny obejmować stany urządzeń, zasięg i typ transportu.",
        "subtopics": {
            "Continuity overview": "Apple's Continuity obejmuje Handoff, Universal Clipboard i Wi-Fi Password Sharing.",
            "Handoff discovery": "Handoff zaczyna się od BLE discovery i przenosi activity state w stacku Continuity.",
            "AirDrop discovery": "AirDrop używa discovery, authentication i transferu na bazie BLE, AWDL i Wi-Fi.",
            "PrivateDrop": "PrivateDrop zastępuje leaked contact checks mechanizmem PSI, żeby nie ujawniać phone number ani email.",
            "AWDL and BLE": "AWDL i BLE niosą niskopoziomowy ruch discovery oraz widoczny dla użytkownika stan Continuity.",
            "Cross-device identity": "Messagi Continuity mogą ujawniać typ urządzenia, wersję OS i zachowanie pasywnemu obserwatorowi.",
            "Spoof relay downgrade": "Atakujący może spoofować, relayować albo downgrade'ować discovery i authentication.",
            "Transport and state machine": "Structured analysis wymaga obserwacji całego state machine na różnych vantage points macOS.",
            "Packet analysis": "Packet captures pokazują, które pola są szyfrowane, a które metadata lecą jawnie.",
            "Mitigations": "PSI, większa ostrożność w contact discovery i twardsza kontrola widoczności ograniczają wyciek.",
            "Test matrix": "Dobry test matrix zmienia stan urządzenia, odległość i użyty transport.",
            "Android comparison": "Android local-network policy daje użyteczny kontrast dla zawsze aktywnych kanałów continuity.",
        },
    },
]


def aspect_block(aspect: str) -> tuple[str, str, str, str]:
    if aspect == "Co to jest":
        return (
            "Definicja i granica pojęcia",
            "Dlaczego to nie jest tylko hasło",
            "Jakie miejsce ma w modelu zagrożeń",
            "Dlaczego ten mechanizm istnieje",
        )
    if aspect == "Jak działa":
        return (
            "Wejście i stan początkowy",
            "Krok po kroku przez przepływ",
            "Decyzja systemu i stan pośredni",
            "Wynik oraz konsekwencja",
        )
    if aspect == "Jak pęka":
        return (
            "Warunek powodzenia ataku",
            "Co kontroluje atakujący",
            "Gdzie system ufa za dużo",
            "Skutek dla danych lub dostępu",
        )
    return (
        "Reguła i miejsce egzekwowania",
        "Minimalny zakres dostępu",
        "Wersja systemu i kompatybilność",
        "Test i regresja",
    )


def bullets_for(block: dict, subtopic: str, aspect: str) -> list[str]:
    specific = block["subtopics"][subtopic]
    lead = block["lead"]
    mechanics = block["mechanics"]
    attack = block["attack"]
    defense = block["defense"]

    if aspect == "Co to jest":
        return [
            specific,
            f"Granica: {lead}",
            f"Miejsce w modelu zagrożeń: {mechanics}",
            "Dlaczego to jest istotne właśnie w mobilu",
        ]
    if aspect == "Jak działa":
        return [
            f"Krok 1: {specific}",
            f"Krok 2: {mechanics}",
            "Krok 3: decyzja systemu lub stan pośredni",
            "Krok 4: wynik i konsekwencja dla aplikacji",
        ]
    if aspect == "Jak pęka":
        return [
            f"Warunek powodzenia: {specific}",
            f"Kontrola atakującego: {attack}",
            "Ufa się za dużo lokalnym odpowiedziom, stanom albo parametrom",
            "Skutek: wyciek, przejęcie, podmiana lub odmowa usługi",
        ]
    return [
        f"Reguła: {defense}",
        "Egzekwowanie: w manifeście, API, pickerze albo parserze",
        "Zakres: tylko to, co naprawdę potrzebne",
        "Test: przypadek zły odpada, przypadek dobry przechodzi",
    ]


def teleprompter(num: int, block: dict, subtopic: str, aspect: str) -> str:
    specific = block["subtopics"][subtopic]
    lead = block["lead"]
    mechanics = block["mechanics"]
    attack = block["attack"]
    defense = block["defense"]
    opening, middle, breach, close = aspect_block(aspect)

    return (
        f"Slajd {num}. {subtopic}. {block['title']}.\n\n"
        f"{opening}. {subtopic} w tym miejscu oznacza dokładnie: {specific} "
        f"Na tle tego bloku chodzi o: {lead}\n\n"
        f"{middle}. {mechanics} "
        f"Jeżeli źródło podaje rekord, API, callback, permission albo stan, to trzeba go rozłożyć na części i nazwać po kolei.\n\n"
        f"{breach}. {attack} "
        f"Tu nie opowiadasz o idei, tylko o tym, co dokładnie robi przeciwnik, jak wchodzi w przepływ i co dostaje na końcu.\n\n"
        f"{close}. {defense} "
        f"Na końcu zawsze ma być test: co ma zostać zablokowane, co ma przejść, i który log albo stan ma to potwierdzić."
    )


def render_slide(num: int, block: dict, subtopic: str, aspect: str) -> str:
    layout = "definition" if aspect == "Co to jest" else "bullet"
    lines = [
        f"#slide {num}",
        "## layout",
        layout,
        "## slide title",
        f"{subtopic} — {aspect}",
    ]
    if aspect == "Co to jest":
        lines += [
            "## term",
            subtopic,
            "## definition",
            block["subtopics"][subtopic],
        ]
    else:
        lines += ["## bullets"]
        for bullet in bullets_for(block, subtopic, aspect):
            lines.append(f"- {bullet}")
    lines += [
        "## teleprompter:",
        teleprompter(num, block, subtopic, aspect),
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    slide_num = 1
    for block in BLOCKS:
        path = OUT_DIR / block["file"]
        chunks: list[str] = []
        for subtopic in block["subtopics"]:
            for aspect_name, _, _ in ASPECTS:
                chunks.append(render_slide(slide_num, block, subtopic, aspect_name))
                slide_num += 1
        path.write_text("\n".join(chunks), encoding="utf-8")


if __name__ == "__main__":
    main()
