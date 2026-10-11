<!-- trace: AUF-20261011-033 -->
# ct-agent Installation: Messung des heutigen Wegs (Scheibe 0)

| Fall | Plattform | Art | Befehle | Entscheidungen | Variablen (nur Namen) | GUI-Zwang | ohne Doku | Fundstellen |
|---|---|---|---|---|---|---|---|---|
| channel | Linux | teils gemessen / abgeleitet | 7 | 4 | CT_OIDC_ISSUER, CT_OIDC_TOKEN, CT_CHANNEL_ROLE, CT_CHANNEL_GRANT, CT_CHANNEL_HOLDER_KEY, CT_CHANNEL_NOISE_KEY, CT_CHANNEL_BROKER, CT_CHANNEL_RELAY | `ct-agent login` Device-Grant: Browser auf beliebigem Gerät (nicht Zwang auf der Installationsmaschine) | ja: `scripts/setup.sh`/`setup.ps1` verdrahten keine `CT_CHANNEL_*`-Variable; Register/Allowlist/Login nur in `docs/channel.md` | docs/channel.md:33-62,63-75,270-300; grep 'CT_CHANNEL' scripts/setup.sh scripts/setup.ps1 → 0 Treffer; scripts/setup.sh:87-93 (detect_env, Zeile 1 des Falls, gemessen) |
| channel | macOS | abgeleitet | 7 | 4 | wie Linux | wie Linux | wie Linux | wie Linux; scripts/setup.sh:92 (`linux\|darwin`) |
| channel | Windows | abgeleitet | ≥7 (siehe Z2/Hürde 2: kein `-ClientOnly`, daher zusätzlich der volle Tunnel-Onboarding-Pfad nötig, +4 Befehle aus Zeile "tunnel / Windows") | ≥4 (+4 aus "tunnel / Windows") | wie Linux, zusätzlich alle in "tunnel / Windows" genannten Variablen (weil der reine CLI-Pfad fehlt) | wie Linux | ja: zusätzlich fehlt `-ClientOnly` in setup.ps1 komplett (siehe Hürde 2) | grep -c ClientOnly scripts/setup.ps1 → 0 (gemessen, ZUG 1); scripts/setup.ps1:22-26 (Parameterliste ohne ClientOnly); README.md:51-60 |
| tunnel | Linux | teils gemessen / abgeleitet | 4 | 4 | CT_BOOTSTRAP (oder CT_AGENT_JOIN_TOKEN+CT_AGENT_TOKEN), CT_AGENT_CP_URL, CT_AGENT_HOSTNAME, CT_AGENT_ORIGIN, CT_AGENT_ORIGIN_PROTO, CT_AGENT_MODE, CT_AGENT_EDGE_CERT_URL, CT_AGENT_CAPABILITY_OUT, CT_AGENT_EDGE, CT_AGENT_ID | nicht belegt für die Einrichtung selbst (Nutzung: siehe Z1) | ja: die 5 stillschweigend gesetzten Variablen (MODE, EDGE_CERT_URL, CAPABILITY_OUT, EDGE, ID) stehen nicht im `.env`-Template und nicht im README; die `--yes`-Pflicht für einen nicht-interaktiven (gepipten) Direct-Install steht nicht im README-Quickstart | scripts/setup.sh:149-174 (Template, gemessen via test-setup-sh-ensure-env.sh), :177-229 (ensure_env, gemessen), :231-269 (stille Defaults, abgeleitet), :363-404 (install_direct, abgeleitet); README.md:37-45 |
| tunnel | macOS | abgeleitet | 4 | 4 | wie Linux | nicht belegt | wie Linux | wie Linux; scripts/setup.sh:92 |
| tunnel | Windows | abgeleitet | 4 | 4 | wie Linux (identische CT_AGENT_*-Namen) | nicht belegt | wie Linux, zusätzlich: `Confirm-Mode` prüft nicht, ob stdin ein Terminal ist (kein Äquivalent zu setup.sh `[ ! -t 0 ]`) | scripts/setup.ps1:108-207 (Import-DotEnv/Defaults), :61-78 (Confirm-Mode ohne TTY-Prüfung) vs scripts/setup.sh:140-142 |
| ssh | Linux | teils gemessen / abgeleitet | 7 (4 aus "tunnel / Linux" für den Origin-Host + 3: Client-Install, `ssh-config`, `ssh`) | 6 (4 aus "tunnel / Linux" + 2: ORIGIN_TLS terminate vs. passthrough; Zertifikatsquelle für TLS_CERT/KEY) | zusätzlich zu "tunnel": CT_AGENT_ORIGIN_TLS, CT_AGENT_TLS_CERT, CT_AGENT_TLS_KEY | keine — einziger Fall ohne GUI-Zwang auf beiden Seiten (Terminal-Protokoll) | ja: CT_AGENT_ORIGIN_TLS/_TLS_CERT/_TLS_KEY stehen nur in native/src/main.rs, nicht in docs/channel.md, README oder `.env`-Template; kein dokumentiertes Backgrounding-Muster für den Origin-Prozess in diesem Fall (nur das für "tunnel" geschriebene `nohup`) | native/src/main.rs:246-263 (SSH-Doku-Block, abgeleitet); README.md:51-56; scripts/setup.sh:382 (nohup, abgeleitet) |
| ssh | macOS | abgeleitet | 7 | 6 | wie Linux | keine | wie Linux | wie Linux |
| ssh | Windows | abgeleitet | ≥7 (kein `-ClientOnly`: der Origin- *und* der Client-Host müssen je den vollen "tunnel / Windows"-Pfad durchlaufen, bevor `ssh-config`/`ssh` nutzbar sind) | ≥6 (+4 aus "tunnel / Windows" statt +0) | wie Linux + alle "tunnel / Windows"-Variablen auf beiden Hosts | keine | ja: zusätzlich kein `-ClientOnly` (Hürde 2); README.md:51-56 verspricht "Install just the binary", das gilt auf Windows nicht | grep -c ClientOnly scripts/setup.ps1 → 0 (gemessen); README.md:51-60 |
| browser | Linux | teils gemessen / abgeleitet | 4 (identisch zu "tunnel / Linux": CT_AGENT_MODE trägt bereits den Default-Wert für den Browser-Modus) | 4 (identisch zu "tunnel / Linux") | identisch zu "tunnel / Linux" | Einrichtung: nicht belegt — Nutzung: siehe Z1 (Browser auf der Gegenseite zum Aufruf der getunnelten HTTPS-Adresse) | wie "tunnel / Linux" | scripts/setup.sh:235 (Default-Zuweisung für CT_AGENT_MODE, Quelltext gelesen — Wert hier absichtlich nicht wiedergegeben), native/src/config.rs:554-555 ("Browser Plane", abgeleitet); scripts/setup.sh:510-516 (Portal-UI für Tunnel-Verwaltung, abgeleitet) |
| browser | macOS | abgeleitet | 4 | 4 | identisch zu "tunnel / macOS" | wie Linux (Z1) | wie "tunnel / macOS" | wie oben |
| browser | Windows | abgeleitet | 4 | 4 | identisch zu "tunnel / Windows" | wie Linux (Z1) | wie "tunnel / Windows" | scripts/setup.ps1:166 (setzt CT_AGENT_MODE auf denselben Default wie setup.sh:235, falls nicht gesetzt; abgeleitet) |
| **Z1: Abgrenzung "browser"** | alle | abgeleitet | — | — | — | Einrichtung (setup.sh/ps1, client-only) verlangt an keiner Stelle eine GUI — belegt durch grep (0 Treffer für Browser-Öffnen in den Skripten). Nutzung des fertigen Tunnels (die am Origin weitergeleitete Site aufrufen) ist nur über einen Browser auf der Gegenseite sinnvoll, da Zweck des Produkts (README.md:3-7: "zero-knowledge tunnel") ein HTTP(S)-Backend ist; ein wörtlicher Beleg "der Endnutzer braucht einen Browser" fehlt im Repo — **nicht belegt, nur plausibel aus dem Produktzweck abgeleitet.** Einzige tatsächlich belegte Browser-Pflicht im gesamten Repo ist die von `ct-agent login` (OIDC Device-Grant), die aber zum "channel"-Fall gehört, nicht zu "browser" | — | README.md:1-19; docs/channel.md:44-49; native/src/config.rs:554-555 |
| **Z2: Windows-SSH und Administratorrechte** | Windows | abgeleitet | — | — | — | Keine Dienst-Einrichtung (kein New-Service, kein sc.exe, kein nssm, kein Eintrag für "Administrator"/"elevat"/"UAC") im gesamten `scripts/setup.ps1` gefunden (grep -ni 'service\|admin\|elevat\|uac\|sc\.exe\|nssm' → keine Treffer außer einem Kommentarwort "service" in einer anderen Bedeutung). Der Prozess wird heute als gewöhnlicher Vordergrund-Kindprozess der SSH-Sitzung gestartet, ohne erhöhte Rechte | — | scripts/setup.ps1:262 (`Start-Process -FilePath .\ct-agent.exe -PassThru -WindowStyle Hidden`, abgeleitet); grep -ni Befehl oben (gemessen in diesem Lauf, 2026-10-11T18:40Z, 0 Treffer) |

## Methodik (Kennzeichnung und Zählweise)

- **gemessen**: in diesem Lauf tatsächlich ausgeführt, Befehl + Ergebniszeile + Zeit (`date -u`) weiter unten wörtlich genannt.
- **abgeleitet**: aus Doku oder Quelltext gelesen, mit Datei:Zeile belegt — nicht ausgeführt.
- **nicht gemessen**: weder ausgeführt noch aus einer belegbaren Quelle abgeleitet.
- **Befehl** = eine Zeile, die ein Betreiber auf der SSH-Sitzung tatsächlich eintippt (ein `curl …\|bash`, ein Editor-Durchlauf, ein einzelner CLI-Aufruf). Das Öffnen der SSH-Sitzung selbst wird nicht mitgezählt (sie ist laut Statement der Zugangsweg, nicht ein Installationsschritt).
- **Entscheidung** = jede Stelle, an der Skript, Doku oder Quelltext dem Betreiber eine Wahl zwischen mindestens zwei Optionen überlässt, die den weiteren Weg ändert (ein Flag, eine Variable mit mehreren gültigen Werten, ein y/N-Prompt). Stillschweigend gesetzte Defaults (z. B. die 5 Variablen aus Befund "mini") sind keine Entscheidung des Betreibers, solange sie nicht manuell überschrieben werden müssen.

## Herkunft je Zeile (Nachzählbar)

**channel / Linux, macOS** — 7 Befehle: (1) `curl …\| bash -s -- --client-only` (gemessen: Versuch in `mktemp -d`, Abbruch "curl is required but not found", 2026-10-11T18:40:48Z, siehe unten); (2) `ct-agent login` mit vorangestelltem CT_OIDC_ISSUER (docs/channel.md:42-43, abgeleitet); (3) Browser-Schritt des Device-Grants auf einem beliebigen Gerät (docs/channel.md:46-48, abgeleitet, nicht als eigener "Befehl" auf der SSH-Sitzung zählbar, aber Teil des Wegs); (4) Variablen setzen (`export CT_CHANNEL_…`, ein Edit/Export-Block, docs/channel.md:270-300); (5) `ct-agent channel register` (docs/channel.md:63-75); (6) `ct-agent channel allowlist add` (docs/channel.md:27, Modes-Tabelle); (7) `ct-agent channel` (Join, docs/channel.md:19 Zeile "Mode"-Tabelle). 4 Entscheidungen: Login-Browser auf welchem Gerät (kosmetisch, keine Pfadänderung — nicht gezählt); Broker/Relay- vs. Direct-Address-Pfad (docs/channel.md:19); `register` vs. `register --rekey` (docs/channel.md:70-71); Transport-Ladder-Variablen (Front-Door an/aus, docs/channel.md:81-86); `CT_CHANNEL_REQUIRE_PEER_GRANT` an/aus (docs/channel.md:295).

**channel / Windows** — zusätzlich zu obigem: kein `-ClientOnly` (ZUG-1-Befehl, gemessen: `grep -c ClientOnly scripts/setup.ps1` → `0`), daher zuerst der volle "tunnel / Windows"-Pfad (s. u., +4 Befehle, +4 Entscheidungen), um überhaupt an `ct-agent.exe` zu kommen.

**tunnel / Linux, macOS, Windows** — 4 Befehle: (1) erster Lauf des Installers ohne `.env` → schreibt `.env.example`, Exit 1 (für Linux **gemessen** über `scripts/tests/test-setup-sh-ensure-env.sh`, Fall 3, PASS, 2026-10-11T18:40:35Z — s. u.); (2) `.env.example` nach `.env` kopieren; (3) `.env` mit echten Werten befüllen (ein Editor-Durchlauf); (4) zweiter Lauf des Installers mit `--yes`/`-Yes` (Linux/macOS: `scripts/setup.sh:149-404`, abgeleitet ab hier — Download/Verifikation/Onboarding in dieser Sandbox nicht ausführbar, s. u.; Windows: `scripts/setup.ps1:108-335`, abgeleitet). 4 Entscheidungen: (a) `CT_BOOTSTRAP` oder `CT_AGENT_JOIN_TOKEN`+`CT_AGENT_TOKEN` (scripts/setup.sh:182-199); (b) `--docker`/`-Docker` oder Direct-Host (scripts/setup.sh:31-85 usage, abgeleitet); (c) `--yes`/`-Yes` nötig, weil ein gepipter Installer nicht interaktiv ist — auf Linux/macOS erzwungen durch `[ ! -t 0 ]` (scripts/setup.sh:140-142), auf Windows **nicht** erzwungen (kein TTY-Check in `Confirm-Mode`, scripts/setup.ps1:61-78 — eigener Befund, s. Hürden); (d) `--template`/`-Template` ja/nein (scripts/setup.sh:31-49 usage).

**ssh / \*** — Befehle/Entscheidungen = "tunnel"-Zeile der jeweiligen Plattform (Origin-Host muss zuerst wie "tunnel" onboarden) **plus** 3 Befehle (Client-Binary installieren, `ct-agent ssh-config <hostname> >> ~/.ssh/config`, `ssh <hostname>` — native/src/main.rs:258-262, abgeleitet) **plus** 2 Entscheidungen (CT_AGENT_ORIGIN_TLS: terminate vs. passthrough, native/src/main.rs:246-253; Zertifikatsquelle für `CT_AGENT_TLS_CERT`/`_TLS_KEY` — ACME via `ct-agent certificate` oder manuell, native/src/main.rs:248-249). Auf Windows zusätzlich durch das fehlende `-ClientOnly` verschärft (s. "channel / Windows").

**browser / \*** — identisch zu "tunnel" derselben Plattform, weil CT_AGENT_MODE bereits von `ensure_env`/`Import-DotEnv` auf den Browser-Modus vorbelegt wird (scripts/setup.sh:235, scripts/setup.ps1:166) — kein zusätzlicher Befehl oder Entscheidung für die Einrichtung; der Unterschied liegt ausschließlich in der Nutzung (Z1).

## Befund vom Knoten "mini" (fünf Anläufe: EDGE_CERT_URL, CAPABILITY_OUT, EDGE, HOSTNAME, MODE)

Ob der Verlauf auf "mini" tatsächlich so war, kann dieser Lauf nicht prüfen — nur die Fundstellen, nicht die Anekdote selbst.

| Variable | Lesestelle (Binary) | Ohne sie | Setzt/nennt sie |
|---|---|---|---|
| `CT_AGENT_EDGE_CERT_URL` | native/src/main.rs:1266 (fetch via Control-Plane-Client) | wartet auf den Shared-Volume-Pfad `/shared/edge-cert.der` (native/src/main.rs:1259) — laut Kommentar scripts/setup.sh:233-234 "makes the agent hang forever, not just error" | scripts/setup.sh:236 / scripts/setup.ps1:167 (Default = `CT_AGENT_CP_URL`); **im `.env`-Template (scripts/setup.sh:150-174) und im README nicht auffindbar** |
| `CT_AGENT_CAPABILITY_OUT` | native/src/main.rs:1260-1261 | Default `/shared/capability.bin` (Docker-Compose-Pfad von CADS-Tunnel) → ENOENT auf einer Kundenmaschine (Kommentar scripts/setup.sh:255-258) | scripts/setup.sh:259 / scripts/setup.ps1:191 (Default = `$STATE_DIR/capability.bin`); **im `.env`-Template und README nicht auffindbar** |
| `CT_AGENT_EDGE` | native/src/config.rs:534 (Default `127.0.0.1:4433`) | kein Hang, aber ein stiller Fehlzeiger auf localhost, falls weder gesetzt noch automatisch ermittelt | scripts/setup.sh:260-269 / scripts/setup.ps1:195-200 (Auto-Ermittlung über `<CP_URL>/network-info`, Fallback: `die`/`Die`); **im `.env`-Template und README nicht auffindbar** |
| `CT_AGENT_HOSTNAME` | native/src/config.rs:556-558 (optional, leer → `None`) | von `ensure_env`/`Import-DotEnv` hart verlangt (scripts/setup.sh:220, scripts/setup.ps1:153) — Fehlen bricht vor dem Agentenstart ab | **im `.env`-Template vorhanden** (scripts/setup.sh:164 traegt die leere CT_AGENT_HOSTNAME-Zeile) — als einzige der 5 dokumentiert, aber ohne Formatangabe |
| `CT_AGENT_MODE` | native/src/config.rs:554-555 (`browser_forward`, Vergleich case-insensitiv mit `"browser"`) | fällt auf `false` (Passthrough statt Terminierung) ohne Fehlermeldung — falsches Verhalten, kein Abbruch | scripts/setup.sh:235 / scripts/setup.ps1:166 (Default `browser`); erwähnt (aber nicht als Variable benannt) in native/src/main.rs:246 (SSH-Doku-Block); **im `.env`-Template und README nicht auffindbar** |

## Fünf größte Hürden nach Häufigkeit

1. **Die 5 stillschweigend gesetzten Variablen (MODE, EDGE_CERT_URL, CAPABILITY_OUT, EDGE, ID/HOSTNAME) stehen nicht im `.env`-Template/README.** Betrifft 6 Tabellenzeilen (tunnel × 3, browser × 3). Fundstellen: scripts/setup.sh:231-269 vs. :149-174; scripts/setup.ps1:162-201 vs. :122-146.
2. **Kein `-ClientOnly`/Äquivalent in `scripts/setup.ps1`** — auf Windows gibt es keinen Weg, nur die CLI zu installieren; der volle Tunnel-Onboarding-Pfad ist erzwungen. Betrifft 3 Zeilen (channel/Windows, ssh/Windows, und die Diskrepanz zum README-Versprechen "Install just the binary"). Fundstelle: `grep -c ClientOnly scripts/setup.ps1` → `0` (gemessen, ZUG 1); scripts/setup.ps1:22-26; README.md:51-60.
3. **Kein dokumentierter Dienst-/Hintergrundstart** (kein systemd-, launchd- oder Windows-Dienst im Repo) — jeder Fall, der über einen abgemeldeten SSH-Betreiber hinaus laufen soll, hängt am selbstgebauten `nohup`/`Start-Process`-Muster des Installer-Skripts, das nur für den "tunnel"-Fall geschrieben ist. Betrifft potenziell alle 12 Zeilen, konkret belegt für 4 (ssh × 2 Hosts, channel-Serve, browser-Dauerbetrieb). Fundstelle: scripts/setup.sh:382, scripts/setup.ps1:262 — kein Treffer für `systemd\|launchd\|service\|sc\.exe\|nssm` (gemessen per grep, 2026-10-11T18:40Z, 0 Treffer außer o. g. Kommentarwort).
4. **`--yes`/`-Yes` ist für einen nicht-interaktiven (gepipten) Direct-Install nötig, aber im README-Quickstart nicht genannt** — und auf Windows fehlt sogar die Absturzsicherung dafür (kein TTY-Check in `Confirm-Mode`). Betrifft 6 Zeilen (tunnel × 3, browser × 3). Fundstellen: scripts/setup.sh:140-148 vs. scripts/setup.ps1:61-78; README.md:37-45.
5. **CT_AGENT_ORIGIN_TLS/_TLS_CERT/_TLS_KEY (für den SSH-Fall) stehen nur im Quelltext**, nicht in `docs/channel.md`, README oder `.env`-Template. Betrifft 3 Zeilen (ssh × 3). Fundstelle: native/src/main.rs:246-263 — keine Entsprechung in docs/channel.md oder README.md.

## Grenzen dieses Laufs (Sandbox)

- `curl` ist in dieser Sandbox nicht installiert (`which curl` → kein Treffer, `command -v curl` schlägt in `detect_env` fehl: "curl is required but not found"). Damit scheiterten `scripts/tests/test-setup-sh-client-only.sh`, `test-setup-sh-piped.sh`, `test-setup-sh-verify.sh` (jeweils an derselben Stelle) und der einmalige `--client-only`-Versuch außerhalb des Repos — alles **nicht gemessen** ab dieser Stelle, entsprechend der Vorgabe (kein zweiter Versuch, kein Ausweichen). `openssl` war vorhanden.
- `test-setup-sh-ensure-env.sh` (kein Netzzugriff nötig) lief vollständig durch: PASS, 2026-10-11T18:40:35Z.
- Der verlangte `mktemp -d` **außerhalb** des Repos landete tatsächlich unter `/workspace/.cads-tmp/…`, weil diese Sandbox `TMPDIR=/workspace/.cads-tmp` setzt — innerhalb des Arbeitsverzeichnisses, nicht wirklich außerhalb des Repos. Eigener Befund, hier dokumentiert statt verschwiegen; der Ordner war nach dem fehlgeschlagenen Versuch leer und wurde entfernt.
- `./ct-agent --version`/`--help` konnten nicht gemessen werden: ohne `curl` wurde kein Binary heruntergeladen.
- macOS und Windows sind in dieser Linux-Sandbox grundsätzlich nicht ausführbar; jede Angabe dort ist "abgeleitet" oder "nicht gemessen", nie "gemessen".
- Die Sandbox selbst (Werkzeuge, Netz) wurde nicht systematisch geprüft, nur an den Stellen, an denen ein Testlauf daran scheiterte.

## Wörtliche Ergebniszeilen (Nachweis)

```
$ date -u
Sun Oct 11 18:40:20 UTC 2026

$ bash scripts/setup.sh --help
[...]
EXIT=0

$ bash scripts/tests/test-setup-sh-client-only.sh
FAIL: case 1 rc=1 output: ==> checking your environment
  ✓ OS/arch: linux/x86_64
error: curl is required but not found — install it and re-run
[...]
EXIT=1

$ bash scripts/tests/test-setup-sh-ensure-env.sh
PASS: all ensure_env() cases behaved correctly
EXIT=0

$ bash scripts/tests/test-setup-sh-piped.sh
FAIL: case 1 did not stop at the confirm gate -- output: [...] error: curl is required but not found [...]
EXIT=1

$ bash scripts/tests/test-setup-sh-verify.sh
FAIL: [...] error: curl is required but not found [...] (8 Fälle), FAIL: docker/verify-release.sh: [...] curl: command not found (4 Fälle)
EXIT=1

$ TMPD=$(mktemp -d) && cd "$TMPD" && bash /workspace/scripts/setup.sh --client-only
==> checking your environment
  ✓ OS/arch: linux/x86_64
error: curl is required but not found — install it and re-run
EXIT=1
(TMPD=/workspace/.cads-tmp/tmp.35px4QJcr0 -- innerhalb des Repo-Arbeitsverzeichnisses, siehe "Grenzen dieses Laufs")

$ grep -n 'CT_AGENT_EDGE_CERT_URL:=\|CT_AGENT_CAPABILITY_OUT:=' scripts/setup.sh
236:  : "${CT_AGENT_EDGE_CERT_URL:=$CT_AGENT_CP_URL}"
259:  : "${CT_AGENT_CAPABILITY_OUT:=$STATE_DIR/capability.bin}"

$ grep -c ClientOnly scripts/setup.ps1
0
```


## Selbstprüfung dieses Berichts (Fortsetzungs-Sitzung, gemessen)

Alle Zeilen in diesem Abschnitt sind in dieser Sitzung ausgeführt worden; die Zeit kommt aus
`date -u`, nichts ist geschätzt.

```
$ date -u
Sun Oct 11 18:51:17 UTC 2026

$ git diff --stat origin/main...HEAD
 docs/installation-messung.md | 176 +++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 176 insertions(+)

$ grep -c 'trace: AUF-20261011-033' docs/installation-messung.md
2
(Zeile 1 dieser Datei ist der Marker; der zweite Treffer ist die Befehlszeile hier selbst)

$ grep -cE '^\| (channel|tunnel|ssh|browser|\*\*Z[12])' docs/installation-messung.md
14
(= 12 Zellen Fall x Plattform + Z1 + Z2)

$ grep -nE 'CT_[A-Za-z_]+ *=' docs/installation-messung.md; echo "exit=$?"
exit=1
(kein Treffer: in dieser Datei steht nirgends ein '=' mit Wert hinter einem CT_-Namen —
 Variablen werden ausschliesslich mit Namen genannt)
```

Nachgeprüfte Messungen (dieselben Befehle wie in der ersten Sitzung, erneut ausgeführt
2026-10-11T18:50-18:51Z — gleiches Ergebnis):

```
$ bash scripts/setup.sh --help   (Ausgabe 18 Zeilen)
EXIT=0

$ bash scripts/tests/test-setup-sh-ensure-env.sh | tail -1
PASS: all ensure_env() cases behaved correctly
EXIT=0

$ command -v curl; echo "curl rc=$?"
curl rc=1            (curl fehlt weiterhin -> die drei netzabhängigen Tests und der
                      --client-only-Versuch bleiben 'nicht gemessen', kein zweiter Versuch)
$ command -v openssl
/usr/bin/openssl

$ grep -ni 'service' scripts/setup.ps1
100:# Where your own site/service is actually running, and how ct-agent should
(= der eine Treffer in anderer Bedeutung, auf den Z2 sich beruft)

$ grep -niE 'new-service|sc\.exe|nssm|elevat|uac|administrator' scripts/setup.ps1; echo "exit=$?"
exit=1

$ grep -nE 'systemd|launchd' scripts/setup.sh scripts/setup.ps1; echo "exit=$?"
exit=1

$ find . -name '*.service' -o -name '*.plist' -o -name 'launchd*'   (ohne .git)
(keine Ausgabe — im Repo existiert keine Dienst-Datei für irgendeine Plattform)
```

Damit ist Z2 belegt: es gibt im Repo keine Windows-Dienst-Einrichtung, also auch keinen
Schritt, der in der SSH-Sitzung Administratorrechte verlangt; gestartet wird der Prozess
heute an genau einer Stelle (scripts/setup.ps1:262, `Start-Process … -WindowStyle Hidden`),
unter den Rechten der SSH-Sitzung selbst.
