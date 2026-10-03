# Paralelné skenovanie súborov cez FastAPI

## Popis problému

Pri úlohách ktoré každodenne riešime je veľmi často potrebné oskenovať sadu súborov našim detekčným enginom a určitým spôsobom spracovať výstup. Skenovanie je pomerne časovo náročné a preto pre našu prácu potrebujeme rýchle a spoľahlivé riešenie. Náš preferovaný spôsob je použitie nástroja ecls.exe (ESET Command Line Scanner). Keďže súbory skenujeme v mnohých projektoch napísaných v mnohých jazykoch je vhodné mať pre ecls.exe vytvorené rozhranie pre tieto jazyky.

## Zadanie

Napíšte FastAPI serverovú aplikáciu, ktorá bude obsluhovať dva typy požiadaviek:

- oskenovanie jedného súboru (`POST /scanFile`),
- paralelné oskenovanie viacero súborov naraz (`POST /scanMultipleFiles`).

Obe API budú na vstupe očakávať uploadnuté dáta formou multipart/form-data.

Server pri štarte na pozadí spustí niekoľko perzistentných inštancií programu ecls.exe v režime streamovej komunikácie pomocou pipes[^1]. Spúšťanie ecls.exe s každou prichádzajúcou požiadavkou by bolo totiž časovo neefektívne. Smerovanie skenovacích požiadaviek na tieto ecls.exe procesy by malo byť dynamické a paralelné tak, aby skenovanie viacero súborov naraz trvalo čo najkratšie.

Výstup zo samotného ecls.exe spracujte do štruktúry, ktorá bude obsahovať meno súboru, threat, action, info. Položka name by mala byť vo forme zoznamu, ktorý vznikne rozdelením názvu súboru podľa znaku „»“.

Program implementujte v jazyku Python s použitím knižnice FastAPI.

[^1]: V tomto móde komunikácie ecls.exe nedostáva mená súborov na vstup pri spustení, ale na štandardný vstup procesu, pričom výsledok vráti na štandardný výstup procesu. Koniec výstupu je označený reťazcom z argumentu /batch-delimiter. ecls.exe spúšťajte s argumentami `/log-all /stdin-filelist /batch-delimiter=__INPUT_END__`

## Vzorové výstupy

Surový výstup z ecls.exe.

```
ECLS Command-line scanner, version 11.1.65535.0, (C) 1992-2018 ESET, spol. s r.o.
Module loader, version 1018NV (20190619), build 11051
Module perseus, version 1554 (20190718), build 2047
Module scanner, version 65715D (20190722), build 732494
Module archiver, version 1289DNA (20190709), build 11390
Module advheur, version 1193 (20190626), build 1175
Module cleaner, version 1197 (20190711), build 1297
Module pegasus, version 703707 (20190722), build 703707

Command line: /log-all test.zip

Scan started at:   Tue Jul 30 14:45:42 2019
name="test.zip", threat="is OK", action="", info=""
name="test.zip » ZIP » ah_dna.exe", threat="is OK", action="", info=""
name="test.zip » ZIP » ah_dna.ini", threat="is OK", action="", info=""
name="test.zip » ZIP » ecls.exe", threat="is OK", action="", info=""
__INPUT_END__
```

Ukážka očakávaného výstupu API pre skenovanie jedného súboru test.zip cez `POST /scanFile`:

```json
{
    "scan_results": [
        {
            "name": [
                "test.zip"
            ],
            "threat": "is OK",
            "action": "",
            "info": ""
        },
        {
            "name": [
                "test.zip",
                "ZIP",
                "ah_dna.exe"
            ],
            "threat": "is OK",
            "action": "",
            "info": ""
        },
        {
            "name": [
                "test.zip",
                "ZIP",
                "ah_dna.ini"
            ],
            "threat": "is OK",
            "action": "",
            "info": ""
        },
        {
            "name": [
                "test.zip",
                "ZIP",
                "ecls.exe"
            ],
            "threat": "is OK",
            "action": "",
            "info": ""
        }
    ]
}
```

Ukážka očakávaného výstupu API pre skenovanie súboru test2.exe a test.zip cez `POST /scanMultipleFiles`:

```json
{
    "scan_results": [
        {
            "name": [
                "test2.exe"
            ],
            "threat": "is OK",
            "action": "",
            "info": ""
        },
        {
            "name": [
                "test.zip"
            ],
            "threat": "is OK",
            "action": "",
            "info": ""
        },
        {
            "name": [
                "test.zip",
                "ZIP",
                "ah_dna.exe"
            ],
            "threat": "is OK",
            "action": "",
            "info": ""
        },
        {
            "name": [
                "test.zip",
                "ZIP",
                "ah_dna.ini"
            ],
            "threat": "is OK",
            "action": "",
            "info": ""
        },
        {
            "name": [
                "test.zip",
                "ZIP",
                "ecls.exe"
            ],
            "threat": "is OK",
            "action": "",
            "info": ""
        }
    ]
}
```
