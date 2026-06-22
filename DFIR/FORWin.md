
## Chapitre 6 : Forensic Windows (L'Analyse "Host")

### 6.1 La Mine d'Or du Registre Windows

Le registre Windows est une base de données hiérarchisée qui contient tous les paramètres, configurations, et surtout **preuves d'activité** du système.

**Localisation physique :**

```
C:\Windows\System32\config\SAM       (Comptes utilisateur, hashes)
C:\Windows\System32\config\SYSTEM    (Configuration système, services)
C:\Windows\System32\config\SOFTWARE  (Applications installées, polices)
C:\Windows\System32\config\SECURITY  (Audit logs)
C:\Users\[USERNAME]\NTUSER.DAT       (Paramètres utilisateur, MRU)
```

#### **Clés Pertinentes pour Forensics**

**A. Détection de Persistance**

| Clé | Localisation | Preuve |
|-----|-------------|---------|
| **Run** | HKCU\Software\Microsoft\Windows\CurrentVersion\Run | Programme auto-lancé au login |
| **RunOnce** | HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce | Lancé une seule fois |
| **Services** | HKLM\System\CurrentControlSet\Services | Service système lancé au boot |
| **Scheduled Tasks** | HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache | Tâche planifiée |
| **Shell Exec Hooks** | HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows | "load" / "run" keys (obsolète mais possible) |

**Exemple : Malware Persistance Détectée**

```powershell
# Sur registry copié (jamais l'original !)
reg load HKLM\OFFLINE_SAM C:\Evidence\SAM
reg query "HKLM\OFFLINE_SAM"

# Résultat : Encontrar entrée suspecte
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

# Output :
# Windows Registry Editor Version 5.00
# HKCU\Software\Microsoft\Windows\CurrentVersion\Run
#   "WindowsDefender"       REG_SZ  C:\Users\jdoe\AppData\Local\Temp\wdef.exe
#   "UpdateCheck"           REG_SZ  C:\ProgramData\Update\upd.exe
#   (normal entries suppressed)

# ↑ Deux clés suspectes = persistence mechanisms
```

**B. Preuve d'Exécution d'Application**

| Clé | Information |
|-----|-------------|
| **HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU** | Programmes récemment exécutés via Run dialog |
| **HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths** | Chemins tapés dans l'explorateur |
| **HKCU\Software\Microsoft\Office\[VERSION]\[APP]\Recent** | Documents récents ouverts |
| **HKCU\Software\Classes\Local Settings\Software\Microsoft\Internet Explorer\TypedURLs** | URLs visitées (IE ancien) |

**C. Détection de Présence d'Attaquant**

| Clé | Preuve |
|-----|--------|
| **HKLM\SAM** | Hash NTLM de tous les comptes (crack offline) |
| **HKCU\Software\Microsoft\Windows\CurrentVersion\Run \| Services créés | Nouveaux comptes administrateur, services |
| **HKCU\Keyboard Layout\Preload** | Changement de clavier/langue (attaquant Russe ? Chinois ?) |
| **HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell** | Changement shell (cmd.exe vs explorer.exe) |

#### **Extraction & Analyse du Registre**

**Outil 1 : RegRipper (Analyse automatisée)**

RegRipper extrait automatiquement les artefacts pertinents du registre.

```bash
# Installation
sudo apt-get install regrip per

# Utilisation basique
regrip.pl -r NTUSER.DAT -p all | tee results.txt

# Résultat : Sommaire structuré de tous les artefacts
# [userassist] User Assist keys
# Last write: 2024-01-15 14:22:35
# Values extracted...
#   C:\Program Files\Firefox\firefox.exe - 125 exécutions
#   cmd.exe - 3 exécutions
#   C:\Users\jdoe\AppData\Local\Temp\wdef.exe - 1 exécution [SUSPICIOUS]

# RegRipper peut aussi être utilisé en mode plugin :
regrip.pl -r SYSTEM -p services
# Affiche uniquement les services (plus focused)
```

**Outil 2 : Volatility Registry plugin (En mémoire)**

Si RAM dump disponible, faire requête registry en mémoire (preuve absence modification post-factum).

```bash
python3 -m volatility3 -f memory.dump windows.registry.hivescan

# Résultat : Hiches en mémoire + timestamps
# [Registry Hives Found]
# SAM                 0xf80... LastWrite: 2024-01-15 16:25:10
# SYSTEM              0x1ae... LastWrite: 2024-01-15 14:35:22
# NTUSER.DAT          0x2bf... LastWrite: 2024-01-15 15:10:05

# Ensuite interroger une clé spécifique
python3 -m volatility3 -f memory.dump windows.registry.printkey \
  --key "Software\Microsoft\Windows\CurrentVersion\Run"
```
**Tableau de Correspondance des Artefacts Windows & Utilité**

### **Quoi Chercher, Où, et Pourquoi**

| Artefact | Localisation | Valeur Forensique | Cas Typique | Outil d'Extraction |
|----------|-------------|-------------------|------------|------------------|
| **Prefetch** | `C:\Windows\Prefetch\*.pf` | Preuve d'exécution programme, timestamps | "Quand malware a-t-il été lancé ?" | PECmd.exe |
| **ShimCache** | `HKLM\System\CurrentControlSet\...\AppCompatCache` | TOUS les programmes exécutés (même supprimés) | Timeline d'exécution complet | RegRipper, Volatility |
| **Amcache** | `HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Amcache` | Programmes installés, chemins, versions | "Quelles apps malveillantes ont été lancées ?" | AmcacheParser.exe |
| **UserAssist** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` | Compte d'exécution utilisateur (GUI) | "Quel utilisateur a exécuté quoi ?" | RegRipper (ROT-13 decoder) |
| **Recent/LNK** | `C:\Users\[USER]\AppData\Roaming\Microsoft\Windows\Recent\` | Fichiers accédés/ouverts par utilisateur | "Quels documents sensibles ont été lus ?" | LnkParser.exe |
| **Jump Lists** | `C:\Users\[USER]\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` | Fichiers récents ouverts par application | Timeline usage application | JumpListExplorer |
| **ShellBags** | `HKCU\Software\Microsoft\Windows\Shell\BagMRU` | Historique navigation dossiers Explorer | "Quels répertoires réseau visités ?" | ShellBagParser.exe |
| **Run Keys** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Programmes lancés automatiquement au login | Persistance malware | Reg query, RegRipper |
| **Services** | `HKLM\System\CurrentControlSet\Services` | Services système (persistence très puissante) | "Service malveillant installé ?" | sc.exe, RegRipper |
| **Scheduled Tasks** | `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule` | Tâches planifiées (persistence) | "Tâche malveillante planifiée ?" | schtasks.exe, TaskSchedulerParser.exe |
| **NTUSER.DAT** | `C:\Users\[USER]\NTUSER.DAT` | Paramètres utilisateur, MRU, clés exécution | Configuration utilisateur compromise | RegRipper, offline registry analysis |
| **SAM** | `C:\Windows\System32\config\SAM` | Hashes NTLM tous les comptes locaux | Offline crack passwords | hashdump (Volatility), mimikatz |
| **SYSTEM** | `C:\Windows\System32\config\SYSTEM` | Configuration système, services, devices | Persistance, services malveillants | RegRipper |
| **SOFTWARE** | `C:\Windows\System32\config\SOFTWARE` | Applications installées, paramètres globaux | Détection logiciel malveillant | RegRipper |
| **Event Log Security** | `C:\Windows\System32\winevt\Logs\Security.evtx` | Logins (4624), failures (4625), process creation (4688) | Timeline attaquant, lateral movement | Event Viewer, LogParser, PowerShell Get-WinEvent |
| **Event Log System** | `C:\Windows\System32\winevt\Logs\System.evtx` | Services started/stopped, driver load, errors | Système anomalies, service install timing | Event Viewer |
| **Event Log PowerShell** | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell.evtx` | PowerShell script execution, commandes | Fileless malware execution | Event Viewer, PowerShell Get-WinEvent |
| **$MFT** | Master File Table (début volume) | Historique TOUS fichiers (deleted inclus) | Carving deleted files, timestamps | FTK Imager, Encase, Sleuth Kit |
| **$UsnJrnl** | `C:\$Extend\$UsnJrnl:$J` | Journal changements fichiers temps-réel | Timeline précise modifications | PowerShell USN parser, MFTECmd |
| **HOSTS file** | `C:\Windows\System32\drivers\etc\hosts` | Redirection DNS locale (C2 domain spoofing) | "Attaquant a-t-il redirigé traffic ?" | cat, type |
| **Recycle Bin** | `C:\$Recycle.Bin` | Fichiers supprimés par utilisateur | Preuve suppression intentionnelle | Explorer, forensic tools |
| **Alternate Data Streams** | Files with **:Stream** (NTFS) | Hidden data attaché aux fichiers | Malware cache data dans ADS | streams.exe, AlternateStreamParser.exe |
| **Registry Hive Backups** | `C:\Windows\System32\config\RegBack\` | Snapshots anciennes du registry | Comparer avant/après modification | Offline registry tools |
| **MiniDumps** | `C:\Windows\Minidump\` | Application crash dumps | Code injected cause crash → trouvé en dump | WinDbg, Volatility |
| **Temporary Files** | `C:\Users\[USER]\AppData\Local\Temp\` | Fichiers temporaires programmes | Malware souvent dropt ici | File Explorer |
| **ProgramData** | `C:\ProgramData` | Données applications globales (pas user-specific) | Persistence shared entre utilisateurs | File Explorer |
| **Ntfs.sys Log** | MFT journal journal | NTFS transaction log | Detect filesystem corruption/attack | MFTECmd.exe |


### 6.2 Preuves d'Exécution : Prefetch, ShimCache, Amcache, UserAssist

Ces artefacts conservent une trace de quels programmes ont été exécutés, quand, et depuis quel chemin.

#### **Prefetch Files**

**Localisation :** `C:\Windows\Prefetch\*.pf`

**Contenu :** Pour chaque programme exécuté, un fichier `.pf` enregistre :
- Timestamp première & dernière exécution
- Nombre d'exécutions
- Fichiers/DLL chargés
- Ressources disque accédées

**Particularité :** Les 128 exécutions les plus récentes (puis rotation).

**Extraction :**

```powershell
# Copier tous les .pf
Get-ChildItem C:\Windows\Prefetch\*.pf | Copy-Item -Destination C:\Evidence\Prefetch\

# Parser avec Eric Zimmerman PECmd.exe
.\PECmd.exe -d C:\Evidence\Prefetch\ -o C:\Evidence\Prefetch_Results.csv

# Résultat CSV
# SourceFile,ExeFileName,Hash,RunCount,LastRun,Created
# firefox.exe-ABC123.pf,firefox.exe,ABC123,47,2024-01-15 14:22:35,2023-12-01 09:15:20
# cmd.exe-DEF456.pf,cmd.exe,DEF456,3,2024-01-15 13:50:15,2024-01-10 16:20:10
# wdef.exe-GHI789.pf,wdef.exe,GHI789,1,2024-01-15 13:45:22,2024-01-15 13:45:22 [NEW+MALWARE]
```

#### **ShimCache (Application Compatibility Cache)**

**Localisation :** `HKLM\System\CurrentControlSet\Control\Session Manager\AppCompatibility\AppCompatCache`

**Contenu :** Liste de TOUS les programmes exécutés depuis dernier boot, avec :
- Chemin complet
- Taille fichier
- Modification time
- Execution flag (yes/no)

**Extraction :**

```powershell
# Via RegRipper
regrip.pl -r SYSTEM -p shimcache

# Résultat
[shimcache]
LastWrite: 2024-01-15 16:30:22

Entries (most recent first):
 Path: C:\Users\jdoe\AppData\Local\Temp\wdef.exe
  Last Modified (file): 2024-01-15 13:44:50
  Last Modified (registry): 2024-01-15 13:45:22
  Execution Flag: YES [EXECUTED]
  Size: 156288
```

#### **Amcache**

**Localisation :** `HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Amcache`

**Contenu :** Plus complet que ShimCache, enregistre :
- Program name, version, publisher
- Fichiers exécutés même si supprimés ultérieurement
- Chemins d'installation d'applications

**Utilité :** Identifier programmes malveillants même s'ils ont été supprimés.

**Extraction :**

```powershell
# Via Amcache parser (Eric Zimmerman)
.\AmcacheParser.exe -f "C:\Evidence\Amcache.hve" -o "C:\Evidence\Amcache_parsed.csv"

# Résultat
# FileID,LongPathHash,FileName,Version,FileSize,ProgramName,Publisher
# ABC123,456def,wdef.exe,1.0.0.0,156288,Windows Defender,Unknown
# DEF456,789ghi,powershell.exe,10.0.19041,448512,PowerShell,Microsoft Corporation
# GHI789,012jkl,cmd.exe,10.0.19041,338944,Command Prompt,Microsoft Corporation
```

#### **UserAssist**

**Localisation :** `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\[GUID]`

**Contenu :** Compteur d'exécutions pour chaque programme lancé depuis le menu Start/Explorer.

**Particularité :** Encodé en ROT-13 (obfuscation légère).

**Extraction :**

```powershell
# Via PowerShell décodeur
function Decode-UserAssist {
    param([string]$input)
    $rot13 = $input -replace '.', { 
        $c = [char]$_
        if ([char]::IsLetterOrDigit($c)) {
            if ($c -lt [char]'N') { [char]($c + 13) }
            else { [char]($c - 13) }
        } else { $c }
    }
    return $rot13
}

# Lire registry
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /s

# Résultat (codé en ROT-13)
# ...
# HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}

# Après décodage :
# firefox.exe - 47 exécutions
# cmd.exe - 3 exécutions
# wdef.exe - 1 exécution [SUSPECT]
```

> **Note du terrain** : Prefetch + ShimCache + Amcache = triple confirmation qu'un programme a été exécuté. Si les trois sources concordent, c'est irréfutable.

---

### 6.3 Preuves d'Accès aux Fichiers : LNK Files, Jump Lists, ShellBags

#### **LNK Files (Raccourcis)**

**Localisation :** 
- `C:\Users\[USERNAME]\AppData\Roaming\Microsoft\Windows\Recent\` (tous les fichiers ouverts)
- `C:\Users\[USERNAME]\Desktop\` (raccourcis bureau)

**Contenu :** Pour chaque fichier ouvert/accédé :
- Chemin complet original
- Horodatage d'accès
- Taille du fichier
- Informations sur la machine source

**Utilité :** Prouver qu'un utilisateur a accédé à un document sensible.

**Extraction :**

```powershell
# Eric Zimmerman LnkParser.exe
.\LnkParser.exe -d "C:\Evidence\Recent" -o "C:\Evidence\LNK_Results.csv"

# Résultat
# SourceFile,TargetFileName,TargetCreated,TargetModified,TargetAccessed
# ....\AppData\Roaming\Microsoft\Windows\Recent\Document1.docx.lnk
#  C:\Users\jdoe\Documents\CONFIDENTIAL\Document1.docx,
#  2024-01-10 10:22:15,2024-01-15 14:35:22,2024-01-15 14:35:22
# [PREUVE : utilisateur a accédé à fichier CONFIDENTIEL le 15 janvier à 14h35]
```

#### **Jump Lists**

**Localisation :** `C:\Users\[USERNAME]\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`

**Contenu :** Pour chaque application (Word, Explorer, etc.), enregistre les fichiers/dossiers récemment utilisés.

**Utilité :** Mêmes que LNK mais plus structuré par application.

**Extraction :**

```powershell
# JumpListExplorer (free tool)
# Ou via PowerShell avec WinRT

# Parser custom
Get-ChildItem "C:\Users\jdoe\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" |
  ForEach-Object {
    $file = $_.FullName
    # Parse binary file (OLE compound format)
    # Extraction manuelle complexe, utiliser tool
  }
```

#### **ShellBags**

**Localisation :** `HKCU\Software\Microsoft\Windows\Shell\BagMRU` et `HKCU\Software\Microsoft\Windows\Shell\Bags`

**Contenu :** Historique de tous les dossiers ouverts dans l'Explorateur Windows, avec timestamps et taille fenêtre.

**Utilité :** Timeline de navigation utilisateur.

**Extraction :**

```powershell
# ShellBagParser (Eric Zimmerman)
.\ShellBagParser.exe -b "C:\Evidence\Bags" -o "C:\Evidence\ShellBags.csv"

# Résultat
# ParentFolder,Folder,DateModified,DateAccessed
# C:\Users\jdoe\,Desktop,2024-01-15 09:00:22,2024-01-15 16:30:15
# C:\Users\jdoe\,Documents,2024-01-15 09:15:22,2024-01-15 14:35:22
# C:\,ProgramFiles,2024-01-15 13:50:15,2024-01-15 13:52:30 [SUSPICIOUS TIME]
# C:\Windows\,System32,2024-01-15 14:20:30,2024-01-15 14:25:30 [ATTACKER ACCESSING SYSTEM]
```

---

### 6.4 Analyse des Journaux d'Événements (Evtx)

#### **Event Logs Clés pour la Sécurité**

Le Windows Event Log enregistre tous les événements système/sécurité/application.

**Fichiers localisés :**

```
C:\Windows\System32\winevt\Logs\
├─ Security.evtx        [Logins, audit, policy changes]
├─ System.evtx          [Driver, service, kernel events]
├─ Application.evtx     [Software errors]
└─ PowerShell.evtx      [PowerShell script execution]
```

#### **Event IDs Critiques pour Forensics**

| Event ID | Source | Preuve |
|----------|--------|--------|
| **4624** | Security | Logon successful |
| **4625** | Security | Logon failure (brute force) |
| **4688** | Security | Process creation |
| **4689** | Security | Process terminated |
| **4720** | Security | User account created |
| **4722** | Security | User account enabled |
| **4724** | Security | User password reset |
| **4732** | Security | Local group member added |
| **4738** | Security | User account changed |
| **5140** | Security | Network share accessed |
| **5145** | Security | Network share file accessed |

#### **Extraction & Analyse**

**Outil 1 : Event Log Parser (Plaso)**

```bash
# Plaso = Plurabus Lanium Automationis Superiendi Ordo
# Tool SANS pour parser tous les logs et créer timeline

plaso_runner.py -o dynamic memory.dump evtx_files/ output.plaso

# Créer timeline CSV
psort.py output.plaso -o dynamic > timeline.csv

# Résultat
# Date,Time,Timezone,Message,Source,Source Type,Type,User,Computer,Filename
# 2024-01-15,14:32:15,UTC,Logon success,Security,4624,Login,SYSTEM,WORKSTATION01,Security.evtx
# 2024-01-15,14:33:22,UTC,Process Create,Security,4688,Execution,jdoe,WORKSTATION01,Security.evtx
#  Command: C:\Users\jdoe\AppData\Local\Temp\wdef.exe
# 2024-01-15,14:35:15,UTC,Logon failure,Security,4625,Login Attempt,SYSTEM,WORKSTATION01,Security.evtx
#  Source IP: 45.133.xxx.xxx [BRUTE FORCE SOURCE]
```

**Outil 2 : Event Log XML Parsing (PowerShell)**

```powershell
# Importer les logs
Get-WinEvent -Path "C:\Evidence\Security.evtx" -FilterXPath "*[System[EventID=4624]]" |
  Select-Object TimeCreated, Properties |
  Where-Object { $_.Properties[18] -eq "10.0.0.50" } |
  Export-Csv logons_from_10_0_0_50.csv
```
