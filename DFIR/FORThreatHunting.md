## Chapitre 10 : Threat Hunting et Rétro-Ingénierie de Malwares

### 10.1 Recherche Proactive via Frameworks MITRE ATT&CK

#### **MITRE ATT&CK : La Bible du Tactique Attaquant**

MITRE ATT&CK est une matrice de techniques documentées utilisées par vrais attaquants.

**Structure :**

```
TACTICS (Phases d'attaque) :
├─ Reconnaissance (gathering info)
├─ Resource Development (outils, infrastructure)
├─ Initial Access (premier accès)
├─ Execution (lancer code)
├─ Persistence (rester après reboot)
├─ Privilege Escalation (admin rights)
├─ Defense Evasion (cacher traces)
├─ Credential Access (voler passwords)
├─ Discovery (cartography réseau)
├─ Lateral Movement (spread dans réseau)
├─ Collection (voler données)
├─ Command & Control (communications)
├─ Exfiltration (sortir données)
├─ Impact (sabotage)

TECHNIQUES : Méthodes précises pour chaque tactic
└─ Ex: T1548 (Privilege Escalation)
        ├─ Abuse Elevation Control Mechanism
        ├─ UAC bypass techniques
        └─ Token impersonation
```

#### **Threat Hunting Baseado em ATT&CK**

Concept : Chercher "indicators of compromise" (IoC) alignés sur ATT&CK.

**Exémple Hunting Playbook :**

```
[HUNTING: Lateral Movement via Pass-the-Hash]
TTactic: Lateral Movement (T1570)
Technique: Pass the Hash (T1550.002)

Hypothèse : Attaquant a les NT hashes (lsass dump)
           et les utilise pour créer sessions SMB vers serveurs

Hunting steps:

1. SIEM Query : Chercher connexions SMB anormales
   Event ID 5140 (Network share accessed)
   + Event ID 4720 (New user created)
   = Timing proximity = suspicious
   
2. Look for :
   - Administrator logons hors heures normales
   - Lateral movement : source IP interne → destination interne
   - Destination : Serveurs sensibles (Domain Controllers, databases)
   - Source : Endpoint normally non-admin
   
3. Query Splunk/ELK:
   sourcetype=WinEventLog:Security EventID=4720 OR EventID=5140
   | stats count by src_ip, dest_ip, user
   | where src_ip != dest_ip
   | lookup threat_intel src_ip OUTPUT threat_level
   
4. Résultat si positif:
   - Identifie source compromise
   - Priorité forensics sur ce endpoint
   - Bloc ACL firewall immédiat
```

#### **Mapping Incident vers ATT&CK**

Quand incident detected, mapper vers ATT&CK pour :
- Comprendre attaque globale
- Identifier missing steps (ex: si lateral movement seen, chercher persistence antérieure)
- Predict étapes suivantes

**Exémple : Emotet Infection Mapped to ATT&CK :**

```
T1598 - Phishing (Initial Access)
  └─ Email avec lien malveillant, used = email cible

T1005 - Data from Local System (Collection)
  └─ Emotet lit adresse book pour propager

T1570 - Lateral Movement over SMB
  └─ Emotet propage vers autres machines via shares

T1025 - Data from Removable Media
  └─ Cherche USB/disques externes pour infection

T1052 - Exfiltration over Alternative Protocol
  └─ Envoie données via HTTP aux serveurs C2

T1104 - Multi-stage Channels
  └─ Utilise multiple C2 serveurs
```

---

### 10.2 Analyse Comportementale de Malwares (Sandboxing)

#### **Sandbox : Environment Contrôlé pour Détoner Malware**

Sandbox = Machine virtuelle isolée où exécuter malware sans risque.

**Processus :**

```
[Suspicious binary found]
     ↓
[Upload to sandbox]
     ↓
[VM isolée boot, execute malware]
     ↓
[Monitor : Fichiers modifiés, network connections, registry changes]
     ↓
[Malware se comporte (dropt files, contact C2, etc)]
     ↓
[Report : API calls, dropped files, network IOCs]
     ↓
[Safe : VM destroyed après analyse]
```

**Sandboxes Public (Gratuit) :**

- **VirusTotal** (virustotal.com) - 90+ moteurs antivirus, report gratuit
- **Hybrid Analysis** (hybrid-analysis.com) - Comportemental détaillé
- **Any.run** (any.run) - Interaction en temps réel

**Exemple VirusTotal Report :**

```
File : wdef.exe
Hash : 8846f7eaee8fb117ad06bdd830b7586c (MD5)

Detection : 91/92 vendors
    ├─ Kaspersky : Trojan.Win32.Emotet.r!c
    ├─ McAfee : Trojan-Emotet
    ├─ Symantec : Trojan.Emotet!C1A
    └─ (88 autres positifs)

Behavior : (Résumé)
    ├─ Creates 23 files
    │   └─ C:\Windows\Temp\payload.exe (main loader)
    │   └─ C:\ProgramData\update\upd.exe (persistence)
    ├─ Makes 156 registry modifications
    │   └─ HKCU\Software\...\Run\WindowsDefender
    ├─ Makes 5401 network connections
    │   └─ 45.133.xxx.xxx:443 (C2 server)
    │   └─ 185.220.xxx.xxx:8443 (Backup C2)
    └─ Injects into 4 processes
        └─ explorer.exe
        └─ svchost.exe
        └─ dwm.exe
        └─ lsass.exe

IOCs extracted:
    - C2 servers : 45.133.xxx.xxx, 185.220.xxx.xxx, ...
    - Dropped files : payload.exe, upd.exe, ...
    - Registry keys : Run keys, Services, ...
    - Network signatures : DNS queries, SSL certs, ...
```

---

### 10.3 Création et Déploiement de Règles de Détection (YARA, Sigma)

#### **YARA : Pattern Matching pour Malwares**

YARA est un langage de règles pour identifier et classer malwares par patterns.

**Syntaxe YARA :**

```yara
rule Emotet_Malware {
    meta:
        description = "Emotet banking trojan"
        author = "CERT"
        date = "2024-01-15"
        ref = "https://www.cert.fr/..."
    
    strings:
        // Signatures binaires (hex patterns)
        $hex1 = { 55 8B EC 83 EC 20 56 57 }  // Prologue x86
        $hex2 = { 48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? FF 15 }  // RIP-relative addressing
        
        // Signatures de chaînes de caractères
        $str1 = "C2_SERVER_ADDRESS"
        $str2 = "Bot_Token"
        $str3 = "Exfil_Data"
        
        // Regex patterns
        $regex1 = /cmd\.exe \/c (powershell|msiexec|certutil)/ nocase
        $regex2 = /(http|https):\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{4,5}/ // C2 IP
    
    condition:
        // Detection logic
        uint16(0) == 0x5A4D and                    // MZ (PE header)
        (any of ($hex*)) and                       // Binaire match
        (any of ($str*)) and                       // String match
        (any of ($regex*)) and                     // Regex match
        filesize > 100KB and filesize < 1MB        // Taille fichier
}
```

**Utilisation :**

```bash
# Scan répertoire avec règles YARA
yara -r emotet_rules.yar /home/user/

# Résultat
wdef.exe : Emotet_Malware MATCH
payload.exe : Emotet_Malware MATCH
innocent_file.txt : [no match]

# Scan avec output JSON
yara -r -j emotet_rules.yar / > yara_results.json

# Parser résultats
jq '.[] | select(.matches | length > 0)' yara_results.json
```

#### **Sigma : Règles de Détection pour SIEM**

Sigma convertir log patterns en règles SIEM (Splunk, ELK, etc).

**Sigma Rule Example :**

```yaml
title: Emotet PowerShell Execution
logsource:
    product: windows
    service: security
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'powershell'
            - 'bypass'
            - 'IEX'  # Invoke-Expression
            - 'DownloadString'  # Typical C2 loader
        Image|endswith: 'powershell.exe'
        ParentImage|endswith:
            - 'explorer.exe'
            - 'winlogon.exe'
            - 'outlook.exe'  # Email-based infection
    filter:
        User: SYSTEM  # Exclude legitimate system processes
    condition: selection and not filter
falsepositives:
    - System administrators running PowerShell legitimately
level: high
```

**Conversion Sigma → Splunk :**

```
sigma convert emotet.yml -t splunk

# Résultat Splunk search:
index=security 
  (process_name=powershell.exe) 
  (command_line="*bypass*" OR command_line="*IEX*" OR command_line="*DownloadString*")
  (parent_process="explorer.exe" OR parent_process="winlogon.exe" OR parent_process="outlook.exe")
  user != SYSTEM
```
