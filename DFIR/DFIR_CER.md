## Chapitre 4 : Confinement, Éradication et Résilience (Phases 3 & 4)

### 4.1 Stratégies de Confinement (Réseau, Comptes, Processus)

#### **Confinement Réseau (Network Isolation)**

L'objectif du confinement réseau est d'empêcher la propagation d'une menace sans arrêter le système (préserver mémoire + logs).

**Niveaux de confinement :**

| Niveau | Technique | Vitesse | Impact | Perte de données |
|--------|-----------|---------|--------|------------------|
| **Complet** | Dépluger câble réseau | <10 sec | Fort (métier arrêté) | Possible |
| **VLAN Isolé** | Déplacer switch port vers VLAN quarantine | 1-2 min | Moyen | Faible si correct |
| **ACL Firewall** | Bloquer trafic sortant, autoriser logs | <30 sec | Faible | Très faible |
| **NAT Transparente** | Rediriger vers "sink hole" server | <1 sec | Minimal | Aucune |

#### **Pratique 1 : Isolation ACL Firewall (Préféré pour Forensics)**

Idéal car permet la collecte de logs continue tout en bloquant l'attaque.

```
[FIREWALL CONFIG - Isoler compromission sans arrêt]

Endpoint : 192.168.10.50 (Workstation infectée)

Règles à déployer :

1. Bloquer sortie C2
   Deny IP 192.168.10.50 any 45.133.0.0/16 any
   Deny IP 192.168.10.50 any 185.220.0.0/16 any  (connu Tor exit)

2. Autoriser infra locale
   Allow IP 192.168.10.50 192.168.10.1 (gateway)
   Allow IP 192.168.10.50 192.168.10.100 (SIEM log collector)

3. Autoriser seulement HTTP/HTTPS pour updates
   Allow TCP 192.168.10.50 0.0.0.0 80 (restriction IP stricte)
   Allow TCP 192.168.10.50 0.0.0.0 443 (restriction IP stricte)

4. Nier tout autre
   Deny IP 192.168.10.50 any any

Temps d'implémentation : <2 minutes
Logs collectés pendant : Oui
Métier impacté : Minimal (dépend des services)
Forensics possible : Oui, system on
```

#### **Pratique 2 : Isolation VLAN (Maximum de Sécurité)**

Pour menaces très sophistiquées ou multi-système.

```
[NETWORK DIAGRAM]

Avant confinement :
━━━━━━━━━━━━━━
Production VLAN (10.0.0.0/24)
├─ Workstation 10.0.0.50 [INFECTED]
├─ Workstation 10.0.0.51
├─ Server 10.0.0.100
└─ Database 10.0.0.150

Après confinement :
━━━━━━━━━━━━━
Production VLAN (10.0.0.0/24) - Workstation 10.0.0.51, Server, Database
               ↓
Quarantine VLAN (172.16.50.0/24) - Workstation 10.0.0.50 replié
               ↓
SOC VLAN (172.16.51.0/24) - Collecte forensique

Configuration switch:
```

**Commandes de déplacement VLAN (Cisco/Juniper) :**

```
[Cisco Switch]
configure terminal
interface Gi0/1
  (port connecté à workstation infectée)
switchport access vlan 50
exit

[Appliquer mapping ACL stricte entre VLAN - voir pare-feu]
```

#### **Confinement de Compte (Account Containment)**

Quand la compromission est limitée à un compte ou un utilisateur.

**Actions immédiates :**

```powershell
# 1. Révoquer toutes les sessions de ce compte
# Sur DC (Domain Controller)

# Identifier sessions actives
wmic logicalsession list
Get-LoggedInUser | Where-Object { $_.UserName -eq 'DOMAIN\jdoe' }

# Terminer toutes les sessions
# (Alternative : Reset password change PDC)
Get-RDPSession | Where-Object { $_.UserName -eq 'DOMAIN\jdoe' } |
  Disconnect-RDPSession -Force

# 2. Changer password immédiatement
# Via GUI ADUC ou CLI :
Set-ADAccountPassword -Identity jdoe -NewPassword `
  (ConvertTo-SecureString -AsPlainText "NewP@ssw0rd123!" -Force) -Reset

# 3. Ajouter flag "User must change password at next logon"
Set-ADUser -Identity jdoe -ChangePasswordAtLogon $true

# 4. Désactiver MFA temporairement (si MFA = SMS/call)
# puis forcer réauthentification au prochain logon
# (Attention : balance securité vs usabilité)

# 5. Révoquer PAT/API keys si développeur
# Via GitHub/AWS/Azure portals
```

#### **Confinement Processus (Process Containment)**

À utiliser quand le système reste critique et opérationnel.

**Via EDR :**

```
[CrowdStrike / Microsoft Defender]

Kill processus malveillant :
Falcon Respond > Contain > Terminate Process
  Process: powershell.exe (PID 4532)
  Justification: Emotet C2 communication detected
  Confirm: YES

Résultat : Processus tué en < 1 seconde, les artefacts en RAM et disque sont conservés
```

**Via PowerShell :**

```powershell
# Identifier processus suspect
Get-Process | Where-Object { $_.ProcessName -eq "notepad" -and $_.Handles -gt 200 }

# Tuer processus (attention : ordre irréversible)
Stop-Process -Name "notepad" -Force
Get-Process notepad | Stop-Process -Force

# Vérifier que tué
Get-Process notepad -ErrorAction SilentlyContinue
```

> **Alerte sécurité** : Tuer un processus sans dump RAM préalable détruit des preuves. Toujours dumper RAM AVANT de tuer si investigation légale envisagée.

---

### 4.2 L'Art du Live Triage : Collecte d'Urgence sur un Système en Cours d'Exécution

#### **Concept & Ordre de Priorité**

Le Live Triage est la collecte rapide d'artefacts volatiles avant arrêt/reboot du système.

**Ordre de collection (la volatilité s'impose) :**

```
[PRIORITY 1 - Microsecondes] Dump RAM
                             ↓
[PRIORITY 2 - Secondes] État réseau, processus, handles
                        ↓
[PRIORITY 3 - Minutes] Fichiers système critiques, logs
                       ↓
[PRIORITY 4 - Heures] Disque complet (bit-stream image)
```

#### **Outils de Live Triage Windows**

**Outil 1 : KAPE (Kroll Artifact Parser and Extractor)**

KAPE est l'outil industry-standard pour triage Windows rapide. Il compile automatiquement les artefacts critiques.

**Installation & exécution :**

```powershell
# Télécharger depuis kapetriage.com
# Placer sur clé USB bootable ou accès réseau

cd C:\kape

# Mode SANS Triage (collection rapide, ~50 artefacts clés)
.\kape.exe -m SANS_TRIAGE --tdest C:\Evidence\Triage_20240115

# Pendant l'exécution, KAPE collecte :
# - Registre Windows (SAM, SYSTEM, SOFTWARE, NTUSER)
# - Event Logs (Security, System, Application)
# - Prefetch files
# - LNK files
# - MFT (Master File Table)
# - Browser history
# - Scheduled tasks
# - Network configuration

# Résultat = Dossier avec timestamp SHA256 d'intégrité
# Durée typique : 2-5 minutes selon disque
```

**Output KAPE :**

```
C:\Evidence\Triage_20240115\
├─ $Boot
├─ C_Drive
│   ├─ Users
│   │   └─ jdoe
│   │       ├─ NTUSER.DAT
│   │       ├─ AppData\Local\Microsoft\Windows\UsrClass.dat
│   │       └─ AppData\Roaming\...
│   ├─ Windows\System32
│   │   ├─ config\SAM
│   │   ├─ config\SYSTEM
│   │   ├─ winevt\Logs\...
│   │   └─ drivers\etc\hosts
│   └─ ProgramData
├─ Execution
├─ Persistence
├─ RecycleBin
└─ kape_targets.tkape

[Hash verification file]
KAPE_Integrity_20240115_1432.sha256
```

**Outil 2 : WinPmem (Memory Acquisition)**

```powershell
# Télécharger WinPmem depuis rekall-project.github.io
# Minimal : exécutable seul, pas de dépendances

# Dump RAM complète
.\winpmem_3.3_x64.exe memory.dump

# Résultat : memory.dump = image complète de la RAM
# Taille : égal à la RAM physique (8GB = 8GB fichier)
# Durée : 30 sec - 2 min selon vitesse disque

# Vérifier intégrité
certutil -hashfile memory.dump SHA256
```

**Outil 3 : DFIR-Toolkit (Powershell Scripts)**

Script PowerShell complets pour triage sans dépendances externes.

```powershell
# Live collection script
# Exécuter sur l'endpoint compromise

Write-Host "=== LIVE TRIAGE COLLECTION ===" -ForegroundColor Green
$basePath = "C:\LiveTriage_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
mkdir $basePath

# 1. DUMP RAM
Write-Host "Dumping RAM..."
.\winpmem_x64.exe "$basePath\memory.dump"

# 2. NETWORK STATE
Write-Host "Collecting network state..."
netstat -anob | Out-File "$basePath\netstat.txt"
Get-NetTCPConnection -State Established | Out-File "$basePath\tcpconnections.txt"
arp -a | Out-File "$basePath\arp.txt"

# 3. PROCESS LIST
Write-Host "Collecting running processes..."
Get-Process | Select-Object Name, ID, Path, CommandLine |
  ConvertTo-Csv | Out-File "$basePath\processes.csv"

# 4. REGISTRY HIVES (User & System)
Write-Host "Collecting registry..."
Copy-Item "C:\Windows\System32\config\SAM" "$basePath\SAM"
Copy-Item "C:\Windows\System32\config\SYSTEM" "$basePath\SYSTEM"
Copy-Item "C:\Windows\System32\config\SOFTWARE" "$basePath\SOFTWARE"
Copy-Item "C:\Windows\System32\config\SECURITY" "$basePath\SECURITY"

# 5. EVENT LOGS
Write-Host "Collecting event logs..."
Get-WinEvent -LogName "Security" -MaxEvents 10000 |
  Export-Csv "$basePath\EventLog_Security.csv" -NoTypeInformation

# 6. DISK STATE
Write-Host "Collecting MFT..."
.\AnalyzeMFT.py C: "$basePath\MFT.csv"

# 7. ZIP & HASH
Write-Host "Packaging and hashing..."
Compress-Archive -Path $basePath -DestinationPath "$basePath.zip"
certutil -hashfile "$basePath.zip" SHA256 | Out-File "$basePath\HASH.txt"

Write-Host "Live triage complete: $basePath" -ForegroundColor Green
```

#### **Live Triage Linux**

Sur Linux, les outils sont similaires mais basés sur les standards Unix.

```bash
#!/bin/bash
# Live triage script Linux

TRIAGE_DIR="/tmp/triage_$(date +%Y%m%d_%H%M%S)"
mkdir -p $TRIAGE_DIR

echo "[+] Dumping RAM..."
sudo dd if=/dev/mem of=$TRIAGE_DIR/memory.dump bs=1M

echo "[+] Network connections..."
sudo netstat -anop > $TRIAGE_DIR/netstat.txt
sudo ss -anop > $TRIAGE_DIR/ss.txt

echo "[+] Process information..."
ps auxww > $TRIAGE_DIR/ps.txt
sudo lsof -i -P -n > $TRIAGE_DIR/lsof.txt

echo "[+] Logged in users..."
w > $TRIAGE_DIR/w.txt
sudo last > $TRIAGE_DIR/last.txt

echo "[+] System logs..."
sudo journalctl --no-pager -n 50000 > $TRIAGE_DIR/journalctl.txt
sudo tail -c 1000M /var/log/syslog > $TRIAGE_DIR/syslog_recent.log

echo "[+] Mounted filesystems..."
mount > $TRIAGE_DIR/mount.txt
df -h > $TRIAGE_DIR/df.txt

echo "[+] Hash all collected data..."
cd $TRIAGE_DIR
find . -type f -exec sha256sum {} + > ../SHA256_MANIFEST.txt

echo "[+] Triage complete: $TRIAGE_DIR"
```

#### **Scénario Réel : Live Triage Pendant Ransomware**

```
[SCENARIO] Ransomware Wannacry détecté 14:32 UTC
           Server DB production (Windows 2016)
           Action rapide nécessaire

Timeline :
━━━━━━━━━━━━━━
14:32 - Alerte ransomware, équipe alertée
14:33 - Analyste accède au serveur (RDP depuis SOC)
14:34 - Lance KAPE sur disque C: pour triage
        └─ KAPE s'exécute pendant confinement
14:36 - Télécharge WinPmem, dump RAM 32GB
        └─ Dump prend 2 min, fichier 32GB transféré
14:39 - Arrête les processus WinRar qui chiffrent
        └─ taskkill /F /IM WinRar.exe
14:40 - Isole serveur réseau (ACL firewall)
14:42 - Arrête l'application métier proprement
14:45 - Premier rapport d'état : ransomware stoppée, données partiellement sauvées

Parallel actions :
14:37 - Analyste T2 lance Volatility sur memory.dump
        └─ Identifie persistence : registry run key pointant vers \Temp\payload.exe
14:38 - Cherche hash du payload en VirusTotal
        └─ Match = WannaCry variant (patch MS17-010 missing)
14:40 - Escalade : Infrastructure/Patch management doit
        └─ Identifier tous serveurs non-patchés

Post-incident :
15:30 - KAPE triage + memory.dump + artefacts transférés vers workstation forensique
16:00 - Analyse complète : vecteur = RDP bruteforce, persistence = registry run key
```

> **Note du terrain** : La qualité du live triage détermine 80% de la qualité forensique ultérieure. Prendre 5 minutes de plus pour bien collecter = économiser 20 heures d'analyse ultérieure.

---

### 4.3 Éradication des Menaces et Remédiation

#### **Processus d'Éradication Structuré**

L'éradication n'est pas "réinstaller et repartir". Elle demande vérification méthodique que la menace est complètement éliminée.

**Phase 1 : Suppression de la menace directe (24h)**

```
Objectif : Supprimer tous les fichiers/processus malveillants identifiés

Actions :
├─ Supprimer payload binaire (vérifier aucun shadow copy)
├─ Supprimer persistence (registry keys, scheduled tasks, services)
├─ Supprimer compte de backdoor créé
├─ Vérifier suppression via comparaison forensique pré/post
└─ Logs d'actions : qui, quoi, quand, pourquoi
```

**Exemple : Éradication de Persistence Registry**

```powershell
# 1. Identifier entries malveillants
# À partir du rapport Volatility ou KAPE

reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

# Résultat typique :
# HKCU\Software\Microsoft\Windows\CurrentVersion\Run
#   "WindowsDefender" REG_SZ C:\Windows\Temp\wdef.exe [MALWARE]
#   "UpdateCheck" REG_SZ C:\ProgramData\Update\upd.exe [MALWARE]

# 2. Supprimer entités malveillants (backuper avant)
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" run_backup.reg

reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefender" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "UpdateCheck" /f

# 3. Vérifier suppression
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

# 4. Documenter pour chaîne de custodie
echo "Malware persistence removed - Run keys deleted - $(date)" >> eradication_log.txt
```

**Phase 2 : Vérification d'Absence de Persistence (72h)**

```
Objectif : Confirmer que le malware ne revient pas après démarrage

Actions :
├─ Monitoring EDR/comportement 72h minimum
├─ Recherche artefacts secondaires (dropper, packer stub)
├─ Vérification Shadow Copies / VSS (malware peut s'y cacher)
├─ Scan antivirus full-system (après mise à jour signatures)
└─ Comparaison baseline pré-intrusion vs post-éradication
```

#### **Nettoyage Active Directory (Cas Domaine Compromise)**

Si le compte administrateur était compromis, il faut considérer l'AD comme compromis.

```powershell
# SCÉNARIO : Compte administrateur Emotet compromise pendant 3 jours

# 1. Audit complet des changements faits par compte
Get-ADUser administrateur -Properties lastLogonDate, PasswordLastSet

# 2. Chercher comptes fantômes créés
Get-ADUser -Filter { Created -gt "2024-01-10" } -Properties Created, CreatedBy |
  Where-Object { $_.CreatedBy -like "*administrateur*" }

# Résultat attendu (exemples suspects) :
# SamAccountName: BackupUser2024
# Created: 2024-01-12
# CreatedBy: DOMAIN\administrateur [SUSPECT - créé par compte compromise]

# 3. Supprimer comptes suspects
Remove-ADUser -Identity BackupUser2024 -Confirm

# 4. Reset password ALL administrateurs
Get-ADGroupMember -Identity "Domain Admins" | 
  ForEach-Object {
    Set-ADAccountPassword -Identity $_.Name -NewPassword `
      (ConvertTo-SecureString -AsPlainText "TempP@ss123!" -Force) -Reset
  }

# 5. Forcer logoff + re-authentification
# Via GPO : "Interactive logon: Machine inactivity limit"
# Ou manuel : logoff tous les administrateurs connectés

# 6. Invalider les KRBTGT tokens (si très serious)
# Attention : opération EXTRÊMEMENT dangereuse
# Invalidate-KrbTgtPassword -Domain corp.local

# 7. Audit des modifications AD (event log 5136)
Get-EventLog -LogName "Directory Service" -InstanceId 5136 -After (Get-Date).AddDays(-5) |
  Where-Object { $_.Message -like "*administrateur*" } |
  Select-Object -First 20 | Format-Table
```

> **Alerte sécurité** : L'invalidation du KRBTGT token cassera TOUS les Kerberos tickets en cours - tous les utilisateurs devront se reconnecter. À faire uniquement en cas d'APT confirmée et avec CIO approval.

#### **Remédiation Infrastructure (Long Terme)**

Éradication != Remédiation. La remédiation corrige les failles qui ont permis l'intrusion.

**Tableau de remédiation post-incident :**

| Faille | Cause Racine | Remédiation | Timeline | Propriétaire |
|--------|-------------|-------------|----------|-------------|
| RDP bruteforce réussi | Pas de MFA, politique mdp faible | Déployer MFA (Duo/Azure), policy 14+ chars | 30 jours | Infra |
| Vulnérabilité non-patchée | Processus de patch manquant | WSUS automatique, SLA 14 jours critiques | 14 jours | Patch Mgmt |
| Malware non-détecté 3j | EDR peu sensible | Retuner détections, ajouter YARA custom | 7 jours | SOC |
| Logs non-centralisés | SIEM config manquante | Ajouter source, configurer règles | 7 jours | SOC/Infra |

---

### 4.4 Retour d'Expérience et Rapport d'Incident

#### **Lessons Learned : Processus et Format**

Le "Lessons Learned" ou "Post-Incident Review" doit se faire 2-4 semaines après clôture opérationnelle.

**Participants requis :**

```
├─ CISO / Responsable sécurité
├─ Équipe IR/Forensics
├─ IT Operations (qui a exécuté remédiation)
├─ Compliance/Legal (s'il y a implications)
└─ Métier impacté (pour impact assessment)
```

**Agenda typique (2-3h) :**

```
[0:00-0:15] Timeline récapitulative
  "Détection 14:32, isolement 14:40, confirmation 15:20, éradication 18:00"

[0:15-0:45] Qu'est-ce qui s'est bien passé ?
  ✓ Détection rapide via EDR
  ✓ Escalade appropriée
  ✓ Confinement efficace sans impact métier majeur
  ✓ Documentation complète

[0:45-1:30] Qu'est-ce qui s'est mal passé ?
  ✗ Délai MFA manquante (RDP bruteforce possible)
  ✗ Logs non-centralisés (perte d'evidence du premier accès)
  ✗ Runbook incomplet (30 min gaspillées à trouver contact ANSSI)
  ✗ Pas de backup externalisé (risk total perte données)

[1:30-2:00] Actions correctives & propriété
  Tableau RACI avec owner, deadline, SLA suivi

[2:00-3:00] Débriefing technique approfondi (séparé)
  Analyse forensique détaillée, TTPs identifiées
```

#### **Rapport d'Incident Complet**

Le rapport d'incident est le document archivé qui scelle l'investigation légalement.

**Structure obligatoire :**

```markdown
# RAPPORT D'INCIDENT
## Case-2024-001 : Intrusion Emotet

### RÉSUMÉ EXÉCUTIF
- **Dates** : 15-20 Janvier 2024
- **Sévérité** : HIGH (pas d'exfiltration confirmée)
- **Vecteur** : RDP bruteforce, compte administrateur
- **Impact** : 3 serveurs infectés, 0 données compromises
- **Statut** : Éradiqué et validé

### TIMELINE DÉTAILLÉE
- **14:32 UTC** - Alerte EDR "Emotet C2 communication"
- **14:35 UTC** - Confirmation true positive, escalade
- **14:40 UTC** - Isolation réseau ACL firewall
- **15:00 UTC** - Dump mémoire, triage KAPE
- **15:30 UTC** - Identification source : RDP bruteforce depuis IP 45.133.xxx.xxx
- **16:00 UTC** - Éradication : suppression persistence registry, reset password
- **17:00 UTC** - Validation : no malware activity post-eradication
- **72h après** - Monitoring confirme non-reinfection
- **+7 jours** - Patch infrastructure (MFA, policy mdp)

### ARTEFACTS CLÉS IDENTIFIÉS
- **Fichier malveillant** : C:\Users\Administrator\AppData\Local\Temp\wdef.exe
  - Hash MD5: a1b2c3d4e5f6a7b8 | SHA256: deadbeefcafebabe...
  - Détecté via : VirusTotal (Trojan.Win32.Emotet.A)
  - Timestamp création : 2024-01-15 13:45:22 UTC
  - Parent process : explorer.exe (compromis par injection code)

- **Persistence** : Registry HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  - "WindowsDefender" = C:\Windows\Temp\wdef.exe [MALICIOUS]
  - Supprimé : 2024-01-15 16:05 UTC

- **C2 Communication** : 5200 connexions vers 45.133.xxx.xxx:443
  - Fenêtre temporelle : 15-20 janvier, 13:45-15:30
  - Protocole : HTTPS (chiffré, payload analysé en mémoire)
  - Flux exfiltré : ~2.3 MB (reconnaissance réseau, pas données sensibles)

### CAUSE RACINE
**RDP Bruteforce Réussi** : Compte administrateur avec politique mdp = "P@ssw0rd"
- Aucune MFA
- Pas de rate limiting RDP
- Logs RDP non-centralisés (découverts rétrospectivement)

### ACTIONS CORRECTIVES
| Action | Propriétaire | Deadline | Statut |
|--------|-------------|----------|--------|
| Déployer MFA Azure/Duo sur tous administrateurs | Infra | 30j | EN COURS |
| WSUS automatique, SLA 14j patches critiques | Patch Mgmt | 21j | EN COURS |
| Centraliser RDP logs via Sysmon+SIEM | SOC | 14j | À DÉMARRER |
| Reset password ALL administrateurs | Infra | Immédiat | ✅ DONE |
| Audit complet AD pour comptes suspects | SecOps | 7j | EN COURS |

### CHAÎNE DE CUSTODIE
- Preuves collectées : 2024-01-15 14:40 UTC par Alice Martin (ANSSI)
- Hash intégrité : SHA256: xyz789...
- Stockage : Coffre sécurisé, accès restreint
- Durée conservation : 2 ans (conformité RGPD)

### CONCLUSION
Incident maîtrisé sans impact majeur. Remédiation en cours.
Retest MFA/policy + monitoring renforcé ==> validation fin janvier.
```

> **Note du terrain** : Le rapport d'incident n'est pas un document "qui reste dans un placard". Il doit être partagé avec :
> - IT Operations (pour remédiation)
> - Audit/Compliance (pour contrôles)
> - C-level management (en résumé exécutif)
> - Équipe sécurité (pour lessons learned)
