## Chapitre 3 : Préparation et Détection (Phases 1 & 2)

### 3.1 Mise en Place d'un Plan de Réponse aux Incidents (IRP)

#### **Composantes Fondamentales d'un IRP**

Un Plan de Réponse aux Incidents (Incident Response Plan) est un document vivant, mis à jour annuellement, qui détaille les processus, les rôles et les outils de réponse.

**Sections obligatoires :**

**A. Gouvernance & Escalade**

Définir la hiérarchie de décision lors d'un incident.

```
[Point de détection - SOC Analyste]
        ↓
[Triage - SOC Manager] (Confirmé/Faux positif ?)
        ↓
[Escalade - Responsable Sécurité] (Sévérité medium+)
        ↓
[Cellule de Crise - CISO] (Sévérité high/critical)
        ↓
[Direction/Légal/Compliance] (Impact métier majeur ou breach)
```

**B. Définition de la Sévérité**

Établir 4-5 niveaux de sévérité avec critères objectifs.

| Niveau | Critères | Réponse Typique | RTD (Response Time) |
|--------|----------|-----------------|-------------------|
| **Critical** | Perte données massives, ransomware, APT confirmée | Cellule de crise, FBI/ANSSI | <30 min |
| **High** | Intrusion confirmée, malware dans réseau, BEC | Équipe complète, escalade management | <2h |
| **Medium** | Anomalie réseau, tentative d'intrusion, compromission compte | SOC complet, forensics si nécessaire | <24h |
| **Low** | Alerte sécurité bénigne, vulnérabilité isolée | Analyse SOC standard | <1 week |

**C. Contacts & Escalade External**

Documenter les contacts externes critiques :

```
- ANSSI (France) : Tél. d'escalade incident
- Prestataire forensique (numéro direct)
- Cabinet juridique spécialisé (contact)
- FAI/Hébergeur (contact incident manager)
- Assureur cyber (hotline incidents)
- Presse (pour grandes organisations)
```

#### **Playbooks Spécialisés**

Un playbook est un scénario d'incident avec procédure pas-à-pas.

**Playbook 1 : Ransomware Détecté**

```
[RANSOMWARE RESPONSE PLAYBOOK]

Phase 0 - Confirmation (15 min)
├─ Confirmer découverte (extension fichier, ransom note)
├─ Identifier vecteur : RDP/VPN compromise, email phishing, vulnérabilité web
├─ Déterminer scope : Single host ? Segment réseau ? Multi-site ?
└─ Escalader à CRITICAL

Phase 1 - Isolement (30 min)
├─ Isoler réseau : couper segment infecté (déplug switch, blocage firewall)
├─ Isoler hôte : déconnecter câble réseau (pas arrêt, garde RAM)
├─ Suspendre accès administrateur (changer mdp, révoquer sessions RDP)
└─ DOCUMENTER : qui a ordonné, à quelle heure

Phase 2 - Acquisition Rapide (1-2h)
├─ Dump RAM via WinPmem ou similaire (garder malware frais en mémoire)
├─ Collecter logs (Event Log, Sysmon)
├─ Identifier patient zero (premier système infecté) via logs de propagation
└─ Hash SHA256 tous les artefacts critiques

Phase 3 - Analyse Prioritaire (parallèle)
├─ Identifier famille ransomware (extension, message, YARA matching)
├─ Chercher clé de décryption (certaines familles ont clés publiques)
├─ Estimer data exfiltrated avant chiffrement (logs de backup)
├─ Identifier chaîne C2 / attaquant (OSINT, rançon demande)

Phase 4 - Notification légale (selon sévérité)
├─ Breach notification : décider si notifier individus affectés
├─ ANSSI / CNIL : notification dans délais (72h RGPD)
├─ Assurance cyber : déclaration sinistre
└─ Autorités : évaluer FIR (dépôt plainte)
```

**Playbook 2 : Compromission Compte Administrateur**

```
[ADMIN ACCOUNT COMPROMISE PLAYBOOK]

Détection (5 min)
├─ Accès anormal depuis IP suspecte
├─ Activité de réplication (replication service, VSS writes)
├─ Enumeration d'utilisateurs ou de partages (net view, Get-ADUser massive)
└─ Escalade à HIGH ou CRITICAL selon scope

Actions Immédiates (30 min)
├─ Identifier compte : username, domaine, quel système compromis
├─ Révoquer sessions : reset token, déconnecter toutes sessions (Powershell)
│  Get-RDPSession -ComputerName SERVER | Disconnect-RDPSession
├─ Changer mot de passe long & complexe
├─ Enregistrer ancien hash pour comparaison (forensics)
└─ Bloquer sur MFA (forcer réauthentification)

Analyse Forensique Parallèle
├─ Analyser logs 4624 (logon) : identifier IP source
├─ Analyser 4688 (process creation) : actions prises avec compte
├─ Rechercher créations de compte fantôme (4720)
├─ Identifier persistance (task scheduled, service créé, WinRM)
└─ Timeline complet d'activité

Remédiation
├─ Changer mots de passe tous les comptes administrateur
├─ Révoquer PAT / API keys si développeur
├─ Forcer reset Yubikey / certificate si authentification multi-facteur
├─ Audit des autorisations : comptes inutilisés à désactiver
└─ Tester l'accès du compte : réduit ou seule session légitime
```

> **Note du terrain** : Les playbooks doivent être testés en dril (simulations) au minimum annuellement. Un playbook qui n'a jamais été exécuté en conditions réelles aura des failles découvertes à la pire moment.

---

### 3.2 Les Sources de Détection : SIEM, EDR, NDR et SOC

#### **SIEM (Security Information and Event Management)**

Le SIEM est un système centralisé qui collecte, normalise et corrèle les logs provenant de tous les systèmes d'une organisation.

**Architecture typique :**

```
[Firewall logs] ┐
[Proxy logs]    ├─> [Collecteur Syslog/Fluentd]
[Web server]    │                     ↓
[Appli métier]  ┘              [SIEM = Elasticsearch/Splunk/IBM QRadar]
                                      ↓
                                [Règles de corrélation]
                                      ↓
                                [Alertes vers SOC]
```

**Capacités clés :**

| Capacité | Exemple | Détection Possible |
|----------|---------|-------------------|
| **Centralisation** | Tous les logs en un seul point | Corrélation multi-système |
| **Enrichissement** | Ajouter géolocalisation, réputation IP | Détecter IP connue malveillante |
| **Recherche historique** | Requête sur 12 mois de logs | "Tous les accès depuis IP X vers DB" |
| **Alertage en temps réel** | Corrélation < 5 secondes | Détecter attaque active immédiatement |
| **Compliance** | Rapports automatisés | Prouver conformité RGPD/NIS2 |

**Exémple de règle SIEM (langage simplifié Splunk/Elasticsearch) :**

```
[Règle : Énumération d'utilisateurs Active Directory]

Détection d'énumération LDAP massive :

sourcetype="ldap" 
  action=search 
  | stats count by src_ip 
  | where count > 1000 
  | lookup threat_intel src_ip OUTPUT threat_level

Résultat : Si source IP inconnue + énumération massive = ALERTE HIGH
```

#### **EDR (Endpoint Detection and Response)**

L'EDR est un agent installé sur chaque endpoint (ordinateur, serveur) qui surveille les comportements suspects au niveau du processus.

**Avantages comparés SIEM :**

- Vision au niveau processus (parent-enfant, handles, mémoire)
- Détection sans dépendre des logs centralisés
- Isolation/kill de processus malveillant en quelques secondes
- Collecte d'artefacts forensiques instantanée

**Outils courants :**

| Produit | Éditeur | Spécialité |
|---------|--------|-----------|
| **CrowdStrike Falcon** | CrowdStrike | Comportement, cloud-native, kernel-level |
| **Microsoft Defender for Endpoint** | Microsoft | Intégration Windows, gratuit avec licence Microsoft |
| **Darktrace** | Darktrace | AI-driven, comportement anormal |
| **SentinelOne** | SentinelOne | Autonome, offline capability |
| **Trellix (ex-FireEye)** | Trellix | Rétro-analyse riche, cloud/on-prem |

**Exemple alerte EDR : Code Injection Détectée**

```
[Alerte CrowdStrike / Microsoft Defender]

Parent Process: svchost.exe
  └─ Child Process: notepad.exe
       ├─ Behavior: OpenProcess(lsass.exe) [SUSPICIOUS]
       ├─ Behavior: ReadVirtualMemory(PROCESS_VM_READ) [HIGH RISK]
       ├─ Behavior: WriteVirtualMemory() [CRITICAL]
       
Pattern: MITRE ATT&CK T1055 (Process Injection)
Severity: CRITICAL
Action: Isoler endpoint, tuer processus notepad.exe
Timeline: 14:32:15 UTC
```

#### **NDR (Network Detection and Response)**

L'NDR surveille le trafic réseau (pas les logs, mais les paquets) pour détecter anomalies comportementales.

**Capacités :**

- Analyse de chaîne de caractères dans le payload (regex, patterns)
- Détection C2 par analyse de flux (connexions répétées, data exfiltration)
- Identification de protocoles anormaux (Tor via port 443, SMB via HTTPS, etc.)
- Carving de données exfiltrées

**Produits courants :**

- Zeek (open-source, très puissant)
- Suricata (open-source, signatures IDS/IPS)
- ExtraHop (comportemental cloud-native)
- Darktrace (AI-based)

**Exemple détection NDR : DNS Data Exfiltration**

```
[Zeek Alert - DNS Tunneling Detection]

Source: 192.168.1.50 (Client)
Destination: 8.8.8.8 port 53 (DNS externe)

Anomaly:
- Requête DNS très longue (1200 caractères) [Typical: 40-100]
- Sous-domaines générés aléatoirement (xk9je3.attacker.com) [HIGH ENTROPY]
- Taux de requête : 2000 req/min [Typical: <50]
- TLD non-standard (.xyz, .tk, .ml) [MALWARE ASSOCIATED]

Verdict: Probable DNS exfiltration (T1048 - Exfiltration)
```

#### **Le SOC (Security Operations Center)**

Le SOC est l'équipe opérationnelle qui exploite SIEM, EDR, NDR 24/7.

**Hiérarchie typique :**

```
[CISO / Chief Security Officer]
        ↓
[SOC Manager] (superviseur)
        ├─ [T1 Analyst] - Triage & alertes bénignes (moins expérimenté)
        ├─ [T2 Analyst] - Investigations moyennes, escalade (senior)
        ├─ [T3 Analyst] - Threat hunting, chasse avancée (experts)
        └─ [Malware/Forensics Specialist] - Deep dives (cas complexes)
```

**Processus typique d'une alerte SOC :**

```
[SIEM ALERT: "Suspicious PowerShell Execution"]
        ↓
[T1 Analyst - Triage] (5 min)
  ├─ Légal ? Champ de la sécurité ?
  ├─ False positive connu ?
  └─ Escalade → T2 si douteux
        ↓
[T2 Analyst - Investigation] (30 min)
  ├─ Identifier le script PowerShell
  ├─ Scanner YARA / Hybridanalysis
  ├─ Examiner la timeline (qui, où, quand)
  ├─ Aller sur endpoint EDR chercher processus parent
  └─ Décision : Faux positif → Close | Vrai positif → Escalade
        ↓
[T3 / Forensics - Deep Dive] (2-24h)
  ├─ Dump mémoire complet
  ├─ Analyse artefacts persistance
  ├─ Chaîne d'attaque complète (kill chain)
  └─ Rapport final + recommandations
```

> **Note du terrain** : Le meilleur SIEM/EDR/NDR n'est efficace que s'il a des analystes compétents pour l'exploiter. Un outil sans talent = bruit et faux positifs.

---

### 3.3 Triage Initial : Qualifier une Alerte et Déterminer la Sévérité

#### **La Matrice de Qualification d'Alerte**

Chaque alerte doit être rapidement classifiée pour orienter la réponse. La qualification repose sur :

1. **Confiance** : Degree of certainty que l'alerte représente une vraie menace
2. **Impact** : Quels actifs/données/services sont affectés
3. **Contexte** : Qu'est-ce qui se passe autour (autres alertes, événements métier)

**Matrice de Sévérité :**

```
              Impact
         Bas | Moyen | Élevé
Confiance    |       |
Élevée       | MEDIUM| HIGH
Moyenne      | LOW   | MEDIUM
Basse        | LOW   | LOW
```

#### **Processus de Triage Structure (Premier Quart d'Heure)**

**Minute 0-2 : Reconnaissance**

```
Poser les questions :
✓ Quel outil a déclenché l'alerte ? (SIEM, EDR, IDS)
✓ Quel type de threat/TTP ? (Malware, Intrusion, Misconfiguration)
✓ Quelle est la source de l'alerte ?
✓ Le contexte métier légitime ? (Ex: déploiement de patch en cours)
```

**Minute 2-5 : Enrichissement**

```
Rechercher rapidement :
✓ IP/Hostname dans threat intel (TIM, OSINT)
✓ Utilisateur affiché : compte de service ? Admin ? Interne ?
✓ Artefact (fichier, hash, domaine) dans VirusTotal / Shodan
✓ Événements similaires dernières 24h (pattern de re-exploitation)
✓ Fenêtre temporelle : heures de travail ou créneau critique (nuit, weekend)
```

**Minute 5-15 : Première Investigation**

```
Sur l'endpoint impliqué (via EDR ou accès direct) :
✓ Vérifier si processus parent = normal
✓ Lister connexions réseau actives (netstat -anob)
✓ Chercher artefacts nouveaux (fichiers modifiés dernière heure)
✓ Vérifier tâches planifiées / services nouveaux
✓ Timeline d'exécution : quand exactement
```

#### **Scénario 1 : Triage Positif (Vrai Positif Identifié)**

```
[ALERTE SIEM] "Powershell.exe downloading from suspicious URL"

Minute 1: Source = Workstation01 (dev network)
          User = jdoe@corp (employee standard)
          URL = http://45.133.xxx.xxx/payload.exe

Minute 3: IP enrichment = Proofpoint threat intel = MALWARE C2
          VirusTotal = Trojan.Win32.Emotet (91/92 vendors)

Minute 7: EDR shows : powershell.exe spawned by explorer.exe
          Network traffic = HTTPS to many IPs (botnet activity)
          File created = C:\Users\jdoe\AppData\Local\Temp\tmpABC123.exe
          Hash = matches known Emotet sample (3 months old)

VERDICT: TRUE POSITIVE - MALWARE INFECTION
SEVERITY: CRITICAL
ACTION: Isolate endpoint, dump RAM, full forensics
```

**Timeline extraction à ce stade :**

```bash
# Sur le workstation via EDR
Get-ChildItem C:\Users\jdoe\AppData\Local\Temp -Recurse |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-2) } |
  Select-Object FullName, LastWriteTime, Length

# Résultat attendu :
# C:\Users\jdoe\AppData\Local\Temp\tmpABC123.exe  14:35:22  156KB
```
