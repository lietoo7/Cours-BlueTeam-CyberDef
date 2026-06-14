# DFIR : Le Guide Opérationnel - Suite
## Chapitres 8-11 & Annexes

---

# 🌐 PARTIE 4 : INVESTIGATIONS SPÉCIALISÉES

---

## Chapitre 8 : Forensic Réseau et Analyse de Trafic

### 8.1 Capture et Analyse de Paquets (Fichiers PCAP via Wireshark/Zeek)

#### **Fondamentaux : Qu'est-ce qu'un PCAP ?**

Un fichier PCAP (Packet Capture) est un enregistrement binaire de tous les paquets réseau transitant par une interface à un moment donné.

**Propriétés :**

- **Format** : .pcap (standard TCPdump) ou .pcapng (plus moderne, avec metadata)
- **Contenu** : Headers Ethernet/IP/TCP/UDP + payload d'application
- **Taille** : Croissance rapide (1 Gbps = ~1 GB/minute)
- **Volatilité** : Très volumineux à archiver long-terme

**Utilité en forensics :**

- Identifier trafic C2 (command & control)
- Détecter exfiltration de données
- Retracer communications attaquant ↔ victime
- Extraire fichiers transférés (carving)

#### **Collecte de PCAP en Production**

**Méthode 1 : tcpdump (Live capture)**

```bash
# Capture simple sur interface eth0
sudo tcpdump -i eth0 -w capture.pcap

# Capture avec filtre (uniquement port 443)
sudo tcpdump -i eth0 "port 443" -w https_traffic.pcap

# Capture avec rotation de fichiers (limite taille)
sudo tcpdump -i eth0 -w traffic_%Y%m%d_%H%M%S.pcap \
  -G 3600 -Z root -C 500  # 500MB max par fichier, rotation chaque heure

# Sortie
tcpdump: listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
^C
30000 packets captured
30000 packets received by filter
0 packets dropped by kernel
```

**Méthode 2 : tshark (Wireshark CLI)**

```bash
# Capture avec dissection en temps réel
tshark -i eth0 -a filesize:500000 -w traffic.pcap

# Capture + filtrer + export en temps réel
tshark -i eth0 -f "tcp.port == 443" -a duration:3600 -w https.pcap

# Dissect PCAP exporté en CSV (pour analysis)
tshark -r https.pcap -T fields -E header=y \
  -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
  -e http.host > traffic_analysis.csv
```

#### **Analyse de PCAP : Wireshark**

Wireshark est l'outil de référence pour explorer et analyser PCAPs manuellement.

```
[Wireshark GUI]

File > Open PCAP
├─ Affiche automatiquement tous les paquets
├─ Colore par protocole (bleu=TCP, rouge=error)
├─ Drill-down sur paquet = voir headers complets

Exemple enquête : "Quel serveur l'attaquant contacte ?"

1. Filtre : ip.src == 192.168.1.50 (machine compromise)
   ↓ Affiche uniquement trafic depuis cette IP

2. Statistiques > Endpoints
   ↓ Montre toutes les IP distantes contactées
   
   45.133.xxx.xxx : 5200 paquets [SUSPECTE - beaucoup trafic]
   8.8.8.8        : 50 paquets   [Google DNS - normal]
   10.0.0.100     : 3000 paquets [Serveur interne - normal]

3. Clic droit sur flux 45.133.xxx.xxx > Follow > TCP Stream
   ↓ Affiche conversation complète, potentiellement décodée

4. Exporter données : File > Export Objects > HTTP
   ↓ Extrait fichiers téléchargés depuis PCAP
```

#### **Analyse Automatisée : Zeek (ELK Stack)**

Pour analyser PCAP massive (100 GB+), utiliser Zeek pour générer logs structurés.

```bash
# Zeek (ancien Bro) = IDS + Log generator
# Lit PCAP, génère logs de haut niveau

zeek -r capture.pcap local

# Résultat : Fichiers logs
ls -la
-rw-r--r--  1 root root  50MB conn.log          # Toutes connexions TCP/UDP
-rw-r--r--  1 root root  20MB http.log          # Requêtes HTTP
-rw-r--r--  1 root root  5MB  dns.log           # Requêtes DNS
-rw-r--r--  1 root root  100MB ssl.log          # Certificats SSL/TLS
-rw-r--r--  1 root root  30MB files.log         # Fichiers téléchargés
-rw-r--r--  1 root root  15MB x509.log          # Certificats extraits

# Parser logs Zeek (CSV-like)
cat conn.log | head -5
# timestamp | uid | id.orig_h | id.orig_p | id.resp_h | id.resp_p | proto | service | duration | orig_bytes | resp_bytes | conn_state | local_orig | local_resp | missed_bytes | history | orig_pkts | orig_ip_bytes | resp_pkts | resp_ip_bytes | community_id

# Analyzer : Chercher connexion du malware
grep "45.133.xxx.xxx" conn.log | awk '{print $1, $3, $5, $7, $9}'
# 2024-01-15T14:35:22Z 192.168.1.50 45.133.xxx.xxx tcp C2_CONNECTION_DETECTED 3600s
```

#### **Forensic Réseau : Cas Réel**

```
[SCENARIO] Exfiltration soupçonnée - 500 MB de données en 2h
           Analyser PCAP pour prouver vol données

Étape 1 : Identifi le volume anormal
grep "192.168.1.50" conn.log | sort -k10 -n -r | head -5
# 2024-01-15T14:35Z 192.168.1.50 45.133.xxx.xxx TCP 2500 500000000 bytes [500 MB !]
# 2024-01-15T14:35Z 192.168.1.50 8.8.8.8 TCP 53 1000 bytes [DNS normal]

Étape 2 : Identifier protocole utilisé
zeek -r capture.pcap local
grep "45.133.xxx.xxx" https.log | wc -l  # HTTPS encrypted
# 5200 connexions HTTPS

grep "45.133.xxx.xxx" http.log
# [Rien - pas de HTTP clair]

Étape 3 : Extraire certificat SSL (pour identifier C2)
cat x509.log | grep "45.133.xxx.xxx"
# Subject: CN=command.attacker.net [ATTACKER DOMAIN]
# Serial: ABC123DEF456 [Enregistrer pour renseignement]

Étape 4 : Estimer données exfiltrées
# HTTPS chiffré donc pas de carving possible
# Mais : orig_bytes = 500MB >>> resp_bytes = 100KB
# Clair : upload (data exfil) asymétrique

Conclusion : Utilisateur 192.168.1.50 a exfiltrée 500 MB vers serveur C2 compromis
Via HTTPS encrypted, impossibilité extraire données du PCAP
Mais communication prouvée, timing établi, domaine C2 identifié
```

---

### 8.2 Analyse des Logs d'Infrastructure (Pare-feu, Proxy, DNS)

#### **Firewall Logs : Stratégie de Détection**

Les pare-feu centralisés enregistrent TOUS les connexions acceptées/refusées.

**Localisation :**

```
Firewalls Cisco ASA, Fortinet FortiGate, Palo Alto :
├─ Local : /var/log/syslog ou interface de gestion
└─ Centralisé : SIEM (Splunk, ELK, IBM QRadar)
```

**Exemple log pare-feu (simplifié) :**

```
2024-01-15 14:35:22 ALLOW 192.168.1.50:54321 -> 45.133.xxx.xxx:443 tcp session_id=ABC123
2024-01-15 14:35:30 ALLOW 192.168.1.50:54322 -> 45.133.xxx.xxx:443 tcp session_id=ABC124
2024-01-15 14:36:10 DENY  192.168.1.50:54323 -> 10.0.0.200:22 tcp [Policy violation]
2024-01-15 14:36:15 ALLOW 192.168.1.50:54323 -> 10.0.0.100:22 tcp session_id=ABC125
```

**Analyse pour incident :**

```bash
# Rechercher connexions inhabitués depuis 192.168.1.50
grep "ALLOW.*192.168.1.50" firewall.log | \
  awk '{print $NF}' | sort | uniq -c | sort -rn

# 5200 connexions vers 45.133.xxx.xxx [ANORMAL - externe non-autorisée]
# 3000 connexions vers 10.0.0.100 [Normal - serveur interne]
# 100 connexions vers 8.8.8.8 [Normal - DNS Google]

# Extraction timeline : Quand a-t-il commencé ?
grep "45.133.xxx.xxx" firewall.log | head -1
# 2024-01-15 14:35:22 ALLOW 192.168.1.50:54321 -> 45.133.xxx.xxx:443
# ↑ Première connexion C2 = 14:35:22

grep "45.133.xxx.xxx" firewall.log | tail -1
# 2024-01-15 15:30:45 ALLOW 192.168.1.50:54350 -> 45.133.xxx.xxx:443
# ↑ Dernière connexion C2 = 15:30:45
```

#### **Proxy Logs : Reconstruction Activité Web**

Si l'organisation utilise proxy centralisé, tous les accès HTTP/HTTPS passent par celui-ci.

**Format log proxy (Squid, Bluecoat, etc.) :**

```
2024-01-15 14:35:22 192.168.1.50 jdoe "GET http://malware-domain.net/payload.exe HTTP/1.1" 200 156288 "Mozilla/5.0"
2024-01-15 14:35:45 192.168.1.50 jdoe "GET http://c2-server.ru/cmd HTTP/1.1" 200 512
2024-01-15 14:36:10 192.168.1.50 jdoe "GET http://legitimate-site.com HTTP/1.1" 200 5242880
2024-01-15 14:37:22 192.168.1.50 jdoe "GET http://exfil-server.net/upload HTTP/1.1" 200 500000000
```

**Forensic analysis :**

```bash
# Timeline précise des accès web
grep "192.168.1.50" proxy.log | awk '{print $1, $2, $6}' | sort -k1,2
# 2024-01-15 14:35:22 malware-domain.net [PAYLOAD DOWNLOAD]
# 2024-01-15 14:35:45 c2-server.ru [C2 CONTACT]
# 2024-01-15 14:36:10 legitimate-site.com [COVER]
# 2024-01-15 14:37:22 exfil-server.net [DATA EXFIL]

# Identifier serveurs exfiltration
grep "192.168.1.50" proxy.log | grep -oP "http://\K[^ ]+" | sort | uniq -c
# 5200 c2-server.ru [Command center]
# 1 exfil-server.net [Data exfil]
# 50 legitimate-site.com [Masking]

# Estimation données transférées (via response size)
awk '/192.168.1.50/ {bytes+=$10} END {printf "Total: %.2f GB\n", bytes/1024/1024/1024}' proxy.log
# Total: 500.23 GB [MASSIVE EXFIL]
```

#### **DNS Logs : Reconnaissance & C2 Communication**

DNS est un protocole peu surveillé mais très révélateur.

**Artefact DNS suspectes :**

```
- Résolution de domaines malveillants (c2-server.ru, exfil.xyz)
- Taux de requêtes anormal (tunneling DNS)
- Sous-domaines générés aléatoirement (a1x2z3.attacker.com) [DNS exfil signature]
- NXDOMAIN massif (domaines n'existant pas) [Brute-force de domaines]
```

**Extraction DNS logs :**

```bash
# Depuis SIEM ou bind logs
grep "192.168.1.50" dns.log | \
  awk '{print $6}' | sort | uniq -c | sort -rn | head -20

# 5200 45.133.xxx.xxx A-record [ATTACKER C2]
# 100 8.8.8.8 A-record [Google DNS - normal]
# 50 1.1.1.1 A-record [Cloudflare DNS - normal]
# 30 malware-domain.net A-record [SUSPICIOUS - non-existent in real DNS]

# Chronologie : Quand la reconnaissance a commencé ?
grep "attacker.net\|c2\|malware" dns.log | head -1
# 2024-01-15 14:33:15 192.168.1.50 query malware-domain.net
# ↑ Avant même l'exécution du malware, reconnaissance DNS

# Entropy (entropie) des domaines : détecte DGA (Domain Generation Algorithm)
awk '/192.168.1.50/ {print $6}' dns.log | \
  awk '{
    for(i=1;i<=length($0);i++) printf("%c", substr($0,i,1))
  }' | sed 's/-//g' | awk 'length > 15 && length < 30 {print}' | wc -l
# 250 domaines avec haute entropie = probable DGA
```

> **Note du terrain** : Les logs DNS centralisés sont **CRITIQUES** pour reconstruction TTK (time-to-kill = temps entre première tentative accès attaquant et détection). Sans DNS, on perd la timeline d'reconnaissance.

---

### 8.3 Détection des Tunnels Malveillants et du Trafic C2

#### **Concepts : C2 Beaconing**

Un malware établit canal de communication ("beacon") avec son serveur de commande toutes les N minutes.

**Signatures beacon :**

```
1. Connexions périodiques régulières (ex: toutes les 5 min)
   Fenêtre temporelle : 14:35, 14:40, 14:45, 14:50... [PATTERN RÉGULIER]

2. Volume constant de données (ex: 512 bytes toujours)
   Symétrie anormale (upload = download)

3. Trafic chiffré ou obfusqué
   Signature entropie très élevée

4. Connexions non-complètement fermées (TIME_WAIT long)
   Évite la détection par IDS basé sur session
```

#### **Détection dans Zeek logs**

```bash
# Chercher beacons dans conn.log
# Signature : même destination, périodicité, même port

cat conn.log | grep "45.133.xxx.xxx" | \
  awk '{print $1, $10, $11}' | sort -k1

# 2024-01-15T14:35:15Z 10000 512
# 2024-01-15T14:40:15Z 10000 512
# 2024-01-15T14:45:15Z 10000 512
# 2024-01-15T14:50:15Z 10000 512
# [Beacon toutes les 5 min, même size]

# Script de détection beacon (Python)
import re
from collections import defaultdict

beacon_times = []
with open('conn.log', 'r') as f:
    for line in f:
        if '45.133.xxx.xxx' in line:
            parts = line.split()
            timestamp = parts[0]
            beacon_times.append(timestamp)

# Calculer interval entre beacons
intervals = []
for i in range(1, len(beacon_times)):
    interval = datetime.fromisoformat(beacon_times[i]) - \
               datetime.fromisoformat(beacon_times[i-1])
    intervals.append(interval.total_seconds())

# Si intervals sont constants = beacon pattern
if len(set(intervals)) <= 3:  # Petit variance admis (< 3 valeurs différentes)
    print(f"BEACON DETECTED: Interval = {intervals[0]}s")
    print(f"Consistency: {len(intervals)} beacons")
```

#### **Tunneling & Exfiltration Déguisée**

Attaquants sophistiqués cachent données dans protocoles innocents.

**Exemples :**

```
1. DNS Tunneling : Données encodées dans questions DNS
   Legitimate DNS : workstation.corp.com IN A
   Tunneling DNS : SGVsbG8gV29ybGQhIFRoaXMgaXMgZXhmaWx... IN A
                   ↑ Base64-encodé, spreads sur N requêtes

2. ICMP Tunneling : Données dans payload ICMP (ping)
   Legitimate : ping 8.8.8.8 (56 bytes data)
   Tunneling : ping attacker.com [4000 bytes data] [ANORMAL]

3. Slack/Discord APIs : Données exfiltrées via chat apps
   HTTP: POST api.slack.com/api/chat.postMessage
   Body: {"channel": "#logs", "text": "[EXFIL DATA HERE]"}
```

**Détection via trafic analysis :**

```bash
# DNS tunneling signature : requêtes DNS très longues
tshark -r capture.pcap -Y "dns.qry.name" | \
  awk '{print length($0), $0}' | sort -rn | head -10

# 4000 attacker.thisdomain.com.thisdomain.com.thisdomain... [SUSPICIOUSLY LONG]
# 100 normal.corporate.com [Normal]
# 98 mail.corporate.com [Normal]

# ICMP tunneling : payload > 56 bytes
tshark -r capture.pcap -Y "icmp" -T fields -e ip.len
# 1500 [HUGE - normal est ~80]
# 1500 [Autre paquet large]
# 80 [Normal ping]
```

---

## Chapitre 9 : Forensic Cloud (AWS, Azure, Microsoft 365)

### 9.1 Spécificités de l'Investigation Cloud

#### **Paradigme Différent : Pas d'Accès Physique**

Contrairement aux investigations on-premise (accès disque physique, serveur dans le datacentre), le cloud impose :

**Contraintes :**

```
❌ Pas d'acquisition bit-stream disque (infrastructure tiers)
❌ Pas d'accès au firmawre / BIOS
❌ Pas de contrôle des timeservers (dépend cloud provider)
✅ Mais : logs centralisés, auditabilité, chaîne de custodie par API
```

**Paradigme d'investigation :**

```
On-Premise       │ Cloud
════════════════════════════════
Acquérir disque  │ Récupérer audit logs
Installer tools  │ Utiliser cloud APIs
Accès physique   │ Accès par IAM roles
Heures           │ Minutes (data sur serveur fournisseur)
```

#### **Principes Forensic Cloud**

**1. Immuabilité des logs :**

Les logs cloud provider (CloudTrail, Azure Activity Logs, M365 Audit Log) sont considérés immuables légalement (Google/Microsoft/AWS garantissent non-modification).

```
On-Premise risk : Administrateur supprime/modifie logs
Cloud avantage : Suppression logs elle-même est loggée
```

**2. Chaîne de Custodie par API :**

Au lieu de "qui a manipulé le disque", on a "qui a requêté les logs" (logs d'accès aux logs).

```
[Utilisateur A demande logs] → API Azure > Log audit "User A accessed logs at 14:35"
                               ↓
                           [Chaîne de custodie = automatic]
```

**3. Tempo rapide :**

Investigation démarre par requête API (instantané) plutôt que transport physique (heures).

---

### 9.2 Analyse des Logs d'Audit (CloudTrail, Azure Activity Logs, M365)

#### **AWS CloudTrail : Audit des Accès**

CloudTrail enregistre TOUTES les API calls contre les services AWS.

**Exemple d'événement CloudTrail :**

```json
{
  "eventVersion": "1.05",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDACKCEVSQ6C2EXAMPLE",
    "arn": "arn:aws:iam::123456789012:user/jdoe",
    "accountId": "123456789012",
    "invokedBy": "jdoe@corp.com",
    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "userName": "jdoe"
  },
  "eventTime": "2024-01-15T14:35:22Z",
  "eventSource": "ec2.amazonaws.com",
  "eventName": "AuthorizeSecurityGroupIngress",
  "awsRegion": "eu-west-1",
  "sourceIPAddress": "45.133.xxx.xxx",
  "userAgent": "aws-cli/2.0.0",
  "requestParameters": {
    "groupId": "sg-0123456789abcdef0",
    "cidrIp": "45.133.0.0/16",
    "fromPort": 22,
    "toPort": 22,
    "ipProtocol": "tcp"
  },
  "responseElements": {
    "return": true
  },
  "requestID": "ABC-123-DEF",
  "eventID": "ABC123DEF456",
  "eventType": "AwsApiCall",
  "recipientAccountId": "123456789012"
}
```

**Forensic interpretation :**

```
▶ Utilisateur : jdoe (IAM user)
▶ Heure : 14:35:22 UTC
▶ Action : AuthorizeSecurityGroupIngress (ourir port)
▶ Détails : Port 22 SSH ouvert vers 45.133.0.0/16 (attaquant IP range)
▶ Source IP : 45.133.xxx.xxx (compromised IP)

VERDICT : Attaquant a utiliser identifiant compromis jdoe
          pour ouvrir accès SSH à serveur EC2
          Preuve : sourceIPAddress + action = latéral movement
```

**Queries CloudTrail (AWS CLI) :**

```bash
# Récupérer logs CloudTrail depuis S3
aws s3 ls s3://my-cloudtrail-logs/

# Rechercher événement spécifique (console)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceType,AttributeValue=AWS::EC2::SecurityGroup \
  --start-time 2024-01-15T00:00:00Z \
  --end-time 2024-01-15T23:59:59Z

# Résultat : Tous les changements de security groups du 15 janvier

# Parser CloudTrail logs JSON pour recherche
aws s3 cp s3://my-cloudtrail-logs/AWSLogs/123456789012/CloudTrail/eu-west-1/2024/01/15/ . --recursive

jq '.Records[] | select(.eventName == "AuthorizeSecurityGroupIngress")' *.json | \
  jq '{user: .userIdentity.userName, time: .eventTime, sourceIP: .sourceIPAddress}'

# Résultat
# { "user": "jdoe", "time": "2024-01-15T14:35:22Z", "sourceIP": "45.133.xxx.xxx" }
# ↑ Permet reconstruction complète de l'attaque
```

#### **Azure Activity Logs : Audit Tenant Azure**

```json
{
  "time": "2024-01-15T14:35:22.123Z",
  "resourceId": "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/prod-vm1",
  "operationName": {
    "value": "Microsoft.Compute/virtualMachines/write",
    "localizedValue": "Create or Update Virtual Machine"
  },
  "category": "Administrative",
  "level": "Informational",
  "durationMs": 1234,
  "identity": {
    "authorization": {
      "scope": "/subscriptions/12345678-1234-1234-1234-123456789012",
      "permission": "*/write",
      "principalId": "user-jdoe@corp.com",
      "principalType": "User"
    },
    "claims": {
      "iss": "https://sts.windows.net/...",
      "oid": "user-object-id",
      "appid": "user-app-id"
    }
  },
  "correlationId": "ABC-123-DEF-456",
  "callerIpAddress": "45.133.xxx.xxx",
  "result": "Succeeded",
  "resultSignature": "Succeeded."
}
```

**Forensic queries (Azure CLI) :**

```bash
# Récupérer logs activité Azure
az monitor activity-log list \
  --start-time 2024-01-15T00:00:00Z \
  --end-time 2024-01-15T23:59:59Z \
  --resource-group prod-rg

# Chercher modifications secrets/credentials
az monitor activity-log list \
  --query "[?contains(operationName.value, 'Microsoft.KeyVault')]" \
  --start-time 2024-01-15T00:00:00Z

# Résultat : Tous les accès Key Vault (credentials stockées)
# Si attaquant lisait secrets = breach credentials
```

#### **Microsoft 365 Unified Audit Log**

M365 consigne toutes les actions Exchange, SharePoint, Teams, etc.

```json
{
  "CreationTime": "2024-01-15T14:35:22",
  "Id": "ABC-123-DEF-456",
  "Operation": "MailItemsAccessed",
  "OrganizationId": "00000000-0000-0000-0000-000000000000",
  "RecordType": "ExchangeItem",
  "UserKey": "user-jdoe@corp.com",
  "UserType": "Regular",
  "Version": 1,
  "Workload": "Exchange",
  "UserId": "jdoe@corp.com",
  "AppId": "00000000-0000-0000-0000-000000000000",
  "ClientIP": "45.133.xxx.xxx",
  "ClientInfoString": "Mozilla/5.0",
  "Details": {
    "MailboxOwner": "jdoe@corp.com",
    "Folders": [
      {
        "FolderId": "folder-id",
        "FolderPath": "/Inbox"
      }
    ],
    "LogonType": "Owner",
    "LogonUserSid": "user-sid",
    "MailboxGuid": "mailbox-guid",
    "MailboxUPN": "jdoe@corp.com",
    "ClientIP": "45.133.xxx.xxx",
    "InternetMessageId": "<msg-id@corp.com>"
  },
  "ResultStatus": "Succeeded"
}
```

**Forensic investigation (PowerShell) :**

```powershell
# Connecter à tenant M365
Connect-ExchangeOnline -UserPrincipalName admin@corp.com

# Chercher tous les accès mailbox anormaux
Search-UnifiedAuditLog -StartDate 2024-01-15 -EndDate 2024-01-16 `
  -Operations MailItemsAccessed `
  -UserIds jdoe@corp.com

# Résultat : Tous les emails lus/envoyés
# Si attaquant accédait = voir avec IP source anormale

# Chercher forwarding rules créées (technique exfil courant)
Search-UnifiedAuditLog -StartDate 2024-01-15 -EndDate 2024-01-16 `
  -Operations New-InboxRule,Set-InboxRule `
  -ResultStatus Succeeded

# Chercher deletions (cover-up)
Search-UnifiedAuditLog -StartDate 2024-01-15 -EndDate 2024-01-16 `
  -Operations Delete `
  -ResultStatus Succeeded
```

---

### 9.3 Répondre à une Compromission de Tenant ou Attaque BEC

#### **Business Email Compromise (BEC) : Scénario Classique**

Un attaquant accède au compte email d'un directeur pour fraud de virement.

**Investigation BEC :**

```
[SCÉNARIO] CFO account compromised, email envoyé autorisant virement 500k €

Timeline reconstruction via M365 logs :

14:00 - Attaquant access mailbox depuis IP externe (45.133.xxx.xxx)
        └─ Event: MailItemsAccessed, ClientIP=45.133.xxx.xxx
        
14:05 - Attaquant crée inbox rule "Forward to attacker@attacker.com"
        └─ Event: New-InboxRule, ForwardingAddress=attacker@attacker.com
        
14:10 - Attaquant envoie email from CFO à comptes bank + board
        └─ Event: Send, Recipient=bank@ourbank.fr, Subject="Urgent Virement"
        
14:15 - Attaquant supprime email sent (cover-up)
        └─ Event: Delete, Items=SentFolder
        
14:20 - Security analyst détecte anomalie IP et alert
        └─ Réponse immédiate : MFA reset, session revoke
        
Post-incident :
└─ Chaîne de custodie = M365 logs immuables
└─ Preuve attaquant = IP source + timestamps
└─ Virement bloqué = Attaquant n'a pas eu accès banking portal
```

**Rémediation BEC :**

```powershell
# 1. Revoke toutes les sessions
Revoke-ExchangeSession -UserId cfo@corp.com

# 2. Reset password & force MFA
Set-MsolUserPassword -UserPrincipalName cfo@corp.com -NewPassword (ConvertTo-SecureString -AsPlainText "NewP@ss123!" -Force) -ForceChangePasswordNextLogon $true

# 3. Supprimer forwarding rules malveillantes
Get-InboxRule -Identity cfo@corp.com | Where-Object {$_.ForwardingAddress -ne $null} | Remove-InboxRule -Confirm:$false

# 4. Audit complet : qui d'autre a accès ?
Get-MailboxPermission -Identity cfo@corp.com | Where-Object {$_.IsInherited -eq $false}

# 5. Review mail forwarding (technique d'exfil alternative)
Get-Mailbox cfo@corp.com | Select-Object *Forward*
```

---

# 🧪 PARTIE 5 : ANALYSE AVANCÉE & CHASSE AUX MENACES

---

## Chapitre 10 : Analyse de la Mémoire RAM (Volatility 3 Avancé)

### 10.1 Concepts Fondamentaux de la Gestion Mémoire Sous Windows

#### **Architecture Mémoire Windows (Simplifiée)**

Windows utilise un schéma de mémoire virtuelle à deux niveaux :

```
Virtual Address Space (4 GB par processus, 64-bit = 16 EB)
     ↓
Page Tables (mappent VA → PA)
     ↓
Physical RAM (8 GB, 16 GB, etc.)
```

**Zones clés :**

| Zone | Adresse | Contenu | Volatilité |
|------|---------|---------|-----------|
| **Kernel Space** | 0xFFFF... | Code kernel, drivers, structures système | Critique |
| **User Space** | 0x0000... | Heap, stack, code application | Très critique |
| **Page File** | Disque | Mémoire "paginée" vers disque | Semi-persistant |
| **Registry** | Physique | Clés registre chargées en RAM | Semi-volatile |

#### **Processus & Virtual Address Spaces**

Chaque processus a son propre "virtual address space" de 4 GB (32-bit) ou 16 EB (64-bit).

```
Process Model (Windows):

Kernel.exe (PID 4)
  ├─ Virtual Address 0x0000:0000 → Physical RAM
  ├─ Page Table (PDPT)
  └─ CR3 = pointer to page tables

Explorer.exe (PID 1234)
  ├─ Virtual Address 0x0000:0000 → Physical RAM (différent que kernel)
  ├─ Page Table (PDPT)
  └─ CR3 = pointeur différent

[Même VA, adresses physiques différentes]
```

**Implication forensique :**

```
Analyser mémoire nécessite :
1. Récupérer CR3 de chaque processus (context switch)
2. Parser page tables (PDPT, PDT, PT, PTE)
3. Résoudre VA → PA pour chaque adresse
4. Reconstituer heap/stack par processus

Volatility automatise cela.
```

#### **Heap & Stack : Où le Malware Se Cache**

**Stack** : Accès rapide, stocke variables locales + return addresses

```
Function A calls B:
  Stack layout :
  ┌─────────────────┐
  │ Frame A         │ ← RSP (stack pointer) = top of stack
  │ Local vars A    │
  │ Return addr     │ ← Où revenir quand B finit
  │ Frame B         │
  │ Local vars B    │ ← Actuellement exécuté
  └─────────────────┘
  
Attack: Débordement stack (buffer overflow)
        Overwrite return address → Jump à code malveillant
```

**Heap** : Mémoire dynamique, lente mais grande

```
malloc() allocation :
  ┌──────────┐
  │ Chunk 1  │ ← Allocé
  │ metadata │
  ├──────────┤
  │ Chunk 2  │ ← Libre
  ├──────────┤
  │ Chunk 3  │ ← Allocé (souvent malware)
  └──────────┘

Attack: Heap spray (remplir heap avec shellcode)
        Heap corruption (overwrite chunk metadata)
```

---

### 10.2 Utilisation Avancée de Volatility 3

#### **Commandes Volatility Essentielles pour Forensics**

**1. Identification du Dump**

```bash
python3 -m volatility3 -f memory.dump windows.info
# Retourne :
# KUSER_SHARED_DATA: 0xffff0f80...
# KDLL Base: 0xfffff800...
# NT Build: 19041 (Windows 10 21H2)
# OS Profile auto-détecté
```

**2. Enumération Processus (Détection Caché)**

```bash
python3 -m volatility3 -f memory.dump windows.pslist
# Liste : processus "normaux" (linked list kernel)
# Manque : processus cachés (unlinked de la liste)

# Volatility compare multiple sources :
# - PsActiveProcessHead (liste kernel)
# - All processes in Virtual Address Space (enumerate pages)
# - CSRSS handles (processus doivent être enregistrés)

# Différence = hidden process
python3 -m volatility3 -f memory.dump windows.psscan
# Scan mémoire pour EPROCESS structures (cache-resistant)
# Retrouve processus hidden

# Différence entre pslist & psscan = processus injecté/caché
```

**3. Injection de Code & DLL Loading**

```bash
# Pour chaque processus, lister DLLs chargées
python3 -m volatility3 -f memory.dump windows.dlllist

# Résultat :
# PID: 1234 (explorer.exe)
#   0x00007ff0: C:\Windows\System32\kernel32.dll
#   0x00007ff8: C:\Windows\System32\ntdll.dll
#   0x00007ffc: C:\Windows\System32\mscoree.dll
#   0x00400000: C:\Users\jdoe\AppData\Local\Temp\injected.dll [SUSPECT]
#               ↑ DLL dans TEMP, chargée dynamiquement

# Code injection : Chercher RWX pages (lecture + écriture + exécution)
python3 -m volatility3 -f memory.dump windows.memmap --pid 1234 | grep RWX

# Résultat : Adresses avec RWX = potentiel shellcode
```

**4. Extraction Secrets (Passwords, Tokens, Keys)**

```bash
# Loot LSA (Local Security Authority) pour NT hashes
python3 -m volatility3 -f memory.dump windows.hashdump

# Résultat :
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
# Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# jdoe:1000:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
# ↑ Hashes NTLM (peuvent être crackés offline)

# Extraire credentials depuis LSASS memory
python3 -m volatility3 -f memory.dump windows.lsadump

# Résultat : Plaintext passwords (Kerberos tickets, SSO)
```

**5. Connexions Réseau Actives**

```bash
python3 -m volatility3 -f memory.dump windows.netscan

# Résultat :
# PID: 2344 (powershell.exe)
#   0x0a000064:55612 → 45.133.xxx.xxx:443 [ESTABLISHED]
#   ↑ PowerShell connectée à serveur C2 externe

# PID: 1024 (chrome.exe)
#   0xc0a80001:5000 → 8.8.8.8:53 [ESTABLISHED]
#   ↑ Chrome connecté à DNS Google (normal)
```

**6. Timeline Reconstruction (Processus Exécution)**

```bash
python3 -m volatility3 -f memory.dump windows.timelineshot
# Timeline de création/terminaison de tous les processus

# Résultat :
# 2024-01-15 13:45:22 Process Created: powershell.exe (PID 2344)
# 2024-01-15 13:45:25 DLL Loaded: C:\Temp\injected.dll
# 2024-01-15 13:45:30 Network Connection: 45.133.xxx.xxx:443
# 2024-01-15 14:35:22 Process Terminated: powershell.exe
```

#### **Cas d'Usage : Fileless Malware Detection**

Fileless malware vit **uniquement en mémoire**, pas sur disque.

```
[SCENARIO] Emotet.C fileless variant
          - Pas d'exécutable sur disque
          - Vit en mémoire PowerShell
          - Détection : uniquement via RAM dump

Detection steps:

1. Dump mémoire système
   ├─ ✅ Dump acquis rapidement

2. Enumerate processus
   └─ PowerShell.exe (PID 2344) chargé + executionPolicy modifiée

3. Analyzer PowerShell process
   python3 -m volatility3 -f memory.dump windows.dumpfiles --pid 2344
   └─ Extrait contenu mémoire processus

4. Chercher signatures PowerShell malveillant
   strings memory_2344 | grep -i "invoke\|obfuscation\|cmd"
   └─ Trouve contenu script PowerShell encodé

5. Decoder script (usually Base64 + obfuscation)
   Decode → Identifie Emotet C2 URLs
   
6. Timeline : Quand PowerShell a lancé le script ?
   ├─ 13:45:22 - Explorer.exe lance PowerShell hidden
   ├─ 13:45:24 - PowerShell télécharge script malveillant
   ├─ 13:45:25 - Script chauffé en mémoire (nunca sur disque)
   └─ Volatility retrouve tout en mémoire
```

---

### 10.3 Reverse Engineering de Malware via Mémoire

#### **Extraction de Malware du Dump**

Parfois, malware n'est pas sur disque (déjà supprimé). Volatility extrait desde mémoire.

```bash
# Trouver processus contenant code malveillant
python3 -m volatility3 -f memory.dump windows.pslist | grep -i "notepad\|svchost\|system"

# Pour processus suspect, dumper mémoire complète
python3 -m volatility3 -f memory.dump windows.dumpfiles --pid 1234 --output-dir ./dumps

# Analyser dump binaire avec Ghidra/IDA
# Chercher :
# - Strings suspectes (C2 domains, API calls)
# - Références mémoire anormales
# - Chunks de code injecté

# Exemple : Dumped data analysé dans Ghidra
strings dumps/pid.1234.img | grep -i "http\|cmd\|powershell"
# http://c2.attacker.ru/cmd?id=
# cmd.exe /c whoami
# powershell.exe -NoProfile -ExecutionPolicy Bypass
```

#### **Identification de Packer & Obfuscation**

```
Packed malware = Original code compressé + Decompressor stub
Detecter packer = Identifier entropie haute (données aléatoires)

Volatility plugin :
python3 -m volatility3 -f memory.dump windows.entropy --pid 1234

Résultat :
Memory page entropy scores:
0x400000: 2.1 [LOW - CODE section]
0x401000: 7.8 [HIGH - PACKED/COMPRESSED]
0x402000: 8.9 [VERY HIGH - ENCRYPTION KEY ?]

HIGH entropy = probability packer détecté
```

---

## Chapitre 11 : Threat Hunting et Rétro-Ingénierie de Malwares

### 11.1 Recherche Proactive via Frameworks MITRE ATT&CK

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

### 11.2 Analyse Comportementale de Malwares (Sandboxing)

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

### 11.3 Création et Déploiement de Règles de Détection (YARA, Sigma)

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

---

# 📝 ANNEXES & FICHES PRATIQUES

---

## Annexe A : Checklist d'Urgence du Premier Intervenant (First Responder)

Cette checklist doit être imprimée et disponible immédiatement lors d'incident.

### **Phase 0 : Premières 30 secondes (avant escalade)**

```
□ Confirmation incident
  ├─ Quoi exactement ? (Alerte spécifique)
  ├─ Quand détecté ? (Timestamp exact)
  └─ Quel système ? (Hostname, IP, localisation physique)

□ Isolement initial
  ├─ Système suspect en isolation réseau ? (ACL firewall ou déplug)
  ├─ Sessions utilisateurs terminées ? (logoff administrateur)
  └─ Endpoint EDR = isolé de SOC backhaul ? (pause de synchronisation)

□ Préservation de preuves
  ├─ PERSONNE NE TOUCHE LE CLAVIER (dégâts preuves)
  ├─ Prendre screenshot de l'écran (appareil photo)
  ├─ Noter exact heure/date/qui a touché quoi
  └─ Éteindre système ? NON - garder RAM vivant
```

### **Phase 1 : Minutes 1-5 (escalade formelle)**

```
□ Alerter chain of command
  ├─ SOC Manager : Confirmation incident
  ├─ CISO/Responsable Sécurité : Escalade sévérité
  └─ IT Ops Lead : Préparer forensics

□ Documenter
  ├─ Ouvrir ticket incident unique (ex: INC-2024-001)
  ├─ Timestamp découverte original
  ├─ Énumérer systèmes affectés
  └─ Chaîne de custodie = commence MAINTENANT

□ Collecte rapide (5 min max)
  ├─ Exécuter KAPE triage (résumé à la fin)
  ├─ Dump mémoire (WinPmem)
  ├─ Collecter browser history (copier dossier)
  └─ Preservare logs avant suppression (copy /var/log/ to USB)
```

### **Phase 2 : Minutes 5-30 (confinement initial)**

```
□ Confinement réseau
  ├─ ACL firewall (bloquer C2 communication)
  ├─ Déplacer VLAN si nécessaire (isolation complète)
  └─ Blocks IP attaquant source (ne pas désactiver - laisser pour logs)

□ Arrêt propagation
  ├─ Kill malware processus (si EDR capable)
  ├─ Disabler services malveillants (vérifier avant)
  └─ Scanner tous les endpoints (EDR full scan)

□ Valider isolation
  ├─ Test : système peut-il contacter C2 ? (netstat, firewall logs)
  ├─ Test : utilisateurs peuvent-ils accéder métier critique ? (balance sécurité vs ops)
  └─ Monitoring : EDR + SIEM pour confirmers arrêt propagation
```

### **Phase 3 : Heures 1-6 (early analysis)**

```
□ Analyse initiale preuves collectées
  ├─ KAPE triage parsing (registre, artefacts)
  ├─ Memory dump = requête Volatility (processus, connexions)
  ├─ Hash malware = VirusTotal lookup (famille identifiée ?)
  └─ Timeline : Quand exactement infection démarrée ?

□ Cause racine investigation
  ├─ Vecteur accès ? (email phishing, RDP bruteforce, exploit)
  ├─ Patient zero ? (premier système infecté)
  ├─ Scope : Combien systèmes affectés ? (EDR scan)
  └─ Blast radius : Données compromises ? (logs exfil)

□ Première estimation impact
  ├─ Combien utilisateurs affectés ?
  ├─ Quels systèmes critiques exposés ? (AD, databases, file servers)
  ├─ Données personnelles impliquées ? (RGPD notification mandatory)
  └─ Downtime estimé ? (pour communication management)
```

### **Checklist Personnalisée par Incident Type**

#### **Ransomware Detected :**

```
ADDITIONAL STEPS (en plus des phases 0-3):

□ Pare-feu : Bloquer encryption C2 communication
  └─ Arrêter propagation entre systèmes

□ Backup validation : Tous les backups hors-ligne ?
  └─ Cryptolocker se propage vers NAS/cloud

□ Isolation complète : Tous les endpoint → air-gapped ?
  └─ Pas de réseau interne

□ Ransom note : Sauvegarder pour forensics + OSINT
  └─ Identifier attacker group, negotiation address

□ Décision escalade : Payer rançon ?
  ├─ Dépend assurance cyber + value données vs cost
  └─ Consulter law enforcement AVANT paiement
```

#### **Data Breach (Exfiltration):**

```
ADDITIONAL STEPS:

□ Identification données exfiltrées
  ├─ Chercher logs accès partages/databases
  ├─ Comparer nombre fichiers lecture vs normal usage
  └─ Estimer volume Mo/Gb téléchargées

□ Breach notification
  ├─ Notifier CNIL si données personnelles
  ├─ Délai : 72h maximum (RGPD)
  ├─ Contenu : Quel données, quand, correction
  └─ Préparer communication publique

□ Damage control
  ├─ Rechercher data dumps dark web
  ├─ Contact dark web monitoring service
  ├─ Cyber extortion attempt = tracker
  └─ Potential buyer identification
```

---

## Annexe B : Modèle de Document pour la Chaîne de Custodie

### **Format Officiel (Compatible Cour)**

```
═════════════════════════════════════════════════════════════════════════════
                      CHAÎNE DE CUSTODIE FORMEL
                    Incident Forensique CASE-2024-001
═════════════════════════════════════════════════════════════════════════════

1. IDENTIFICATION DE LA PREUVE

   Numéro de cas :               CASE-2024-001
   Date ouverture :              2024-01-15
   Tribunal compétent :          Tribunal de Grande Instance de Paris
   Enquêteur principal :         Alice Martin (Licencié ANSSI)
   
   Preuves identifiées :
   ├─ Preuve A : Disque dur serveur (Seagate SkyHawk 2TB, S/N ABC123)
   ├─ Preuve B : Image disque (evidence.dd, 2TB)
   ├─ Preuve C : Dump RAM (memory.dump, 32GB)
   └─ Preuve D : Triage KAPE (artefacts Windows)

═════════════════════════════════════════════════════════════════════════════

2. ACQUISITION INITIALE

   Preuve : Disque dur physique (Seagate SkyHawk)
   
   Lieu d'acquisition :          Datacentre Paris-1, Salle serveurs
   Date/Heure acquisition :      2024-01-15 14:40 UTC
   Acquéreur :                   Alice Martin (ANSSI)
   Témoin présent :              Bob Chen (Cabinet juridique X)
   
   Méthode :
   ├─ Hardware utilisé : Tableau Forensique (SAFE-3, write-blocker)
   ├─ Connexion : SATA → USB 3.1 via adaptateur scellé
   ├─ Paramètres : blocksize=4M, bs=4M, DD clone
   └─ Commande exacte : dd if=/dev/sdb of=/mnt/evidence/image.dd bs=4M
   
   Résultat :
   ├─ Taille : 2199023255552 bytes (2 TB exactement)
   ├─ Durée : 2h 15min
   ├─ Erreurs I/O : 0 bad sectors
   └─ Statut : ✅ SUCCÈS

   Hash d'intégrité (Source disque) :
   ├─ MD5 : a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
   ├─ SHA1 : deadbeefcafebabecafebabecafebabecafebabed
   └─ SHA256 : 1111111111111111111111111111111111111111111111111111111111111111

   Signature d'acquisition :
   ├─ Acquéreur : Alice Martin ____________________________ Date: 2024-01-15
   └─ Témoin :    Bob Chen      ____________________________ Date: 2024-01-15

═════════════════════════════════════════════════════════════════════════════

3. TRANSFERT VERS ANALYSTE

   De : Alice Martin (Forensicien, ANSSI)
   À : Charlie Davis (Analyste Sénior, Cabinet X)
   
   Date/Heure transfert :        2024-01-15 18:00 UTC
   Méthode transfert :           Clé USB chiffrée (BitLocker)
   Transporteur :                Alice Martin (accompagnée)
   Emballage : Enveloppe scellée avec numéro case
   
   Hash verification (avant transfert) :
   ├─ MD5 source :   a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 ✅
   ├─ MD5 copie :    a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 ✅
   └─ Résultat : CONFORME - Intégrité vérifiée
   
   Signature transfert :
   ├─ Alice Martin _____________________ Date: 2024-01-15 18:00 UTC
   └─ Charlie Davis ____________________ Date: 2024-01-15 18:15 UTC

═════════════════════════════════════════════════════════════════════════════

4. ANALYSE & MANIPULATIONS

   Analyste : Charlie Davis
   Dates analyse : 2024-01-16 à 2024-01-20
   
   Accès à la preuve :
   ├─ 2024-01-16 09:00 - Montage image disque (lecture seule)
   │                     Signature: CD _____ Heure: 09:00
   ├─ 2024-01-16 14:30 - Analyse Ghidra/Registry
   │                     Signature: CD _____ Heure: 14:30
   ├─ 2024-01-17 10:00 - Dump fichiers malveillants
   │                     Signature: CD _____ Heure: 10:00
   └─ 2024-01-20 16:00 - Fermeture pour report
   
   Hash de l'image analysée (continuous monitoring) :
   └─ SHA256 : 1111111111111111111111111111111111111111111111111111111111111111
               [Vérifié à chaque accès = immuabilité preuve]

   Modifications autorisées :
   └─ [AUCUNE] - Analyse sur copies uniquement

═════════════════════════════════════════════════════════════════════════════

5. RAPPORT & PRÉSENTATION

   Rapport complété :            2024-01-25
   Rapport signé par :           Charlie Davis
   Relecture par :               Alice Martin (auditeur indépendant)
   
   Hash du rapport finalisé :
   ├─ SHA256 : 2222222222222222222222222222222222222222222222222222222222222222
   └─ Signature numérique : [GPG signature ici]

   Présentation en cour :
   ├─ Date : 2024-06-20 09:00
   ├─ Témoin expert : Charlie Davis
   ├─ Audience : Tribunal GI Paris, Salle 5
   └─ Statut preuve : Admissible ✅

═════════════════════════════════════════════════════════════════════════════

6. ARCHIVAGE FINAL

   Stockage preuve :             Coffre-fort sécurisé, Locataire privé
   Localisation physique :       Rue de X, 75000 Paris
   Clé d'accès : Gardé par     Huissier de justice
   
   Durée conservation :          2 ans (conformément loi RGPD + prescriptions)
   Date destruction :            2026-01-15
   Autorisation destruction :    Jugement du tribunal [numéro jugement]

   Signature finale custodian :  _________________________ Date: 2024-06-20

═════════════════════════════════════════════════════════════════════════════
```

---

## Annexe C : Tableau de Correspondance des Artefacts Windows & Utilité

### **Référence Rapide : Quoi Chercher, Où, et Pourquoi**

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

---

### **Matrice : Quoi Chercher par Scenario d'Attaque**

| Scenario | Artefacts Clés | Priority |
|----------|---|---|
| **Malware Execution** | Prefetch, ShimCache, Amcache, UserAssist, Event Log 4688 | CRITICAL |
| **Persistence (Reboot survival)** | Run keys, Services, Scheduled Tasks, Startup folders | CRITICAL |
| **Lateral Movement** | Event Log 4720 (new accounts), 5140 (network shares), RDP Event IDs | CRITICAL |
| **Privilege Escalation** | Services changed, Registry SYSTEM changes, UAC bypass artefacts | CRITICAL |
| **Data Theft** | Recent files, Jump Lists, $MFT (large file copies), Proxy logs | HIGH |
| **Credential Access** | SAM hashes, LSASS dump evidence, .rdp/.ppk files | CRITICAL |
| **Defense Evasion** | Event Log deletion, Prefetch clearing, AV disabled timestamps | HIGH |
| **C2 Communication** | Prefetch "powershell"/"cmd", network shares accessed, DNS queries | CRITICAL |

---

## Annexe D : Ressources & Références

### **Outils Incontournables**

```
=== FORENSICS WINDOWS ===
- KAPE (Acquisition) : kapetriage.com
- Volatility 3 (RAM) : volatility3.readthedocs.io
- Eric Zimmerman Tools (Parsing) : ericzimmerman.github.io
- RegRipper (Registry) : github.com/keydet89/RegRipper3.0
- Ghidra (Reverse Engineering) : ghidra-sre.org

=== FORENSICS LINUX ===
- SIFT Workstation : SANS sift-files.sans.org
- Sleuth Kit : sleuthkit.org
- Plaso (Timeline) : plaso.readthedocs.io
- Autopsy : sleuthkit.org/autopsy

=== NETWORK FORENSICS ===
- Wireshark : wireshark.org
- Zeek : zeek.org
- Suricata : suricata.io
- NetworkMiner : networkminer.org

=== MALWARE ANALYSIS ===
- VirusTotal : virustotal.com
- Hybrid Analysis : hybrid-analysis.com
- YARA : virustotal.github.io/yara
- ClamAV : clamav.net

=== THREAT INTELLIGENCE ===
- MITRE ATT&CK : attack.mitre.org
- CVE Details : cvedetails.com
- Shodan : shodan.io
- URLhaus : urlhaus.abuse.ch
```

### **Formations & Certifications**

```
- GCIH (GIAC Certified Incident Handler) : SANS
- GCFE (GIAC Certified Forensic Examiner) : SANS
- CEH (Certified Ethical Hacker) : EC-Council
- OSCP (Offensive Security Certified Professional) : Offensive Security
- CompTIA Security+ : CompTIA
```

### **Littérature Recommandée**

```
1. "The Art of Memory Forensics" - Ligh, Case, Levy (Volatility bible)
2. "Windows Forensics Analysis" - Carvey (Registry, artefacts)
3. "Network Forensics" - Davidoff, Ham (Pcap analysis)
4. "Incident Response & Computer Forensics" - Mandia, Prosise, Pepe
5. "Malware Analysis" - Sikorski, Honig (Reverse engineering)
```

---

## Annexe E : Exemples de Timeline Complète (Reconstruction)

### **Cas Réel Simplifié : Emotet Infection 3 Jours**

```
═════════════════════════════════════════════════════════════════════════════
                    TIMELINE RECONSTRUCTION
                  INCIDENT CASE-2024-001 : Emotet
═════════════════════════════════════════════════════════════════════════════

JOUR 1 : 2024-01-10 (Infection Initial)
─────────────────────────────────────────

10:00 UTC  [Email Alert]
           From: client@legitimate-bank.fr (SPOOFED)
           Subject: "Invoice for services - Action required"
           Attachment: Invoice_2024.xlsx [MALICIOUS]
           To: jdoe@corp.com
           │
           └─ Source: Cloud EDR logs, email security gateway

10:15 UTC  [User Interaction]
           User jdoe opens Invoice_2024.xlsx in Excel
           └─ Source: Event Log 4688 (Excel.exe process creation)

10:16 UTC  [Macro Execution]
           Excel macro enabled (User clicked "Enable Content")
           Macro downloads payload from hxxp://evil.ru/payload.exe
           └─ Source: Prefetch (Invoice_2024.xlsx accessed)
                      Proxy logs (HTTP to evil.ru)

10:17 UTC  [Malware Execution]
           Payload saved to C:\Users\jdoe\AppData\Local\Temp\pppx.exe
           pppx.exe executed (parent: Explorer.exe)
           └─ Source: Prefetch (pppx.exe first execution)
                      ShimCache (pppx.exe confirmed)
                      Event Log 4688 (parent Explorer)

10:18 UTC  [Initial Reconnaissance]
           Malware checks:
           │
           ├─ Queries local admin groups (net localgroup administrators)
           │  └─ Source: Event Log 4688 (cmd.exe + arguments)
           │
           ├─ Checks if running in VM (checks WMI, drivers)
           │  └─ Source: Registry queries (no artifact - live memory analysis)
           │
           └─ Enumerates running processes (tasklist /v)
              └─ Source: Event Log 4688

10:19 UTC  [Persistence Installation]
           Malware registers itself as scheduled task
           TaskName: "Windows Offline Update"
           Program: C:\ProgramData\WindowsUpdate\update.exe
           Trigger: At startup + every hour
           └─ Source: Task Scheduler logs (Event ID 141)
                      Registry Schedule\TaskCache entry
                      Created timestamp = 10:19 UTC

10:25 UTC  [Lateral Movement Preparation]
           Malware scans local network for shares
           Executes: net view /all  (enumerate computers)
           Executes: net use * \\TARGET\C$ /user:administrator (attempt lateral)
           └─ Source: Event Log 4688 (net commands)

10:30 UTC  [C2 Beacon Begins]
           Malware contacts C2 : 45.133.xxx.xxx:443
           Establishes encrypted HTTPS connection
           Beacon interval: Every 5 minutes
           └─ Source: Firewall logs (outbound ALLOW 45.133.xxx.xxx:443)
                      Zeek conn.log (5 min interval pattern)
                      Certificate analysis (Domain: c2-master.ru)

─────────────────────────────────────────────────────────────────────────────

JOUR 2-3 : 2024-01-11 to 2024-01-12 (Propagation + Exfiltration)
──────────────────────────────────────────────────────────────────

11:00 UTC  [Spreading - RDP Bruteforce]
           Malware attempts crack admin passwords via RDP
           Targets: 10.0.0.100-150 (internal network range)
           │
           ├─ Event Log 4625 (Logon failures) : 5000+ attempts/hour
           │  └─ From: 192.168.1.50 (jdoe's workstation)
           │  └─ To: 10.0.0.* (internal servers)
           │
           └─ Source IP: Initially 192.168.1.50, later compromised hosts

11:45 UTC  [Successful Compromise #2]
           RDP credentials bruteforced on 10.0.0.100 (SQL Server)
           └─ Source: Event Log 4624 (Successful logon)
                      eventID=4624, LogonType=3 (RDP)
                      SourceIP=192.168.1.50

12:00 UTC  [Lateral Movement to Critical System]
           jdoe@corp credentials used to access 10.0.0.100
           SQL Server machine infected with Emotet
           │
           ├─ Malware copies itself to \\10.0.0.100\ADMIN$\update.exe
           │  └─ Event Log 5140 (Network share accessed)
           │  └─ Event Log 4688 (copy command)
           │
           ├─ Scheduled Task created on 10.0.0.100 (persistence)
           │  └─ Event Log 141 (Task created)
           │
           └─ Malware beacons from 10.0.0.100 to C2
              └─ Firewall logs: New outbound 10.0.0.100 → 45.133.xxx.xxx:443

13:30 UTC  [Data Collection]
           Malware enumerates file shares accessible from 10.0.0.100
           Finds : \\FILESERVER\FinancialReports, \\FILESERVER\HRdata
           │
           └─ Collects file listings (dir output captured in memory)
              └─ Volatility: FileList entries in malware memory space

14:00 UTC  [Data Exfiltration Begins]
           C2 commands malware to upload sensitive files
           Targets: *.xlsx, *.docx, *.pdf from FinancialReports
           │
           ├─ Proxy logs: 1200 MB HTTPS to 185.220.xxx.xxx:8443
           │  Byte ratio : upload >> download (asymmetric exfil signature)
           │
           ├─ Firewall logs: Sustained connection 2+ hours
           │  Unusual pattern (normal users = bursty traffic)
           │
           └─ Zeek logs: DNS tunneling detected
              (Side channel exfil via DNS queries containing base64 file chunks)

18:00 UTC  [Human Attacker Interaction]
           C2 operator logs into compromised domain admin account
           From IP: 185.99.xxx.xxx (different C2 infrastructure)
           │
           ├─ Event Log 4624 : LogonType=3 (RDP), username=Administrator
           │  SourceIP=185.99.xxx.xxx
           │
           ├─ Event Log 4688: Attacker opens cmd.exe, powershell.exe
           │  Executes : whoami /all, net group "Domain Admins"
           │
           └─ Remote lateral movement to 10.0.0.200 (Domain Controller)
              Command: psexec.exe -i -s cmd.exe (PsExec toolkit)

─────────────────────────────────────────────────────────────────────────────

JOUR 3 : 2024-01-13 (Detection + Response)
─────────────────────────────────────────────

14:30 UTC  [DETECTION]
           EDR detects Emotet signature on 10.0.0.100
           │
           ├─ Alert: "Emotet C2 Communication Detected"
           │  Severity: CRITICAL
           │
           └─ Escalated to SOC T2 analyst

14:32 UTC  [IMMEDIATE RESPONSE]
           │
           ├─ Endpoint isolation via EDR
           │  └─ IP 10.0.0.100 blocked outbound to all except SIEM
           │
           ├─ Firewall rule deployed
           │  └─ Block outbound from 10.0.0.100 to 45.133.0.0/16, 185.220.0.0/16
           │
           ├─ Admin session revoked
           │  └─ RDP session terminated (attacker booted off)
           │
           └─ Volatility dump initiated
              └─ WinPmem acquisition 32 GB (1.5 hour duration)

15:00 UTC  [FORENSIC ANALYSIS BEGINS]
           │
           ├─ Registry analysis:
           │  └─ Scheduled Task "Windows Offline Update" identified
           │  └─ Persistence vector confirmed
           │
           ├─ Event Log analysis:
           │  └─ RDP bruteforce timeline reconstructed
           │  └─ Lateral movement to Domain Controller identified (CRITICAL)
           │
           ├─ Memory analysis (Volatility):
           │  └─ Emotet process (update.exe) extracted
           │  └─ C2 server list extracted from memory
           │  └─ Injected DLLs identified (code injection vector)
           │
           └─ Scope assessment:
              └─ Patient zero: 192.168.1.50 (jdoe workstation) - initial infection
              └─ Secondary: 10.0.0.100 (SQL Server) - lateral movement
              └─ Risk critical: 10.0.0.200 (DC) - attacker connected
              └─ Data compromise: FinancialReports share (1200 MB exfiltrated)

16:00 UTC  [REMEDIATION BEGINS]
           │
           ├─ Isolate compromised accounts
           │  ├─ jdoe@corp.com : Reset password, revoke all sessions
           │  ├─ SQLSERVER$:
