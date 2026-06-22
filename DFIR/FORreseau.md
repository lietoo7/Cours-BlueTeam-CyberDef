
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
