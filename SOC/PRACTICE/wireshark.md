# TP – Analyse de trafic réseau avec Wireshark
---

## Introduction

Ce TP a pour objectif de vous apprendre à analyser des captures de trafic réseau à l'aide du logiciel Wireshark. Vous apprendrez à identifier les protocoles présents dans une capture, à reconnaître des comportements normaux ou suspects, et à extraire des informations utiles à partir de trames brutes. L'ensemble des manipulations se déroule sur des fichiers PCAP fournis  
 
### ⚠️ Consignes de sécurité

- Ne **jamais** réaliser de capture sur un réseau sans autorisation explicite.
- Les fichiers PCAP fournis sont **strictement réservés à un usage pédagogique**.
- Ne pas tenter de reproduire les attaques observées sur un réseau réel.
- Tout ce qui est analysé ici relève de la **détection**, non de l'exploitation.

---

## Consignes générales

### Méthode d'analyse
1. Ouvrir le fichier PCAP dans Wireshark.
2. Lire d'abord la liste des trames sans filtre pour avoir une vue d'ensemble.
3. Appliquer le filtre indiqué dans chaque partie.
4. Observer les champs demandés dans le panneau du bas (détail des trames).
5. Suivre les flux si nécessaire : clic droit → *Follow > TCP Stream* ou *UDP Stream*.

### Utilisation des filtres
- Les filtres s'écrivent dans la **barre verte** en haut de Wireshark.
- Un filtre valide fait passer la barre en **vert** ; rouge = erreur de syntaxe.
- Combiner les filtres avec `&&` (ET), `||` (OU), `!` (NON).
- Exemple : `dns && ip.src == 192.168.1.1`

### Comment répondre aux questions
- Répondez **avec précision** : indiquez les valeurs exactes relevées (adresses IP, ports, flags, noms, etc.).
- Joignez **la ou les captures d'écran** demandées.
- Pour chaque capture, **annotez** (flèche, cercle) les éléments importants.
- Rédigez en **phrases courtes et claires**.

---

## SOMMAIRE

1. [Trouver les Scans NMAP](#partie-1)
2. [ARP Poisoning & MITM Attack](#partie-2)
3. [Identification des hôtes : DHCP, NetBIOS et Kerberos](#partie-3)
4. [Trafic DNS & ICMP](#partie-4)
5. [Analyse du protocole FTP](#partie-5)
6. [Analyse du protocole : HTTP](#partie-6)
7. [Analyse du protocole : HTTPS](#partie-7)
8. [Analyse du protocole : SFTP](#partie-8)
9. [Analyse du protocole : SSH](#partie-9)

---

## Partie 1 — Trouver les Scans NMAP

**Objectif pédagogique :** Identifier les signatures caractéristiques d'un scan de ports réalisé avec NMAP à partir de l'analyse des flags TCP et de la cadence des connexions.

### Étapes dans Wireshark

1. Appliquer le filtre : `tcp`
2. Trier par **IP source** pour regrouper les paquets d'un même hôte.
3. Observer la colonne **Info** : chercher des séquences de `SYN` vers de nombreux ports différents.
4. Appliquer ensuite : `tcp.flags.syn == 1 && tcp.flags.ack == 0`
5. Vérifier les **réponses** : `RST/ACK` = port fermé, `SYN/ACK` = port ouvert, absence de réponse = port filtré.
6. Pour un scan UDP : `udp && icmp.type == 3` (ICMP Port Unreachable en retour).
7. Identifier l'IP source suspecte et noter les ports ciblés.

**Mots-clés à relever :**
- Flags TCP : `SYN`, `RST`, `RST/ACK`, `SYN/ACK`
- Ports ciblés (22, 80, 443, 3389…)
- Adresse IP source du scanner
- Intervalle de temps très court entre les paquets (< 1 ms)

### Livrable élève

- **Capture 1 :** Vue filtrée montrant la séquence de SYN vers plusieurs ports (annoter l'IP source et au moins 3 ports).
- **Capture 2 :** Détail d'une trame SYN (panneau bas) montrant les flags TCP.

**Questions :**
1. Quelle est l'adresse IP de l'hôte qui effectue le scan ? Justifiez votre réponse.
2. Quels flags TCP sont caractéristiques d'un scan SYN (dit « half-open ») ? Pourquoi ce scan est-il discret ?
3. Citez trois ports ouverts découverts par le scan et les services associés.
4. Comment distingue-t-on un port fermé d'un port filtré dans les réponses réseau ?
---

## Partie 2 — ARP Poisoning & MITM Attack

**Objectif pédagogique :** Détecter une attaque ARP Poisoning en identifiant les réponses ARP falsifiées et comprendre comment elles permettent une attaque de type Man-in-the-Middle (MITM).

### Étapes dans Wireshark

1. Appliquer le filtre : `arp`
2. Observer les messages **ARP Reply** (is-at) non sollicités (sans ARP Request préalable).
3. Repérer une adresse **MAC identique** associée à plusieurs **IP différentes**.
4. Utiliser : *Analyze > Expert Information* pour voir les alertes de duplication ARP.
5. Trier par **adresse MAC source** pour détecter l'hôte malveillant.
6. Vérifier si le trafic d'une victime transite par une IP intermédiaire (l'attaquant).

**Mots-clés à relever :**
- `ARP who-has` (Request) / `ARP is-at` (Reply)
- Adresse MAC dupliquée sur plusieurs IP
- Gratuitous ARP (réponse sans requête)
- Adresse de la passerelle usurpée

### Livrable élève

- **Capture 1 :** Filtre ARP actif — montrer plusieurs Reply avec la même MAC pour des IP différentes (annoter la MAC suspecte).
- **Capture 2 :** Détail d'un paquet ARP Reply falsifié (champs Sender MAC / Sender IP / Target IP).

**Questions :**
1. Quelle adresse MAC envoie des réponses ARP pour plusieurs adresses IP ? Qu'est-ce que cela indique ?
2. Quelle est la différence entre un ARP Request et un ARP Reply ? Lequel est utilisé pour l'empoisonnement ?
3. Comment un attaquant MITM peut-il intercepter le trafic entre deux hôtes grâce à l'ARP Poisoning ?

 
---

## Partie 3 — Identification des hôtes : DHCP, NetBIOS et Kerberos

**Objectif pédagogique :** Reconstituer l'identité des hôtes du réseau (nom, IP, domaine) à partir des échanges DHCP, NetBIOS/NBNS et Kerberos.

### Étapes dans Wireshark

**DHCP :**
1. Filtre : `dhcp` ou `bootp`
2. Observer la séquence : `Discover → Offer → Request → ACK`
3. Dans le paquet **DHCP ACK**, relever : IP attribuée, masque, passerelle, serveur DNS, nom d'hôte (option 12), domaine (option 15).

**NetBIOS / NBNS :**
1. Filtre : `nbns`
2. Observer les **Name Query** (qui cherche qui ?) et **Name Response**.
3. Relever les noms NetBIOS des machines (souvent en majuscules).

**Kerberos :**
1. Filtre : `kerberos`
2. Observer les messages : `AS-REQ` (demande de ticket), `AS-REP` (réponse du KDC), `TGS-REQ`, `TGS-REP`.
3. Relever le **nom d'utilisateur** (cname) et le **realm** (nom de domaine AD).

**Mots-clés à relever :**
- DHCP : `Discover`, `Offer`, `Request`, `ACK`, option 12 (hostname), option 15 (domain)
- NBNS : `Name Query`, `Name Response`, nom NetBIOS
- Kerberos : `AS-REQ`, `AS-REP`, `TGS-REQ`, `TGS-REP`, `cname`, `realm`

### Livrable élève

- **Capture 1 :** Séquence DHCP complète (les 4 messages) — annoter les options importantes.
- **Capture 2 :** Un message Kerberos AS-REQ avec le nom d'utilisateur et le domaine visibles.

**Questions :**
1. Dressez un tableau avec : Nom d'hôte, Adresse IP, Adresse MAC — pour au moins deux machines identifiées via DHCP.
2. Quel protocole permet de résoudre les noms NetBIOS en adresses IP ? Dans quel contexte est-il utilisé ?
3. Que contient un message Kerberos AS-REQ ? Quelle information permet d'identifier l'utilisateur ?
4. Quel est le nom du domaine Active Directory identifié dans les échanges Kerberos ?

 
---

## Partie 4 — Trafic DNS & ICMP

**Objectif pédagogique :** Analyser les requêtes DNS pour identifier les domaines consultés et les échanges ICMP pour diagnostiquer la connectivité réseau.

### Étapes dans Wireshark

**DNS :**
1. Filtre : `dns`
2. Observer les **Query** (type A, AAAA, MX, PTR…) et les **Response**.
3. Dans le détail d'une trame, relever : nom de domaine demandé, type d'enregistrement, IP retournée, TTL.
4. Chercher des requêtes vers des domaines suspects (longues chaînes aléatoires = possible DNS tunneling).

**ICMP :**
1. Filtre : `icmp`
2. Identifier les messages : `Echo Request` (type 8) et `Echo Reply` (type 0).
3. Relever : IP source, IP destination, TTL, taille du paquet, séquence des échanges.
4. Repérer d'éventuels messages d'erreur : `Destination Unreachable` (type 3), `Time Exceeded` (type 11 = traceroute).

**Mots-clés à relever :**
- DNS : `Query`, `Response`, types `A`, `AAAA`, `PTR`, `MX`, TTL, NXDOMAIN (domaine inexistant)
- ICMP : `Echo Request`, `Echo Reply`, type 3 (unreachable), type 11 (TTL exceeded), `icmp.type`, `icmp.code`

### Livrable élève

- **Capture 1 :** Une paire Query/Response DNS — annoter le domaine, le type et l'IP résolue.
- **Capture 2 :** Une séquence ICMP Echo Request / Reply — annoter les IPs et le TTL.

**Questions :**
1. Quelle est la différence entre un enregistrement DNS de type A et de type AAAA ?
2. Qu'indique un message DNS de type NXDOMAIN ?
3. Quel type ICMP correspond à un ping classique (Echo Request) ? Et à la réponse ?
4. Comment Wireshark permet-il de détecter un éventuel traceroute dans le trafic ICMP ?

 
---

## Partie 5 — Analyse du protocole FTP

**Objectif pédagogique :** Comprendre le fonctionnement du protocole FTP et identifier les risques liés à la transmission de credentials en clair.

### Étapes dans Wireshark

1. Filtre : `ftp`
2. Observer la **séquence de connexion** : commandes `USER` puis `PASS`.
3. Relever les **codes de réponse** du serveur : 220 (bienvenue), 331 (mot de passe requis), 230 (connecté), 530 (échec).
4. Suivre le flux complet : clic droit sur une trame FTP → *Follow > TCP Stream*.
5. Chercher les commandes de navigation : `LIST`, `CWD`, `RETR` (téléchargement), `STOR` (envoi).
6. Pour le trafic de données FTP : filtre `ftp-data` (port 20 ou port passif).

**Mots-clés à relever :**
- Commandes : `USER`, `PASS`, `LIST`, `RETR`, `STOR`, `QUIT`, `CWD`, `PWD`
- Codes : 220, 230, 331, 530, 226 (transfert OK)
- Mode actif vs passif (`PORT` / `PASV`)
- Credentials en clair dans le flux

### Livrable élève

- **Capture 1 :** Flux TCP FTP complet (Follow TCP Stream) — identifier et annoter les identifiants (nom d'utilisateur, mot de passe).
- **Capture 2 :** Trame de commande `RETR` ou `LIST` — annoter le nom de fichier ou le répertoire.

**Questions :**
1. Quels identifiants (login et mot de passe) avez-vous trouvés dans le flux FTP ? Que cela révèle-t-il sur la sécurité du protocole ?
2. Quelle est la différence entre les modes FTP actif et passif ?
3. Quel code de retour indique une connexion FTP réussie ? Et un échec d'authentification ?
4. Quel protocole conseilleriez-vous à la place de FTP pour sécuriser les transferts ? Pourquoi ?
 
---

## Partie 6 — Analyse du protocole : HTTP

**Objectif pédagogique :** Analyser les échanges HTTP pour identifier les méthodes utilisées, les ressources demandées et les données potentiellement exposées.

### Étapes dans Wireshark

1. Filtre : `http`
2. Observer les **requêtes** : méthode (`GET`, `POST`, `PUT`…), URI, version HTTP, headers (Host, User-Agent, Cookie…).
3. Observer les **réponses** : code de statut (200, 301, 404, 500…), Content-Type.
4. Pour les **POST** : chercher des formulaires soumis → *Follow > TCP Stream* → chercher les champs `username=`, `password=`.
5. Filtre ciblé sur les POST : `http.request.method == "POST"`
6. Inspecter le corps de la requête dans le panneau bas : *Line-based text data*.

**Mots-clés à relever :**
- Méthodes : `GET`, `POST`, `HEAD`, `PUT`, `DELETE`
- Codes HTTP : 200 (OK), 301/302 (redirect), 401 (auth), 403 (interdit), 404 (not found), 500 (erreur serveur)
- En-têtes : `Host`, `User-Agent`, `Cookie`, `Set-Cookie`, `Authorization`
- Corps de requête POST : paramètres en clair

### Livrable élève

- **Capture 1 :** Une requête GET — annoter l'URI, le Host et le User-Agent.
- **Capture 2 :** Un flux TCP complet d'une requête POST (Follow TCP Stream) — annoter les données soumises.

**Questions :**
1. Quelle est la différence entre une requête HTTP GET et POST ?
2. Quelles données sensibles avez-vous identifiées dans le trafic HTTP ? Comment aurait-on pu les protéger ?
3. Qu'indique un code de réponse HTTP 401 ? Et 403 ?
4. Quel en-tête HTTP permet d'identifier le navigateur utilisé par le client ?

 
---

## Partie 7 — Analyse du protocole : HTTPS

**Objectif pédagogique :** Comprendre la négociation TLS (handshake) et identifier les métadonnées visibles dans un flux HTTPS malgré le chiffrement.

### Étapes dans Wireshark

1. Filtre : `tls` ou `ssl`
2. Observer la séquence du **TLS Handshake** :
   - `Client Hello` → version TLS, cipher suites proposées, **SNI** (nom de domaine dans l'extension server_name)
   - `Server Hello` → cipher suite choisie, version TLS retenue
   - `Certificate` → certificat du serveur (CN, organisation, autorité)
   - `Client Key Exchange` / `Change Cipher Spec`
   - `Application Data` (chiffré, illisible)
3. Filtre pour isoler le Client Hello : `tls.handshake.type == 1`
4. Filtre pour le Server Hello : `tls.handshake.type == 2`
5. Chercher le champ **SNI** : *Transport Layer Security > Extension: server_name*.

**Mots-clés à relever :**
- `Client Hello`, `Server Hello`, `Certificate`, `Change Cipher Spec`, `Application Data`
- **SNI** (Server Name Indication) — nom de domaine en clair
- Version TLS (1.2 / 1.3)
- Cipher suite retenue (ex. : `TLS_AES_256_GCM_SHA384`)
- CN du certificat, autorité de certification (CA)

### Livrable élève

- **Capture 1 :** Client Hello — annoter le SNI et les cipher suites proposées.
- **Capture 2 :** Certificat serveur — annoter le CN (Common Name) et l'autorité émettrice.

**Questions :**
1. Qu'est-ce que le SNI et pourquoi est-il visible en clair dans un flux HTTPS ?
2. Quelle version de TLS est utilisée dans votre capture ? Est-ce une version sécurisée ?
3. Que contient le message `Certificate` envoyé par le serveur ? À quoi sert-il ?
4. Que signifie `Application Data` dans la trace Wireshark ? Peut-on en lire le contenu ? Pourquoi ?

---

## Partie 8 — Analyse du protocole : SFTP

**Objectif pédagogique :** Distinguer SFTP de FTP en observant que le contenu des transferts est chiffré, et identifier les éléments visibles dans la couche SSH sous-jacente.

### Étapes dans Wireshark

1. Filtre : `ssh` (SFTP utilise SSH comme transport, port 22 par défaut)
2. Observer l'établissement de la connexion SSH : bannière (`SSH-2.0-...`), échange de clés (`Key Exchange Init`).
3. Constater que les données SFTP sont **encapsulées et chiffrées** dans SSH : on voit uniquement des paquets `Encrypted Packet`.
4. Comparer avec la partie FTP : aucun nom d'utilisateur, aucun mot de passe, aucun nom de fichier n'est lisible.
5. Filtre pour la bannière SSH : `ssh.protocol`
6. Suivre le flux TCP : observer que tout le contenu applicatif est opaque.

**Mots-clés à relever :**
- `SSH-2.0` (bannière de version)
- `Key Exchange Init`, `New Keys`
- `Encrypted Packet` (données illisibles)
- Port 22 (SSH/SFTP)
- Absence totale de credentials en clair

### Livrable élève

- **Capture 1 :** Échange SSH initial — annoter la bannière et le Key Exchange.
- **Capture 2 :** Flux TCP complet (Follow TCP Stream) — montrer l'absence de données lisibles.

**Questions :**
1. Sur quel port fonctionne SFTP ? Quel protocole de transport utilise-t-il ?
2. Comparez ce que vous voyez dans un flux SFTP et dans un flux FTP : quelles différences notez-vous ?
3. Pourquoi SFTP est-il considéré comme plus sûr que FTP ?
4. Qu'est-ce que la bannière SSH et quelle information utile contient-elle pour un analyste ?

 
---

## Partie 9 — Analyse du protocole : SSH

**Objectif pédagogique :** Identifier les caractéristiques d'une connexion SSH dans une capture réseau et comprendre pourquoi son contenu reste protégé.

### Étapes dans Wireshark

1. Filtre : `ssh`
2. Observer la **séquence d'établissement** :
   - Échange des bannières : client et serveur annoncent leur version SSH (`SSH-2.0-OpenSSH_8.x`…)
   - `Key Exchange Init` : algorithmes proposés de part et d'autre
   - `Diffie-Hellman Key Exchange` : échange de clés (ECDH, DH…)
   - `New Keys` : confirmation de l'activation du chiffrement
   - `Encrypted Packet` : toute la session chiffrée
3. Filtre sur les bannières : `ssh.protocol`
4. Filtre sur l'échange de clés : `ssh.message_code`
5. Comparer la taille et la régularité des paquets chiffrés (activité interactive vs transfert fichier).

**Mots-clés à relever :**
- `SSH-2.0` (bannière)
- `Key Exchange Init`, `Diffie-Hellman`, `Elliptic Curve DH`
- `New Keys` (bascule vers le chiffrement)
- `Encrypted Packet`
- Algorithmes : `aes256-ctr`, `hmac-sha2-256`, `curve25519-sha256`

### Livrable élève

- **Capture 1 :** Les 4 à 5 premières trames SSH — annoter les bannières client et serveur.
- **Capture 2 :** Détail d'un paquet `Key Exchange Init` — lister les algorithmes proposés.

**Questions :**
1. Quelle version de SSH est utilisée dans la capture ? Comment la lisez-vous dans Wireshark ?
2. Quel mécanisme permet à deux hôtes SSH d'établir une clé de session partagée sans qu'elle transite en clair sur le réseau ?
3. Qu'est-ce que le message `New Keys` indique dans la séquence SSH ?
4. Un analyste peut-il lire le contenu d'une session SSH correctement établie ? Justifiez votre réponse.

 
---

## Aide rapide — 10 filtres Wireshark essentiels

| Filtre | Explication |
|---|---|
| `arp` | Affiche tous les échanges ARP (résolution MAC/IP) ; utile pour détecter l'ARP poisoning. |
| `dns` | Isole les requêtes et réponses DNS ; permet de voir les domaines consultés et les éventuelles anomalies. |
| `dhcp` | Filtre les échanges DHCP (Discover/Offer/Request/ACK) pour identifier les hôtes et leur configuration réseau. |
| `nbns` | Affiche le trafic NetBIOS Name Service ; utile pour retrouver les noms de machines Windows sur le réseau local. |
| `kerberos` | Isole les échanges Kerberos (AS-REQ/REP, TGS-REQ/REP) pour identifier les utilisateurs et le domaine Active Directory. |
| `tls` | Affiche le trafic TLS/HTTPS ; permet d'analyser le handshake, le SNI et les certificats sans déchiffrer les données. |
| `http` | Filtre uniquement le trafic HTTP en clair ; permet de lire les requêtes, réponses et données de formulaires. |
| `ftp` | Affiche les commandes et réponses FTP ; permet de voir les identifiants, commandes et codes de statut en clair. |
| `ssh` | Isole le trafic SSH (et SFTP) ; utile pour observer l'échange de clés et confirmer le chiffrement de la session. |
| `icmp` | Affiche les messages ICMP (ping, unreachable, TTL exceeded) ; permet de diagnostiquer la connectivité et détecter les traceroutes. |

---
 
