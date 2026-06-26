L’analyse du trafic réseau (Network Traffic Analysis, NTA) est un processus qui consiste à capturer, inspecter et analyser des données pendant qu’elles circulent au sein d’un réseau. Son objectif est d’obtenir une visibilité complète et de comprendre ce qui est communiqué à l’intérieur comme à l’extérieur du réseau.

Il est important de souligner que la NTA n’est pas un synonyme de l’outil Wireshark. Elle va plus loin : c’est une combinaison de la corrélation de plusieurs journaux (logs), de l’inspection approfondie des paquets (Deep Packet Inspection, DPI) et de statistiques de flux réseau (network flow statistics) avec des objectifs précis et définis (que nous aborderons plus tard).

Savoir analyser le trafic réseau est une compétence essentielle, non seulement pour un analyste SOC L1 en devenir, mais aussi pour de nombreux autres rôles des équipes blue team et red team. En tant qu’analyste L1, vous devez être capable de naviguer dans la « mer » d’informations réseau et de comprendre ce qui est normal et ce qui s’écarte de la référence (baseline).

Dans cette section, nous nous concentrerons sur la définition de l’analyse de trafic réseau, sur la raison pour laquelle vous en avez besoin, sur ce que vous pouvez observer et sur la manière dont vous pouvez observer le trafic réseau, ainsi que sur certaines sources et certains flux de trafic réseau que vous devez connaître.

## À quoi sert l’analyse du trafic réseau ?

Pourquoi devrait-on analyser le trafic réseau ? Avant de répondre à cette question, examinons le scénario suivant.

### Contournement DNS (DNS Tunneling) et « Beaconing »
Vous êtes analyste SOC et vous recevez une alerte indiquant qu’un nombre inhabituel de requêtes DNS provient d’une machine nommée WIN-016 avec l’adresse IP 192.168.1.16. Les logs DNS du pare-feu montrent plusieurs requêtes DNS envoyées vers le même TLD, à chaque fois avec un sous-domaine différent.

2025-10-03 09:15:23    SRC=192.168.1.16      QUERY=aj39skdm.malicious-tld.com    QTYPE=A      
2025-10-03 09:15:31    SRC=192.168.1.16      QUERY=msd91azx.malicious-tld.com    QTYPE=A     
2025-10-03 09:15:45    SRC=192.168.1.16      QUERY=cmd01.malicious-tld.com       QTYPE=TXT     
2025-10-03 09:15:45    SRC=192.168.1.16      QUERY=cmd01.malicious-tld.com       QTYPE=TXT     

À partir des logs DNS, nous pouvons récupérer les informations suivantes :

- Requête et type de requête (query and querytype)
- Sous-domaine et domaine de premier niveau (subdomain and top-level domain) : on peut vérifier via des outils comme abuseDB ou VirusTotal si le domaine est malveillant
- Adresse IP de l’hôte (host IP) : on peut identifier le système qui émet les requêtes DNS
- Adresse IP de destination (destination IP) : on peut utiliser des outils comme AbuseIPDB (ouvre un nouvel onglet) ou VirusTotal (ouvre un nouvel onglet) pour vérifier si l’IP est signalée comme malveillante
- Horodatage (timestamp) : on peut construire une chronologie (timeline) reliant les différentes requêtes suspectes

Cependant, les logs DNS ne contiennent pas davantage d’informations, donc il est difficile de tirer une conclusion uniquement à partir de cela. Nous devrons inspecter le trafic DNS plus en profondeur et vérifier le contenu des requêtes DNS et des réponses. Cela nous permettra de déterminer la nature de ces requêtes et réponses.

Ce scénario est un exemple parfait de raison pour laquelle on a besoin d’une analyse du trafic réseau. Les pare-feu et d’autres équipements enregistrent les requêtes DNS et leurs réponses, mais pas leur contenu. Les attaquants pourraient, par exemple, utiliser des enregistrements TXT pour envoyer des instructions de Command and Control (C2) à un système compromis. On peut le découvrir en inspectant le contenu des requêtes DNS. Le fragment de capture de paquet ci-dessous montre le contenu d’une réponse DNS qui contient des commandes C2.

### Système de noms de domaine (réponse)
- **Domain Name System (response)**
- Transaction ID : 0x4a2b  
- Flags : 0x8180 Réponse de requête standard, pas d’erreur  
  - 1... .... .... .... = Réponse : le message est une réponse  
  - .... .... .... 0000 = RCODE : pas d’erreur (0)  
- Questions : 1  
- Answer RRs : 1  
- Authority RRs : 0  
- Additional RRs : 0  

**Requêtes**
- cmd1.evilc2.com : type TXT, classe IN  

**Réponses**
- cmd1.evilc2.com : type TXT, classe IN, TTL 60, longueur TXT : 20  
  - TXT : "SSBsb3ZlIHlvdXIgY3VyaW91c2l0eQ=="

## Pourquoi devriez-vous analyser le trafic réseau ?
En général, nous allons utiliser l’analyse du trafic réseau pour :

- Surveiller les performances du réseau
- Vérifier les anomalies dans le réseau (par ex. pics soudains de performance, réseau lent, etc.)
- Inspecter le contenu des communications suspectes, en interne comme en externe (par ex. exfiltration via DNS, téléchargement d’un fichier ZIP malveillant via HTTP, mouvement latéral, etc.)

Du point de vue d’un SOC, l’analyse du trafic réseau aide :

- À détecter une activité suspecte ou malveillante
- À reconstituer les attaques pendant la réponse à incident
- À vérifier et valider des alertes

Voici deux autres scénarios illustrant l’importance de l’analyse du trafic réseau :

- D’après les logs d’un poste utilisateur, le système a commencé à s’écarter de son comportement normal vers 16 h UTC. En analysant le trafic réseau entrant et sortant de ce système, nous avons trouvé une requête HTTP suspecte et avons pu en extraire un fichier ZIP malveillant.
- Nous avons reçu une alerte indiquant qu’un poste utilisateur envoie beaucoup de requêtes DNS par rapport à la référence (baseline) du réseau. En inspectant les requêtes DNS, nous avons découvert que des données étaient exfiltrées grâce à une technique appelée **DNS tunneling**.

 ## Que peut-on observer dans le trafic réseau ?

La meilleure façon de montrer le trafic qu’on peut observer dans un réseau est d’utiliser l’architecture implémentée dans presque tous les équipements disposant d’une interface réseau : la pile TCP/IP.
```text
 
+---------------------------+
|      Applications        |
| (HTTP/HTTPS, DNS, SMTP)  |
+-------------+-------------+
              |
              v
+---------------------------+
|        Transport         |
|        TCP / UDP         |
+-------------+-------------+
              |
              v
+---------------------------+
|          Internet        |
|      IP (v4/v6) / ICMP   |
+-------------+-------------+
              |
              v
+---------------------------+
|  Liaison de données /    |
|     Accès réseau         |
| (Ethernet, Wi‑Fi, PPP)   |
+-------------+-------------+
              |
              v
+---------------------------+
|   Support physique       |
| (câble, ondes radio, etc)|
+---------------------------+
```
 
Les logs incluent souvent des morceaux de ces en-têtes, mais jamais les détails complets du paquet. C’est justement pour cela qu’on a besoin d’une analyse du trafic réseau.

### Couche Application
À la couche application, on trouve deux structures d’information importantes : les informations d’en-tête de l’application et les données de l’application elles-mêmes (charge utile, payload). Ces informations varient selon le protocole de couche application utilisé.

Regardons un exemple avec HTTP.

Les extraits de code ci-dessous montrent les en-têtes applicatifs d’un client envoyant une requête GET, ainsi que la réponse du serveur. La plupart des proxys web et des pare-feu journalisent ces en-têtes. Ce qu’ils ne journalisent pas, en revanche, c’est la charge utile (payload).

Dans la requête GET, on peut déterminer que le client demande un fichier nommé `suspicious_package.zip`. La réponse du serveur inclut un code `200`, ce qui signifie que la requête a été acceptée. Cependant, ce que l’on ne peut pas voir dans les logs, c’est le contenu du fichier ZIP (mis en évidence en jaune).

**Requête**

```text
GET /downloads/suspicious_package.zip HTTP/1.1
Host: www.tryhackrne.thn
User-Agent: curl/7.85.0
Accept: */*
Connection: close
```

**Réponse**

```text
HTTP/1.1 200 OK
Date: Mon, 29 Sep 2025 10:15:30 GMT
Server: nginx/1.18.0
Content-Type: application/zip
Content-Length: 10485760
Content-Disposition: attachment; filename="suspicious_package.zip"
Last-Modified: Mon, 29 Sep 2025 09:54:00 GMT
ETag: "5d8c72-9f8a1c-3a2b4c"
Accept-Ranges: bytes
Connection: close
[binary ZIP file bytes follow — 10,485,760 bytes]
```

### Couche Transport
La charge utile et l’en-tête de l’application sont segmentés et encapsulés à la couche transport en morceaux plus petits. Chaque morceau inclut un en-tête de transport, le plus souvent TCP ou UDP.

Regardons les entrées de log du pare-feu ci-dessous :

```text
2025-10-13 09:15:32 ACCEPT TCP src=192.168.1.45 dst=172.217.22.14 sport=51432 dport=443 flags=SYN len=60
2025-10-13 09:15:32 ACCEPT TCP src=172.217.22.14 dst=192.168.1.45 sport=443 dport=51432 flags=SYN,ACK len=60
```

Les logs de pare-feu incluent souvent les ports source et destination ainsi que les flags, mais les autres champs ne sont généralement pas inclus. Pourtant, ces éléments peuvent être utiles pour détecter certains types d’attaques, comme le **session hijacking** (détournement de session).

Le session hijacking peut être détecté en analysant les numéros de séquence (sequence numbers) inclus dans l’en-tête. Si les numéros de séquence sont soudainement très éloignés les uns des autres, une investigation plus poussée est nécessaire.

Le résultat ci-dessous montre une série de paquets capturés avec Wireshark.

```text
No.     Time        Source          Destination     Protocol Length  Info
1       0.000000    192.168.1.45    172.217.22.14   TCP      74      51432 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460
2       0.000120    172.217.22.14   192.168.1.45    TCP      74      80 → 51432 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460
3       0.000220    192.168.1.45    172.217.22.14   TCP      66      51432 → 80 [ACK] Seq=1 Ack=1 Win=64240 Len=0
4       0.010500    192.168.1.45    172.217.22.14   TCP      1514    51432 → 80 [PSH, ACK] Seq=1 Ack=1 Win=64240 Len=1460
5       0.010620    172.217.22.14   192.168.1.45    TCP      66      80 → 51432 [ACK] Seq=1 Ack=1461 Win=65535 Len=0
6       0.020100    192.168.99.200  172.217.22.14   TCP      74      51432 → 80 [PSH, ACK] Seq=34567232 Ack=1 Win=64240 Len=20
```

- Les 3 premières lignes montrent une poignée de main TCP normale (3-way handshake).
- Les lignes 4 et 5 montrent un transfert de données légitime.
- La ligne 6 montre un paquet provenant d’une autre source qui essaie de s’insérer dans la session. Notez le saut massif dans le numéro de séquence.

### Couche Internet
Quand la couche transport envoie un segment, la couche Internet ajoute son propre en-tête. Si le segment est plus grand que l’Unité Maximale de Transmission (MTU), il est divisé en fragments et un en-tête est ajouté à chacun d’eux.

Les champs le plus souvent journalisés sont l’adresse IP source, l’adresse IP destination et le TTL. Cela suffit pour la plupart des cas d’usage.

Mais si, par exemple, nous voulons détecter des **attaques par fragmentation**, nous devons aussi inspecter les champs *fragment offset* et *total length*. Il existe différentes variantes d’attaques par fragmentation.

Par exemple, un attaquant peut créer de très petits fragments pour contourner l’IDS, ou perturber le réassemblage en utilisant des plages d’octets qui se chevauchent.

L’exemple ci-dessous montre des plages d’octets qui se chevauchent : le décalage de la ligne 3 (en surbrillance jaune) chevauche celui de la ligne 2. Cela signifie que le paquet complet peut être réassemblé de différentes façons.

Les attaquants peuvent utiliser cette technique pour contourner un IDS, par exemple.

```text
No.   Time       Source        Destination   Protocol Length Info
1     0.000000   203.0.113.45  192.168.1.10  UDP      1514    Fragmented IP protocol (UDP) (id=0x1a2b) [MF] Offset=0, Len=1480
2     0.000015   203.0.113.45  192.168.1.10  UDP      1514    Fragmented IP protocol (UDP) (id=0x1a2b) [MF] Offset=1480, Len=1480
3     0.000030   203.0.113.45  192.168.1.10  UDP       600    Fragmented IP protocol (UDP) (id=0x1a2b) Offset=1480, Len=64   <-- Overlap
4     0.000045   192.168.1.10  203.0.113.45  ICMP      98     Destination unreachable (Fragment reassembly time exceeded)
```

### Couche Lien (Link)
Une fois que la couche Internet a fini d’encapsuler, le paquet IP est envoyé à la couche lien. La couche lien ajoute aussi son en-tête, avec davantage d’informations d’adressage.

La plupart des logs affichent les adresses MAC source et destination. Pour certains types d’attaques, par exemple l’**ARP poisoning** (empoisonnement ARP) ou l’usurpation, les informations présentes dans les logs ne sont pas suffisantes. Pour ces types d’attaques, il faut le paquet complet et le contexte.

Ce que vous ne pouvez pas voir dans un log, par exemple, c’est quand l’adresse MAC apparaît depuis plusieurs interfaces, ou quand beaucoup de requêtes ARP gratuites (*gratuitous ARP*) sont envoyées avec des adresses MAC en conflit.

L’exemple ci-dessous montre une capture qui détaille une attaque d’ARP poisoning : l’hôte ayant l’IP 192.168.1.200 répond à chaque requête ARP avec la même MAC.

```text
No.   Time       Source           Destination      Protocol Length Info
1     0.000000   192.168.1.1      Broadcast        ARP      60     Who has 192.168.1.10? Tell 192.168.1.1
2     0.000025   192.168.1.10     192.168.1.1      ARP      60     192.168.1.10 is at 00:11:22:33:44:55
3     1.002010   192.168.1.200    192.168.1.1      ARP      60     192.168.1.10 is at aa:bb:cc:dd:ee:ff  <-- Attacker spoof
4     1.002015   192.168.1.200    192.168.1.10     ARP      60     192.168.1.1 is at aa:bb:cc:dd:ee:ff  <-- Attacker spoof
5     1.100000   192.168.1.10     172.217.22.14    TCP      74     54433 → 80 [SYN] Seq=0 Win=64240 Len=0
6     1.100120   192.168.1.200    172.217.22.14    TCP      74     54433 → 80 [SYN] Seq=0 Win=64240 Len=0  <-- Relayed via attacker
```
### Sources
Il existe deux sources principales de trafic réseau : les appareils d’extrémité (endpoints) et les appareils intermédiaires (intermediary devices). Ces appareils se trouvent à la fois dans le LAN (réseau local) et le WAN (réseau étendu).

### Sources intermédiaires
Ce sont les appareils par lesquels le trafic passe principalement. Même s’ils génèrent une partie du trafic, celle-ci est nettement inférieure à celle produite par les appareils d’extrémité. Dans cette catégorie, on trouve notamment : les pare-feu, les commutateurs (switches), les proxys web, les IDS, les IPS, les routeurs, les points d’accès, les contrôleurs de réseau sans fil (wireless LAN controllers), et bien d’autres. C’est peut-être moins pertinent pour nous, mais toute l’infrastructure des fournisseurs d’accès à Internet (FAI) fait aussi partie de cette catégorie.

Le trafic qui provient de ces appareils est généré par des services comme les protocoles de routage (EIGRP, OSPF, BGP), les protocoles de gestion (SNMP, PING), les protocoles de journalisation (SYSLOG), et d’autres protocoles de support (ARP, STP, DHCP).

### Sources d’extrémité
Ce sont les appareils à partir desquels le trafic démarre et où il se termine. Les appareils d’extrémité concentrent l’essentiel de la bande passante du réseau. Les dispositifs qui entrent dans cette catégorie sont : les serveurs, les postes hôtes (hosts), les objets connectés (IoT), les imprimantes, les machines de laboratoire, les ressources cloud, les téléphones mobiles, les tablettes, et bien d’autres encore.

### Flots (Flows)
Un flux de trafic réseau est généralement déterminé par les services disponibles dans le réseau, tels que Active Directory, SMB, HTTPS, etc. Dans un réseau d’entreprise typique, on peut regrouper ces flux en trafic Nord-Sud et Est-Ouest.

### Trafic Nord-Sud
Le trafic NS est souvent étroitement surveillé puisqu’il circule du LAN vers le WAN et inversement. Les services les plus connus dans cette catégorie sont les protocoles client-serveur comme HTTPS, DNS, SSH, VPN, SMTP, RDP, et bien d’autres. Chaque protocole possède deux flux : ingress (entrant) et egress (sortant). Tout ce trafic passe d’une manière ou d’une autre par le pare-feu. Configurer correctement les règles du pare-feu et la journalisation (logging) est essentiel pour la visibilité.

### Trafic Est-Ouest
Le trafic EW reste à l’intérieur du LAN de l’entreprise, donc il est souvent moins surveillé. Toutefois, il est important de suivre ces flux. Lorsque le réseau est compromis, un attaquant exploite souvent différents services en interne pour se déplacer latéralement (mouvement latéral) dans le réseau. Comme on le voit ci-dessous, il existe de nombreux services dans cette catégorie. Cliquez sur chaque catégorie pour voir quels services elle contient.

- Services de répertoire, d’authentification et d’identité  
- Partage de fichiers & services d’impression  
- Services de routage, de commutation et services d’infrastructure  
- Communication applicative  
- Sauvegarde & réplication  
- Suivi & gestion  

### Exemples de flux (Flow Examples)
Regardons visuellement quelques-uns des flux réseau mentionnés ci-dessus.

#### HTTPS
Il existe différentes variantes de flux de trafic réseau HTTPS. Examinons un flux dans lequel le proxy web effectue une inspection TLS (Transport Layer Security).

Un hôte demande un site web ; cette requête est envoyée au NGFW, qui inclut un proxy web. Le proxy web se comporte comme le serveur web et établit simultanément une nouvelle session TCP avec le serveur web réel, tout en transmettant les requêtes des clients. Lorsque le proxy web reçoit la réponse du serveur web, il en inspecte le contenu puis la transmet à l’hôte si elle est jugée sûre. Pour résumer, on observe deux sessions : l’une entre le client et le proxy, et l’autre entre le proxy et le serveur web. Du point de vue du client, il a établi une session avec le serveur web.
### DNS externe (External DNS)
Le trafic DNS dans un réseau d’entreprise commence lorsqu’un hôte envoie une requête DNS. L’hôte envoie la requête au serveur DNS interne sur le port 53, qui agira alors pour le compte de l’hôte. D’abord, il vérifie s’il a une réponse en cache ; si ce n’est pas le cas, il transmet la requête via le routeur, à travers le pare-feu, vers les serveurs DNS configurés. La réponse suivra ensuite le même chemin jusqu’au serveur DNS interne, qui la transmettra alors à l’hôte. Le schéma réseau ci-dessous montre un flux simplifié.

### SMB avec Kerberos
Lorsqu’un hôte ouvre un partage, par exemple \\FILESERVER\MARKETING, une session SMB est établie. Tout d’abord, l’authentification se fait via Kerberos. Quand un utilisateur s’est connecté sur l’hôte, il s’est authentifié auprès du Key Distribution Center (Centre de distribution des clés) sur le contrôleur de domaine, et a reçu un Ticket Granting Ticket pour demander des « tickets d’authentification de service ». Ensuite, l’hôte demande un ticket de service en utilisant le Ticket Granting Ticket reçu précédemment. L’hôte utilise alors ce ticket pour établir la connexion SMB. Une fois la session SMB établie, l’hôte peut accéder au partage. Ci-dessous, on voit un schéma réseau simplifié du flux.

### Comment observer le trafic réseau ?
Maintenant que nous avons vu ce qu’il faut observer dans un réseau, examinons comment le faire. Comme mentionné dans l’introduction, l’analyse du trafic réseau consiste à combiner plusieurs sources d’informations, à les analyser, à repérer des schémas, puis à utiliser les résultats pour prendre des actions.

Ces sources d’informations peuvent être obtenues de plusieurs manières :

- **Journaux (Logs)**
- **Capture complète de paquets (Full Packet Capture)**
- **Statistiques réseau (Network Statistics)**

### Journaux (Logs)
Les journaux sont notre première entrée pour obtenir de l’information sur ce qui se passe sur le réseau. Chaque système et chaque protocole du réseau incluent un moyen d’enregistrer des informations. Il est essentiel de comprendre qu’il n’existe pas de norme universelle pour la manière d’implémenter la journalisation sur chaque système et protocole. Chaque fournisseur choisit comment gérer la journalisation pour ses propres systèmes.

Par exemple, Microsoft utilise les **journaux d’événements Windows** (Windows Event Logs). De plus, les données consignées dépendent du fournisseur. La plupart des fournisseurs ne journalisent pas un paquet complet à son entrée ou à sa sortie du système. Ils enregistrent plutôt certains champs qu’ils jugent utiles, comme **l’adresse IP source** et **l’adresse IP de destination**.

Sur l’extrait ci-dessous, on voit des exemples de journaux d’authentification sur un hôte Linux via le format **Syslog**, ainsi qu’un journal d’accès d’un serveur web Apache utilisant la norme **CLF** :

- Auth log  
  Oct  8 11:20:15 web01 sshd[2145]: Accepted password for gensane from 192.168.1.50 port 52234 ssh2

- Apache web server access log  
  192.168.1.50 - - [08/Oct/2025:11:20:18 +0200] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"

Même s’il n’y a pas de manière standard unique de journaliser, certains protocoles proposent une méthode standard pour envoyer des messages de log depuis des équipements vers des collecteurs, par exemple **Syslog** et **SNMP**.

Quand les journaux ne donnent pas assez d’informations, il faut aller plus loin : corréler les journaux, inspecter des captures complètes de paquets et consulter les statistiques réseau.

### Capture complète de paquets (Full Packet Capture)
Dans la tâche trois, nous avons discuté à quoi ressemble une capture complète de paquets. Maintenant, on veut savoir comment capturer et analyser ces paquets. Pour cela, nous avons deux options :

- Installer un **tap réseau physique**
- Configurer le **mirroring de port** (port mirroring)

#### Tap réseau (Network Tap)
Un tap réseau est un dispositif physique que l’on place en ligne dans le réseau. Il crée une copie de tout le trafic qui passe, sans affecter les performances. Cette copie est ensuite envoyée vers une **boîte de capture de paquets**, un **IDS**, ou un autre système, via le port de monitoring dédié.

Un point important : un TAP fonctionne uniquement au niveau de la **couche liaison** du modèle TCP/IP ; il n’a pas besoin d’une adresse MAC ou IP, car il copie les signaux électriques/lumineux et les envoie vers son port de surveillance. Ainsi, il n’y a pas de délai ajouté au réseau. L’image ci-dessous montre un exemple de TAP réseau.

#### Mirroring de port (Port Mirroring)
Le mirroring de port est une approche logicielle qui consiste à copier des paquets provenant d’un port d’un équipement intermédiaire vers un autre port, auquel on connecte par exemple un IDS, une machine de capture de paquets, ou d’autres systèmes. Chaque fournisseur a son propre nom : par exemple, Cisco l’appelle **SPAN**.

Dans l’exemple ci-dessous, on voit comment configurer SPAN sur un équipement Cisco. Ici, les paquets passant par fastEthernet0/1 sont dupliqués et envoyés vers fastEthernet0/2 :

```cisco
Switch(config)# monitor session 1 source interface fastEthernet0/1
Switch(config)# monitor session 1 destination interface fastEthernet0/2
```

L’image ci-dessous montre à quoi cela ressemble : le poste WIN-001 envoie des paquets via le switch pour communiquer avec le serveur. Quand le paquet arrive sur le switch, il est dupliqué et envoyé aussi vers l’équipement de monitoring.

Note : les équipements intermédiaires n’ont pas forcément besoin d’être physiques. Le mirroring peut aussi être configuré sur des équipements virtuels, par exemple sur un **vSwitch VMware**. Les environnements cloud proposent aussi des services dédiés au mirroring. Par exemple, **AWS** propose **VPC Traffic Mirroring**.

### Bonnes pratiques (Best Practices)
Quand on fait une capture complète de paquets, il faut prendre en compte :

- **Placement** : selon le trafic que l’on veut capturer, il faut placer le TAP ou configurer le mirroring au bon endroit.
- **Durée** : la capture complète nécessite une quantité de stockage proportionnelle. Si on capture du trafic sur une ligne **1 Gbps** pendant une journée, il faut environ **10,8 TB** de stockage. Imaginez la quantité nécessaire sur des lignes **10Gb** ou **40Gb**.
- **Mirroring vs TAP** : les TAP physiques réduisent presque à zéro les performances. Le mirroring peut avoir un impact sur les performances quand une très grande quantité de trafic traverse le port mis en miroir.

### Exercice
Ouvrez le site statique et complétez les deux exercices en plaçant le tap au bon endroit et en retrouvant le drapeau (flag) dans le trafic. Renseignez les flags à la fin de cette tâche. Vous pouvez ouvrir le site statique en cliquant sur le bouton **"View Site"** et en haut de cette tâche. Le site statique s’ouvrira en écran partagé. Pour l’ouvrir en plein écran, cliquez sur le bouton **"Full Screen"** du site statique.

### Outils (Tools)
Maintenant que nous savons comment faire des captures complètes de paquets, regardons les outils disponibles pour analyser ces paquets :

- **Wireshark**
- **TCPdump**
- **IDS/IPS** comme **Snort**, **Suricata** et **Zeek**

Ce ne sont que quelques-uns des nombreux outils disponibles pour analyser des captures complètes. Dans les salles suivantes de ce module, nous nous concentrerons sur l’utilisation de **Wireshark**.

### Statistiques réseau (Network Statistics)
Une autre excellente façon de repérer des anomalies dans votre réseau consiste à collecter des métadonnées sur les données qui circulent dans le réseau, par exemple compter le nombre de requêtes DNS qu’un hôte envoie.

Plusieurs protocoles facilitent cela. Nous allons brièvement en discuter deux : **NetFlow** et **IPFIX**.

- **NetFlow** est un protocole développé par Cisco qui collecte des métadonnées sur le trafic circulant dans un réseau. Il est très utile pour détecter des éléments comme le trafic de **C2**, l’**exfiltration de données** et le **mouvement latéral**. L’image ci-dessous montre un exemple de sortie NetFlow : on voit que l’exemple ne contient pas des paquets individuels, mais des métadonnées sur le flux de paquets allant de l’IP source **12.1.1.1** vers l’IP de destination **13.1.1.2**.

- Le protocole **IPFIX (Internet Protocol Flow Information Export)** peut être vu comme l’évolution de **NetFlow**. NetFlow était à l’origine un protocole propriétaire de Cisco, donc conçu uniquement pour les systèmes Cisco. À partir de NetFlow v9, Cisco a ajouté de la **templating** pour que d’autres fournisseurs puissent l’adapter à leurs équipements. En collaboration avec Cisco et d’autres fournisseurs, l’IETF a créé IPFIX et l’a publié comme standard indépendant du fournisseur. Il propose des fonctionnalités similaires à NetFlow, mais avec plus de souplesse pour configurer quels champs capturer.

Pour implémenter NetFlow ou IPFIX, on n’a pas besoin d’une infrastructure entièrement nouvelle ni de serveurs dédiés. La plupart des fournisseurs implémentent ces protocoles directement dans leurs équipements. Il suffit d’activer et configurer le protocole, puis d’indiquer où envoyer les métadonnées. Vous n’avez pas besoin d’un serveur dédié : beaucoup de **NGFW**, **IPS** et **IDS** ont une implémentation pour collecter et analyser les données de flux.
