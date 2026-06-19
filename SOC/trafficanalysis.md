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

