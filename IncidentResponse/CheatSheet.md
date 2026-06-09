# Cheat Sheet 
Source : SANS Institute Windows to UNIX : [windows-to-unix-cheat-sheet](https://www.sans.org/posters/windows-to-unix-cheat-sheet)
  
Il s'agit d'un guide de poche au format poche/dépliant destiné aux administrateurs système, analystes SOC et experts en cybersécurité pour avoir sous la main les commandes essentielles, les structures de paquets et les ports réseau courants.
 
---

## 1. Tableau comparatif des commandes : Unix vs Windows (DOS)

Ce tableau permet de basculer rapidement d'un environnement à l'autre pour les tâches courantes :

| Action recherchée | Commande Unix / Linux | Commande Windows / DOS |
| --- | --- | --- |
| **Lister le contenu d'un répertoire** | `ls`<br> | `dir`<br> |
| **Afficher le répertoire courant** | `pwd`<br> | `chdir` ou `cd`<br> |
| **Afficher l'historique des commandes** | `history`<br> | `doskey /h`<br> |
| **Rechercher un motif / du texte** | `grep`<br> | `find`<br> |
| **Afficher le contenu d'un fichier** | `cat`<br> | `type`<br> |
| **Copier un fichier** | `cp`<br> | `copy`<br> |
| **Déplacer / Renommer un fichier** | `mv`<br> | `rename` / `move`<br> |
| **Supprimer un fichier** | `rm`<br> | `del` / `erase`<br> |
| **Lister les processus actifs** | `ps`<br> | `tasklist`<br> |
| **Configuration réseau (IP)** | `ifconfig`<br> | `ipconfig`<br> |
| **Tracer la route réseau** | `traceroute`<br> | `tracert`<br> |
| **Afficher la table de routage** | `route -n`<br> | `route print`<br> |

---

## 2. Commandes Unix avancées pour l'analyse de Logs

Le document fournit des lignes de commandes combinées (pipelines) pour analyser rapidement des fichiers de capture ou des logs de serveurs Web :

* **Top 10 des adresses IP sources (via un dump tcpdump) :**
```bash
tcpdump -nr dumpfile | cut -f3 -d ' ' | cut -f1-4 -d '.' | sort | uniq -c | sort -nr | head -10

```



```
    *(Permet d'extraire, trier et compter les 10 IP les plus actives dans une capture réseau[cite: 1])*
*   **Top 10 des référents (referrers) dans un log Apache :**
    ```bash
    cat access_log | cut -d ' ' -f11 | cut -d '/' -f3 | sort | uniq -c | sort -nr | head -10

```

```
*(Permet d'identifier d'où viennent principalement les visiteurs sur un site[cite: 1])*

```

* **Conversion de formats de fichiers (retrait des retours chariots Windows `\r` ou `^Z`) :**
* *Windows vers Unix :* `tr -d '\15\32' < windows.txt > unix.txt`

* *Unix vers Windows :* `awk 'sub("$", "\r")' unix.txt > windows.txt`




---

## 3. Top des ports réseau fréquemment scannés

Une liste des ports essentiels à surveiller lors d'une analyse de flux ou d'alertes d'intrusion (IDS) :

* **Ports d'infrastructure / Web :** `21` (FTP), `23` (Telnet), `25` (SMTP), `53` (DNS), `80` (HTTP), `443` (HTTPS).


* **Ports Windows / Partage (Cibles fréquentes) :** `135` (RPC), `137/139` (NetBIOS), `445` (SMB/CIFS).


* **Bases de données & Administration :** `1433` (SQL Server), `3306` (MySQL), `3389` (RDP - Terminal Services), `5900` (VNC).



---

 ## 4. Structures des En-têtes IP (IPv4 & IPv6)

Le document cartographie la structure exacte des paquets pour l'analyse de trames au niveau binaire :

* **IPv4 :** Comprend les champs Version, IHL, TOS, Longueur Totale, Identification, Drapeaux (Flags), Fragment Offset, TTL, Protocole, Checksum, IP Source et IP Destination.


* **IPv6 :** Identifie la Version, Traffic Class, Flow Label, Payload Length, Next Header (qui remplace le champ protocole), Hop Limit, ainsi que les adresses Source et Destination codées sur 128 bits.


* **Numéros de protocoles courants :** `1` = ICMP, `2` = IGMP, `6` = TCP, `17` = UDP, `47` = GRE, `50` = ESP (IPsec).


Voici une cartographie comparative et structurée des en-têtes IP et des protocoles associés, optimisée pour l'analyse de trames au niveau binaire.

---

## 5. Tableau Comparatif des Structures d'En-têtes IP

| Catégorie | Champs d'En-tête / Spécifications | Caractéristiques Binaires Clés |
| --- | --- | --- |
| **IPv4** | VersionIHL (Internet Header Length)TOS (Type of Service)Longueur TotaleIdentificationDrapeaux (Flags)Fragment OffsetTTL (Time to Live)ProtocoleChecksumIP Source (32 bits)IP Destination (32 bits) | En-tête de taille variable (minimum 20 octets, indiqué par l'IHL). Comprend la gestion native de la fragmentation et un checksum d'en-tête recalculé à chaque saut. |
| **IPv6** | VersionTraffic ClassFlow LabelPayload Length**Next Header** (remplace le champ Protocole)Hop Limit (remplace le TTL)Adresse Source (128 bits)Adresse Destination (128 bits) | En-tête de taille fixe (40 octets). Simplification drastique : pas de checksum d'en-tête, fragmentation gérée par des extensions de routage (champs optionnels via le *Next Header*). |

---

## 6. Référence des Numéros de Protocoles Courants

Ces valeurs décimales se retrouvent directement au niveau binaire dans le champ **Protocole** (IPv4) ou **Next Header** (IPv6) pour identifier le protocole de couche supérieure :

| Valeur (Décimal) | Code Protocole | Utilisation / Signification |
| --- | --- | --- |
| **`1`** | `ICMP` | Internet Control Message Protocol (messages de contrôle/erreur, ex: ping) |
| **`2`** | `IGMP` | Internet Group Management Protocol (gestion des groupes multicast) |
| **`6`** | `TCP` | Transmission Control Protocol (transport orienté connexion) |
| **`17`** | `UDP` | User Datagram Protocol (transport en mode non-connecté) |
| **`47`** | `GRE` | Generic Routing Encapsulation (encapsulation pour tunnels VPN) |
| **`50`** | `ESP` | Encapsulating Security Payload (chiffrement de paquets avec IPsec) |

 
