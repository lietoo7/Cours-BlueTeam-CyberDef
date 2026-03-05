## 1. Des Logs partout (Logs Everywhere)

Dans un réseau, tous les appareils communiquent entre eux et avec Internet via un routeur. 
Qu'il s'agisse de postes de travail (Windows/Linux), de serveurs de données ou de serveurs web, tous génèrent en continu des traces de leurs activités : 
ce sont les **sources de logs**.

On divise ces sources en deux grandes catégories :

### A) Les Sources de Logs "Hôtes" (Host-Centric)

Elles capturent les événements qui se produisent **à l'intérieur** d'une machine.

* **Exemples :**
* Un utilisateur accède à un fichier.
* Une tentative d'authentification (réussie ou échouée).
* L'exécution d'un processus.
* La modification d'une clé de registre (Windows).
* L'exécution d'une commande PowerShell.



### B) Les Sources de Logs "Réseau" (Network-Centric)

Elles capturent les événements liés aux **communications** entre les machines ou vers Internet. Elles proviennent des pare-feu, IDS/IPS, routeurs, etc.

* **Exemples :**
* Une connexion SSH.
* L'accès à un fichier via FTP.
* Le trafic Web (HTTP/HTTPS).
* Un utilisateur accédant aux ressources via un VPN.
* Le partage de fichiers sur le réseau (SMB).



 

## 2. Des Réponses nulle part (Answers Nowhere)

Sur le papier, il suffit d'analyser ces logs pour identifier les attaques. En réalité, c'est un défi immense pour plusieurs raisons :

* **L'abondance des sources :** Un réseau génère des centaines d'événements **par seconde**. Examiner chaque appareil un par un en cas d'incident est une tâche titanesque.
* **L'absence de centralisation :** Comme les logs résident sur chaque machine, vous devriez vous connecter à chacune d'elles (via SSH ou RDP) pour les analyser. C'est une perte de temps précieuse en pleine investigation.
* **Le manque de contexte :** Un log isolé ne raconte pas toute l'histoire.
* *Exemple :* L'accès à un fichier semble normal. Mais si on **corrèle** les données, on découvre que l'utilisateur a accédé à cette machine par **mouvement latéral** après avoir compromis un autre ordinateur. Seule la vue d'ensemble permet de voir l'attaque.
* **Une analyse limitée :** Il est humainement impossible de surveiller manuellement tous les logs de tous les appareils. Des informations cruciales finiraient forcément par être ignorées.
* **La diversité des formats :** Chaque équipement a sa propre manière d'écrire ses logs. Un analyste devrait connaître des dizaines de formats différents, ce qui rend l'interprétation très complexe.

## Pourquoi le SIEM ?

Pour gérer efficacement le déluge de données provenant des multiples sources de logs, on utilise le **SIEM (Security Information and Event Management)**. C'est une solution de sécurité qui collecte les logs, uniformise leur format, les corrèle entre eux et détecte les activités malveillantes grâce à des règles spécifiques.

 

## Les Fonctionnalités Clés du SIEM

Le SIEM ne se contente pas de stocker des données ; il les rend exploitables grâce à cinq capacités majeures :

### 1. Collecte Centralisée des Logs

Le SIEM récupère les logs de toutes les sources (postes, serveurs, pare-feu) via des **agents légers** ou des **API**.

* **Le bénéfice :** Plus besoin de se connecter individuellement à chaque machine ; tout est accessible depuis une console unique.

### 2. Normalisation des Logs

Un log Windows est illisible pour un système Linux, et vice versa. Le SIEM résout ce problème en deux étapes :

* **Le Parsing :** Découper un log brut en champs compréhensibles (ex: "Utilisateur", "IP source", "Action").
* **La Normalisation :** Convertir tous les logs disparates en un format cohérent et standardisé pour faciliter la recherche.

### 3. Corrélation des Logs

C'est ici que réside la véritable puissance du SIEM. Il crée des liens entre des événements isolés pour identifier un schéma d'attaque.

> **Exemple de corrélation (fenêtre de 5 minutes) :**
> 1. Haris se connecte via **VPN** depuis une IP inhabituelle.
> 2. Haris accède à des documents sur un **disque partagé**.
> 3. Haris exécute un script **PowerShell**.
> 4. Le système établit une **connexion sortante** vers Internet.
> 
> 
> *Individuellement, ces actions sont banales. Corrélées, elles indiquent une **exfiltration de données** suite à un vol d'identifiants VPN.*

### 4. Alertes en Temps Réel

Le SIEM contient des **règles de détection**. Lorsque les conditions d'une règle sont remplies, une alerte est déclenchée instantanément pour prévenir les analystes, qui peuvent alors enquêter directement sur la plateforme.

### 5. Tableaux de Bord (Dashboards) et Reporting

Le SIEM transforme des millions de lignes de données en graphiques visuels et exploitables. Un tableau de bord type affiche :

* Les alertes les plus critiques.
* Le nombre de tentatives de connexion échouées.
* Le volume de données ingérées.
* Les domaines internet les plus visités.

### Autres capacités avancées

Le SIEM peut également s'intégrer à des flux de **Threat Intelligence** (pour connaître les IP malveillantes connues), offrir une rétention de données à long terme et proposer des moteurs de recherche ultra-puissants pour les investigations.

---

## Les Sources de Logs (Log Sources)

Chaque appareil du réseau génère des traces dès qu'une activité est réalisée (visite d'un site, connexion SSH, ouverture de session). Voici à quoi ressemblent les logs des systèmes les plus courants :

### A) Machine Windows

Windows enregistre chaque événement dans l'**Observateur d'événements** (Event Viewer).

* **Le point clé :** Un **ID unique** (Event ID) est attribué à chaque type d'activité (ex: l'ID 4624 correspond à une connexion réussie), ce qui facilite grandement le travail de l'analyste.
* Ces logs sont ensuite transférés au SIEM pour une surveillance centralisée.

### B) Machine Linux

Sous Linux, les logs sont généralement stockés dans des fichiers texte sous le répertoire `/var/log/`.

* `/var/log/httpd` : Requêtes HTTP (Apache) et erreurs.
* `/var/log/cron` : Événements liés aux tâches planifiées (cron jobs).
* `/var/log/auth.log` ou `/var/log/secure` : Logs d'authentification (très importants pour détecter les attaques par force brute).
* `/var/log/kern` : Événements liés au noyau (kernel).

### C) Serveur Web

Surveiller les flux entrants et sortants d'un serveur web est vital pour bloquer les attaques applicatives (SQLi, XSS). Sous Linux, on les trouve souvent dans `/var/log/apache` ou `/var/log/httpd`.

> **Exemple de log Apache brut :**
> `192.168.21.200 - - [21/March/2022:10:17:10] "GET /cgi-bin/try/ HTTP/1.0" 200 ...`
> *On y voit l'IP source, la date, la méthode (GET), la page consultée et le code de réponse (200 = succès).*

 

## L'Ingestion des Logs (Log Ingestion)

L'ingestion est le processus d'envoi de ces données vers le SIEM. Chaque solution a ses méthodes, mais voici les plus courantes :

| Méthode | Description |
| --- | --- |
| **Agent / Forwarder** | Un petit logiciel installé sur l'ordinateur (appelé *agent* ou *forwarder* chez Splunk) qui capture et envoie les logs en temps réel. |
| **Syslog** | Un protocole standard très utilisé pour collecter les données des serveurs, bases de données et équipements réseau vers une destination centrale. |
| **Téléchargement Manuel** | Pour une analyse rapide d'un fichier hors-ligne (format .csv, .json, .log), certains SIEM permettent d'importer directement un fichier. |
| **Port-Forwarding** | Le SIEM est configuré pour "écouter" sur un port spécifique, et les équipements lui envoient directement leurs flux de données sur ce port. |

 

### Résumé du flux de données

1. **Génération :** L'activité crée un log sur l'hôte (Windows/Linux).
2. **Expédition :** L'**Agent** ou le protocole **Syslog** récupère ce log.
3. **Réception :** Le **SIEM** reçoit le log, le parse et le normalise.
4. **Action :** L'analyste SOC voit l'alerte sur son tableau de bord.

---

## Les Coulisses des Alertes (Behind the Triggered Alerts)

Nous savons que le SIEM détecte les menaces, mais quel est le "secret" derrière ces détections ? Tout repose sur les **règles de détection**.

Ces règles sont essentiellement des expressions logiques conçues pour se déclencher dès qu'une condition spécifique est remplie.

### Exemples de règles logiques :

* **Tentatives infructueuses :** SI un utilisateur cumule 5 échecs de connexion en 10 secondes, ALORS déclencher l'alerte *"Tentatives de connexion multiples échouées"*.
* **Succès après échec :** SI une connexion réussit juste après plusieurs échecs, ALORS déclencher l'alerte *"Connexion réussie après échecs multiples"* (signe potentiel de Brute Force réussi).
* **Usage de clé USB :** SI un utilisateur branche un périphérique USB, ALORS déclencher une alerte (si la politique de l'entreprise l'interdit).
* **Exfiltration :** SI le trafic sortant est supérieur à 25 Mo, ALORS déclencher l'alerte *"Tentative potentielle d'exfiltration de données"*.

 

## 2. Comment créer une règle de détection ?

Prenons deux cas d'usage (Use-Cases) basés sur les journaux d'événements Windows (Eventlogs) :

### Cas d'usage n°1 : Effacement des traces

Les attaquants tentent souvent de supprimer les logs après une intrusion pour cacher leurs activités. Sous Windows, l'**Event ID 104** est généré chaque fois qu'un utilisateur vide les journaux.

> **La Règle :** SI (Source = WinEventLog) ET (EventID = 104) ➔ **ALERTE : Journaux d'événements effacés.**

### Cas d'usage n°2 : Reconnaissance (whoami)

Après avoir compromis un système, un attaquant tape souvent `whoami` pour connaître ses privilèges. L'**Event ID 4688** correspond à la création d'un nouveau processus.

> **La Règle :** SI (Source = WinEventLog) ET (EventID = 4688) ET (NewProcessName contient "whoami") ➔ **ALERTE : Exécution de la commande WHOAMI détectée.**

 

## 3. L'Investigation de l'Alerte (Alert Investigation)

Lorsqu'une alerte surgit sur son tableau de bord, l'analyste SOC doit mener l'enquête pour déterminer s'il s'agit d'un **Vrai Positif** ou d'un **Faux Positif**.

### Actions possibles après l'analyse :

* **Si c'est un Faux Positif :** L'alerte est classée. Il peut être nécessaire d'**affiner (tuner)** la règle de détection pour éviter que ce faux signal ne se reproduise inutilement.
* **Si c'est un Vrai Positif :**
* Approfondir l'investigation pour voir l'étendue des dégâts.
* Contacter le propriétaire de l'équipement (le salarié ou l'administrateur) pour vérifier s'il est à l'origine de l'action.
* Si l'activité malveillante est confirmée : **Isoler l'hôte infecté** du réseau.
* **Bloquer l'adresse IP** suspecte au niveau du pare-feu.


 
