## INTRODUCTION

Le terme **Kill Chain** (chaîne de destruction) est un concept militaire lié à la structure d'une attaque. Il se compose de l'identification de la cible, de la décision et de l'ordre d'attaquer cette cible, et enfin de sa destruction.

C'est l'entreprise **Lockheed Martin** (une entreprise mondiale de sécurité et d'aérospatiale) qui a transposé ce concept au secteur de la cybersécurité en 2011 en créant le framework **Cyber Kill Chain®**. Ce modèle définit les étapes successives suivies par les adversaires ou les acteurs malveillants dans le cyberespace. Pour réussir son attaque, un intrus doit impérativement valider toutes les phases de cette chaîne. Comprendre ces étapes et les techniques associées permet aux défenseurs de mieux anticiper et bloquer les menaces.

### Pourquoi est-il crucial de comprendre le fonctionnement de la Cyber Kill Chain ?

La Cyber Kill Chain aide à comprendre et à se protéger contre les attaques par ransomware, les violations de données ainsi que les menaces persistantes avancées (**APT - Advanced Persistent Threats**). Elle permet d'évaluer la sécurité de vos réseaux et systèmes en identifiant les contrôles de sécurité manquants et en comblant les failles en fonction de l'infrastructure de votre entreprise.

En tant qu'analyste SOC, chercheur en sécurité, chasseur de menaces (*Threat Hunter*) ou intervenant sur incident (*Incident Responder*), ce modèle vous permettra de reconnaître les tentatives d'intrusion et de comprendre les buts et objectifs finaux de l'attaquant.

Ce cours explore les phases d'attaque suivantes :

1. **Reconnaissance** (*Reconnaissance*)
2. **Armement** (*Weaponization*)
3. **Livraison** (*Delivery*)
4. **Exploitation** (*Exploitation*)
5. **Installation** (*Installation*)
6. **Commandement & Contrôle** (*Command & Control - C2*)
7. **Actions sur les Objectifs** (*Actions on Objectives*)

---

## 1. RECONNAISSANCE (RECO)

La reconnaissance est la phase de recherche et de planification d'une attaque contre un système ou une victime. Les attaquants l'utilisent pour collecter des informations sur leur cible afin d'orienter leurs prochaines actions. Ces informations peuvent inclure des détails sur l'infrastructure, des données sur les employés, des processus métiers et des technologies exposées sur Internet. Cette phase est souvent passive et difficile à détecter.

> Une mauvaise reconnaissance conduit généralement à des attaques maladroites, tandis que des attaquants bien informés peuvent concevoir des charges utiles (*payloads*) hautement ciblées et crédibles, augmentant considérablement leurs chances de succès.

L'**OSINT (Open-Source Intelligence ou Renseignement d'Origine Source Ouverte)** est un élément précieux de cette phase. Grâce à l'OSINT, les attaquants recueillent des informations via des sources publiques accessibles à tous :

* Les moteurs de recherche
* Les médias imprimés et en ligne
* Les comptes de réseaux sociaux
* Les forums et blogs en ligne
* Les bases de données publiques de registres légaux
* Le WHOIS et les données techniques associées aux serveurs

### Les types de reconnaissance

* **Reconnaissance Passive :** N'implique aucune interaction directe avec la cible. Exemples : consultations WHOIS, aspiration (*scraping*) de profils sur les réseaux sociaux, ou analyse de bases de données de fuites de données antérieures.
* **Reconnaissance Active :** Implique un contact direct avec l'infrastructure ou le personnel de la cible. Exemples : ingénierie sociale, scans de ports, capture de bannières (*banner grabbing*) ou test de services ouverts.

### Scénario : La perspective de l'attaquant

Imaginons un attaquant malveillant nommé "Megatron". Il décide de mener une attaque sophistiquée qu'il planifie depuis longtemps. Pour commencer, il doit récolter des données et utilise la technique de la **collecte d'e-mails (Email harvesting)**.

La collecte d'e-mails consiste à obtenir des adresses électroniques à partir de services publics, payants ou gratuits. L'attaquant pourra ensuite les utiliser pour une campagne de **phishing** (hameçonnage), une technique d'ingénierie sociale visant à voler des données sensibles (identifiants, cartes bancaires). Pour ce faire, il dispose d'un large arsenal d'outils OSINT :

* **theHarvester :** Permet de collecter des e-mails, mais aussi des noms, des sous-domaines, des IP et des URL en interrogeant de multiples sources de données publiques.
* **Hunter.io :** Un outil de recherche d'e-mails professionnelles permettant d'obtenir les coordonnées associées à un nom de domaine d'entreprise.
* **OSINT Framework :** Un site web répertoriant une collection exhaustive d'outils OSINT classés par catégories.

---

## 2. ARMEMENT (WEAPONIZATION)

Après avoir réussi sa phase de reconnaissance, "Megatron" s'attache à transformer les informations brutes en outils d'attaque opérationnels en combinant un logiciel malveillant (*malware*) ou un exploit dans une charge utile (*payload*).

La plupart des attaquants utilisent des outils automatisés pour générer le malware ou se tournent vers le **Dark Web** pour l'acheter. Les acteurs plus sophistiqués ou les groupes étatiques (**APT**) développent leurs propres malwares sur mesure afin de les rendre uniques et d'échapper aux solutions de détection de la cible.

### Terminologie clé

* **Malware (Logiciel malveillant) :** Programme ou logiciel conçu pour endommager, perturber ou obtenir un accès non autorisé à un système informatique.
* **Exploit :** Programme ou morceau de code qui exploite une vulnérabilité ou une faille de sécurité dans une application ou un système.
* **Payload (Charge utile) :** Le code malveillant final exécuté par l'attaquant sur le système de la victime (par exemple, le script qui chiffre les fichiers).

Dans notre scénario, "Megatron" choisit d'acheter un payload clé en main sur le Dark Web afin de consacrer son temps aux phases suivantes. Durant cette phase d'Armement, plusieurs tactiques peuvent être adoptées :

* Créer un document Microsoft Office infecté contenant des **macros malveillantes** ou des scripts VBA (*Visual Basic for Applications*).
* Concevoir un ver informatique sophistiqué, le charger sur des clés USB, puis abandonner ces clés dans des lieux publics.
* Configurer l'infrastructure de **Commandement et Contrôle (C2)** qui servira à envoyer des ordres à la machine de la victime.
* Intégrer une **backdoor** (porte dérobée) au malware pour garantir un accès futur en contournant les mécanismes de sécurité standard.
* Personnaliser des modèles de phishing ou de fausses applications d'authentification OAuth pour duper la victime.

---

## 3. LIVRAISON (DELIVERY)

La phase de livraison correspond au moment où "Megatron" choisit la méthode de transmission de sa charge utile malveillante vers l'environnement cible. Les vecteurs sont variés :

* **E-mail de Phishing :** Après avoir identifié ses cibles lors de la reco, l'attaquant envoie un e-mail malveillant. S'il vise une personne spécifique (le service comptable par exemple), on parle de **Spear Phishing** (harponnage). L'e-mail contient une pièce jointe ou un lien piégé.
* **Le dépôt de clés USB (USB drops) :** Ce support physique consiste à laisser des clés USB dans des endroits publics (parkings, cafés, rue). Une variante sophistiquée consiste à imprimer le logo de l'entreprise visée sur les clés et à les envoyer par courrier en se faisant passer pour un client offrant des cadeaux.
* **L'attaque par point d'eau (Watering Hole) :** Cette technique cible un groupe de personnes spécifique en piratant un site web légitime qu'elles ont l'habitude de visiter fréquemment. Le site est modifié pour rediriger les visiteurs vers un serveur malveillant qui télécharge automatiquement un virus sur leur ordinateur à leur insu (mécanisme de *drive-by download*, comme une fausse invite de mise à jour d'extension de navigateur).

> **Question de révision :**
> Comment appelle-t-on une attaque qui cible un groupe spécifique en infectant un site web qu'il visite fréquemment ?
> *Réponse : Une attaque par point d'eau (Watering Hole).*

---

## 4. EXPLOITATION

L'exploitation est le moment précis où le code de l'attaquant s'exécute sur la machine cible en profitant d'une vulnérabilité. Pour obtenir ce premier accès, "Megatron" peut s'appuyer sur plusieurs techniques :

* **L'exécution de macros malveillantes :** Déclenchée par l'utilisateur à l'ouverture d'un document reçu par phishing (ex: exécution d'un ransomware).
* **Les exploits Zero-day (0-day) :** Exploitation de failles inconnues de l'éditeur et pour lesquelles aucun correctif n'existe. Ces failles offrent un taux de réussite maximal au début car elles contournent la plupart des détections.
* **Les CVE connues :** L'attaquant cible des vulnérabilités publiques bien documentées mais que l'entreprise n'a pas encore corrigées (*systèmes non mis à jour*).

Une fois le pied posé dans le système, l'attaquant utilise des vulnérabilités locales pour élever ses privilèges (*Privilege Escalation*) ou se déplacer de machine en machine sur le réseau (*Lateral Movement*).

### Signes d'exploitation à surveiller (SOC)

* Apparition de processus enfants inattendus (ex: un processus Word qui lance une invite de commande `cmd.exe`).
* Modifications suspectes de la base de registre ou création de nouveaux services non documentés.
* Arguments de ligne de commande suspects ou hautement obfusqués dans les journaux d'événements système.

---

## 5. INSTALLATION

Une fois l'accès initial obtenu, l'attaquant doit faire face à un risque : perdre sa connexion si l'utilisateur redémarre son ordinateur, si le système est mis à jour, ou si la session se ferme. C'est pourquoi il procède à l'**installation d'une backdoor persistante** pour maintenir son accès sur le long terme.

La persistance peut être obtenue par plusieurs techniques :

* **L'installation d'un Web Shell :** Un script malveillant (écrit en PHP, ASP ou JSP) déposé sur le serveur web de l'entreprise. En raison de sa simplicité de format, il peut facilement se fondre au milieu du code légitime et s'avérer difficile à détecter.
* **L'utilisation d'outils comme Meterpreter :** Une charge utile du framework *Metasploit* qui fournit un shell interactif permettant à l'attaquant de contrôler à distance la machine de la victime.
* **La création ou modification de services Windows :** Technique répertoriée sous l'identifiant **T1543.003** dans la matrice **MITRE ATT&CK**. L'attaquant configure un service système pour exécuter son payload à intervalles réguliers. Il utilise pour cela des outils natifs comme `sc.exe` ou `reg.exe`. Il recourt souvent au **masquage (masquerading)** en donnant à son service un nom très proche d'un composant système légitime (ex: *Svchost32*).
* **L'inscription dans les Run Keys du Registre ou le dossier de démarrage (Startup Folder) :** Le payload s'exécute ainsi automatiquement à chaque fois qu'un utilisateur ouvre sa session.

> **Technique anti-forensic : Le Timestomping**
> Pendant cette phase, l'attaquant utilise souvent le *timestomping* pour modifier les horodatages (dates de création, modification, accès) des fichiers malveillants installés. Cela induit en erreur les enquêteurs numériques (*forensic investigators*) en faisant passer le malware pour un fichier ancien intégré au système d'origine.

---

## 6. COMMANDEMENT & CONTRÔLE (COMMAND & CONTROL - C2)

Le canal de persistance étant en place, le malware implanté sur la machine de la victime ouvre un canal de communication vers l'extérieur pour écouter les ordres de "Megatron". Ce mécanisme de communication régulier entre la machine infectée et le serveur de l'attaquant s'appelle le **C2 Beaconing** (balisage).

La machine compromise initie la connexion vers un serveur externe contrôlé par l'attaquant. Si l'IRC (*Internet Relay Chat*) était très utilisé par le passé, il est aujourd'hui abandonné car trop facilement détecté par les pare-feux modernes.

Les canaux C2 contemporains les plus courants incluent :

* **HTTP (port 80) et HTTPS (port 443) :** Le trafic malveillant se fond parfaitement dans le trafic web légitime de l'entreprise, ce qui lui permet de franchir les pare-feux sans éveiller de soupçons.
* **Le protocole DNS (DNS Tunneling) :** La machine infectée encapsule ses messages dans des requêtes DNS légitimes envoyées à un serveur de noms contrôlé par l'attaquant. Ce canal est particulièrement robuste car le trafic DNS est rarement bloqué en sortie des entreprises.

---

## 7. ACTIONS SUR LES OBJECTIFS (EXFILTRATION)

Après avoir franchi avec succès les six premières phases, l'attaquant atteint enfin son but ultime. Disposant d'un accès interactif complet (*hands-on-keyboard*), il peut exécuter ses actions finales :

* Collecter les identifiants et mots de passe des utilisateurs (via du vol de jetons ou le vidage de la mémoire LSASS).
* Réaliser une **Élévation de privilèges** pour devenir administrateur du domaine à partir d'un simple poste de travail en exploitant des mauvaises configurations Active Directory.
* Procéder à une reconnaissance interne du réseau pour cartographier les serveurs critiques et les bases de données.
* Effectuer un **déplacement latéral** (se connecter à d'autres serveurs de l'entreprise).
* Collecter et **exfiltrer les données sensibles** vers ses serveurs externes.
* Saboter les défenses en **supprimant les sauvegardes et les clichés instantanés de volume (Shadow Copies)** de Microsoft pour empêcher la restauration du système.
* Chiffrer, corrompre ou détruire définitivement les données (déclenchement final du ransomware).

