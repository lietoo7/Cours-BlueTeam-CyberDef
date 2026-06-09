# Introduction à MITRE

Au cours de votre parcours en cybersécurité, vous avez probablement déjà croisé le nom de MITRE, peut-être lors de recherches sur une faille connue ou en explorant les différentes tactiques employées par les attaquants. MITRE est une organisation à but non lucratif qui mène des activités de recherche et développement dans divers domaines, notamment la cybersécurité, l'intelligence artificielle, la santé et les systèmes spatiaux, le tout au service de sa mission : « résoudre des problèmes pour un monde plus sûr ».

Dans ce cours, nous nous concentrerons sur les référentiels (frameworks) et les ressources de MITRE dédiés à la cybersécurité, y compris MITRE ATT&CK®, la base de connaissances CAR, D3FEND, MITRE Engage™, ainsi que d'autres outils pertinents. Ces ressources sont devenues indispensables dans la sécurité moderne, permettant aux équipes offensives (*Red Teams*) comme défensives (*Blue Teams*) de comprendre le comportement des adversaires, de développer des détections plus efficaces et d'améliorer leurs défenses.

### Objectifs d'apprentissage

* Comprendre l'objectif et la structure du référentiel MITRE ATT&CK®
* Découvrir comment les professionnels de la sécurité appliquent ATT&CK dans leur travail
* Utiliser le renseignement sur les cybermenaces (CTI - *Cyber Threat Intelligence*) et la matrice ATT&CK pour profiler les menaces
* Découvrir les autres référentiels de MITRE, notamment CAR et D3FEND

---

## Le Référentiel ATT&CK®

Le référentiel MITRE ATT&CK® est « une base de connaissances accessible mondialement qui répertorie les tactiques et techniques des adversaires sur la base d'observations du monde réel. La base de connaissances ATT&CK sert de fondement au développement de modèles et de méthodologies de menaces spécifiques dans le secteur privé, le secteur public et la communauté des produits et services de cybersécurité. »

En 2013, MITRE a identifié le besoin de documenter et de catégoriser les tactiques, techniques et procédures (TTP) standards utilisées par les groupes de menaces persistantes avancées (APT). Pour mieux comprendre le mode opératoire des adversaires, il est utile de détailler chaque composante des TTP :

* **Tactique** : L'objectif ou le but de l'adversaire. Le « pourquoi » d'une attaque.
* **Technique** : La manière dont un adversaire atteint son objectif ou son but. Le « comment ».
* **Procédure** : L'implémentation concrète ou la façon dont la technique est exécutée.

### Évolution d'ATT&CK

Le référentiel ATT&CK a considérablement évolué au fil des ans. Initialement centré sur la plateforme Windows, il s'est étendu pour couvrir un large éventail d'environnements, notamment macOS, Linux, les plateformes cloud, et bien plus encore, sous la matrice *Enterprise*. De plus, des référentiels spécialisés existent pour le secteur Mobile et les systèmes de contrôle industriel (ICS). Le framework continue de s'enrichir grâce aux contributions de la communauté de la cybersécurité. Bien qu'extrêmement précieux d'un point de vue défensif, les *Red Teams* s'appuient également sur ce référentiel pour planifier des simulations d'attaques réalistes et tester les défenses des organisations.

### La Matrice ATT&CK

La matrice MITRE ATT&CK est une représentation visuelle puissante de toutes les tactiques et techniques existant au sein du référentiel. Vous pouvez également utiliser l'ATT&CK Navigator, un outil très pratique pour annoter et explorer les matrices. Les tactiques sont représentées sur la ligne supérieure de la matrice. Sous chaque tactique se trouvent les techniques correspondantes, qui peuvent être développées pour révéler des sous-techniques.

Prenons un exemple concret :

* **Tactique** : Disons qu'un attaquant souhaite effectuer une reconnaissance (*Reconnaissance*) sur sa cible. C'est l'objectif de l'attaquant.
* **Technique** : Il peut utiliser le balayage actif (*Active Scanning*). C'est ainsi qu'il atteint son objectif de reconnaissance.
* **Sous-technique** : Le balayage actif comprend trois méthodes spécifiques : le balayage de blocs IP (*Scanning IP Blocks*), le balayage de vulnérabilités (*Vulnerability Scanning*) ou le balayage par liste de mots (*Wordlist Scanning*).

### Exploration approfondie

Examinons de plus près la technique de balayage actif (*Active Scanning*). Sur la page de description de cette technique, vous verrez à nouveau la liste des sous-techniques. La page liée comprend également toutes les informations pertinentes, notamment une description et l'ID de la technique, que vous rencontrerez souvent dans vos recherches en cybersécurité.

En plus des informations mentionnées ci-dessus, chaque page de tactique et de technique comprend des exemples de procédures (groupes d'attaquants, logiciels utilisés et campagnes), des mesures d'atténuation (*mitigations*), des méthodes de détection et des références. ATT&CK peut sembler impressionnant au début, tout simplement en raison de l'immense quantité d'informations disponibles. Prenons un peu de recul et répondons à quelques questions pour mieux comprendre.

---

## ATT&CK en Pratique

Maintenant que vous savez ce qu'est ATT&CK et le type de renseignement qu'il contient, voyons de plus près comment et pourquoi il est utilisé. Avec autant de données disponibles, comment les organisations s'y retrouvent-elles concrètement ? Explorons la manière dont les défenseurs, les chercheurs et les *Red Teams* mettent en œuvre ATT&CK.

### Pourquoi ATT&CK est-il important ?

ATT&CK fournit aux professionnels et aux organisations de cybersécurité un langage standardisé et cohérent pour décrire le comportement des adversaires. Au cours de votre apprentissage, vous avez probablement vu une même action ou technique désignée par plusieurs noms différents. En proposant une terminologie standard et des identifiants uniques (IDs), le référentiel facilite la comparaison des données et des incidents, permettant ainsi une communication efficace au sein de la communauté de la sécurité.

### Renseignement sur les menaces et Défense

Au-delà de l'amélioration de la communication, ATT&CK aide également à combler le fossé entre le renseignement sur les menaces (*Threat Intelligence*) et les opérations défensives. Un rapport de menace peut décrire ce qu'un attaquant a fait, mais pas comment transformer cette information en mesures de détection exploitables. En faisant correspondre l'activité de la menace aux TTPs, les défenseurs peuvent traduire le renseignement en règles de détection concrètes, en requêtes et en guides de procédures (*playbooks*). Plus tard dans ce cours, nous aborderons certains des outils mis à disposition par MITRE pour soutenir ces efforts.

### Qui utilise ATT&CK ?

ATT&CK est utilisé dans l'ensemble de l'industrie de la cybersécurité. Le tableau ci-dessous met en évidence la manière dont les différentes équipes et professionnels l'appliquent dans leur travail quotidien et comment il soutient les opérations offensives et défensives.

| Qui | Leur Objectif | Comment ils utilisent ATT&CK |
| --- | --- | --- |
| **Équipes CTI** *(Cyber Threat Intelligence)* | Collecter et analyser les informations sur les menaces pour améliorer la posture de sécurité de l'organisation. | Associer les comportements observés des cyberattaquants aux TTPs d'ATT&CK pour créer des profils exploitables dans toute l'industrie. |
| **Analystes SOC** | Enquêter et trier les alertes de sécurité. | Lier l'activité suspecte à des tactiques et techniques pour fournir un contexte détaillé aux alertes et prioriser les incidents. |
| **Ingénieurs Détection** | Concevoir et améliorer les systèmes de détection. | Aligner les règles SIEM/EDR et autres mécanismes de détection sur ATT&CK pour garantir une meilleure couverture face aux menaces. |
| **Analystes Réponse aux Incidents** | Répondre aux incidents de sécurité et mener les investigations. | Cartographier la chronologie des incidents avec les tactiques et techniques MITRE pour mieux visualiser le déroulement de l'attaque. |
| **Red & Purple Teams** | Émuler le comportement des adversaires pour tester et améliorer les défenses. | Construire des plans d'émulation et des exercices alignés sur les techniques et les opérations connues de groupes d'attaquants. |

### La cartographie en action

Imaginons que votre organisation ait été victime d'une attaque. Dans un scénario post-incident, il est crucial d'analyser le déroulement de l'attaque et d'en cartographier chaque étape dans un format structuré. Cela permettra à votre équipe de mieux se préparer aux futures campagnes ciblant votre organisation.

Le groupe **Mustang Panda** (G0129) a été associé à une grande variété de techniques ATT&CK sur la base de ses années d'attaques contre des entités gouvernementales et des ONG. Ci-dessous, vous pouvez voir que Mustang Panda privilégie les techniques de phishing pour l'accès initial, se maintient dans le système (*Persistence*) via des tâches planifiées, obscurcit des fichiers pour contourner les défenses, et utilise le transfert d'outils entrants (*Ingress Tool Transfer*) pour le contrôle et la commande (C2). Pour les questions de cet exercice, vous allez analyser la page dédiée à Mustang Panda et sa matrice associée à l'aide d'ATT&CK Navigator.

### Informations Générales (Mustang Panda)

* **À propos** : Mustang Panda (G0129) - Techniques Enterprise utilisées par Mustang Panda, groupe ATT&CK G0129 (v2.1)
* **Domaine** : Enterprise ATT&CK v17
* **Plateformes** : Windows, Linux, macOS, Équipements Réseau, ESXi, PRE, Conteneurs, IaaS, SaaS, Suite bureautique, Fournisseur d'identité

---

### Matrice des Tactiques et Techniques (Exemple Mustang Panda)

| Développement de ressources | Accès Initial | Exécution | Persistance | Élévation de privilèges | Contournement des défenses | Accès aux identifiants | Découverte | Déplacement Latéral | Collecte | Commande et Contrôle |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Acquérir une infrastructure | Phishing **(Sélectionné)** | Interpréteur de commandes et de scripts **(Sélectionné)** | Exécution automatique au démarrage ou à la session | Exécution automatique au démarrage ou à la session | Garde-fous d'exécution | Extraction d'identifiants OS | Découverte de fichiers et répertoires | Réplication via des supports amovibles | Archiver les données collectées | Protocole de la couche application |
| Établir des comptes | Réplication via des supports amovibles | Exécution de codes via l'exploitation de clients | Exécution déclenchée par un événement | Exécution déclenchée par un événement | Masquer des artefacts |  | Découverte de processus **(Sélectionné)** |  | Collecte automatisée | Canal chiffré |
| Obtenir des capacités |  | Tâche/Travail planifié | Détournement du flux d'exécution | Détournement du flux d'exécution | Détournement du flux d'exécution |  | Découverte de logiciels |  | Données centralisées (*Data Staged*) | Transfert d'outils entrants **(Sélectionné)** |
| Centraliser les capacités |  | Exécution par l'utilisateur | Tâche/Travail planifié **(Sélectionné)** | Tâche/Travail planifié | Suppression d'indicateurs |  | Découverte d'informations système |  |  | Protocole hors couche application |
|  |  | Instrumentation de gestion Windows (WMI) |  |  | Usurpation d'identité (*Masquerading*) |  | Découverte de la configuration réseau système |  |  | Proxy |
|  |  |  |  |  | Fichiers ou informations obscurcis **(Sélectionné)** |  | Découverte des connexions réseau système |  |  | Outils d'accès à distance |
|  |  |  |  |  |  |  |  |  |  | Service Web |

---

## ATT&CK pour le Renseignement sur les Menaces

Dans l'exercice précédent, nous avons vu comment les organisations utilisent le renseignement sur les cybermenaces (CTI) pour comprendre le comportement des adversaires et orienter les stratégies de défense en alignant ces informations sur le référentiel ATT&CK. Vous avez également acquis de l'expérience avec le Navigator pour analyser les TTPs d'un groupe. À présent, vous allez utiliser ces nouvelles connaissances pour effectuer des recherches sur les groupes de menaces susceptibles de cibler votre organisation.

```text
Rapport CTI (Rapport de Cyber Threat Intelligence)
L'ordre chronologique ou logique des tactiques identifiées dans le rapport :
1. Reconnaissance
2. Initial Access (Accès Initial)
3. Persistence (Persistance)
4. Defense Evasion (Contournement des défenses)
5. Collection (Collecte)

Matrice de Correspondance ATT&CK
Voici l'association entre les étapes du rapport CTI et les identifiants uniques des techniques MITRE ATT&CK :

| Étape | Nom de la Tactique | ID de la Technique ATT&CK |
| :---: | :--- | :--- |
| **1** | Reconnaissance | **T1595** (Active Scanning) |
| **2** | Initial Access | **T1190** (Exploit Public-Facing Application) |
| **3** | Persistence | **T1136** (Create Account) |
| **4** | Defense Evasion | **T1564** (Hide Artifacts) |
| **5** | Collection | **T1560** (Archive Collected Data) |

```

---

## Cyber Analytics Repository (CAR)

MITRE définit le *Cyber Analytics Repository* (CAR) comme « une base de connaissances d'analyses développée par MITRE et basée sur le modèle d'adversaire MITRE ATT&CK. CAR définit un modèle de données exploité dans ses représentations en pseudocode, mais inclut également des implémentations directement ciblées sur des outils spécifiques (par exemple, Splunk, EQL) dans ses analyses. En ce qui concerne la couverture, CAR se concentre sur la fourniture d'un ensemble d'analyses validées et bien expliquées, en particulier en ce qui concerne leur théorie de fonctionnement et leur logique. »

Tout cela semble un peu complexe, alors simplifions. CAR est une collection d'analyses de détection prêtes à l'emploi, construites autour d'ATT&CK. Chaque analyse décrit comment détecter le comportement d'un adversaire. C'est un élément clé car cela vous permet d'identifier les schémas et comportements spécifiques à rechercher en tant que défenseur. CAR fournit également des exemples de requêtes pour des outils courants du marché comme Splunk, afin que vous puissiez traduire les TTPs d'ATT&CK en détections réelles.

Passons à la pratique avec CAR. Commençons par examiner l'analyse **CAR-2020-09-001 : Scheduled Task - File Access**. En visitant la page, nous y trouvons une description de l'analyse ainsi que des références aux tactiques et techniques ATT&CK associées.

Dans la section *Implementations*, vous trouverez du pseudocode, une requête Splunk et une recherche LogPoint, qui servent d'exemples pour montrer comment un analyste peut filtrer cette technique à l'aide du SIEM (*Security Information and Event Management*) de son organisation. Le pseudocode est une façon simple et lisible par un humain de décrire une série d'instructions ou d'algorithmes qu'un programme ou un système va exécuter. Notez que toutes les analyses au sein de CAR ne disposent pas des mêmes exemples d'implémentation. Certaines incluent même des tests unitaires (*Unit Tests*), qu'un analyste peut utiliser pour vérifier si l'analyse fonctionne comme prévu.

CAR possède également sa propre couche dans l'ATT&CK Navigator (*layer*), où les techniques sont cartographiées dans une matrice similaire à celle que vous avez vue lors de l'étude des groupes. Vous utiliserez la liste des analyses CAR et sa matrice pour répondre aux questions de cet exercice.

---

## Le Référentiel MITRE D3FEND

Avec MITRE ATT&CK, vous apprenez comment les attaques se produisent, mais avec MITRE D3FEND, vous découvrez comment les arrêter.

D3FEND (*Detection, Denial, and Disruption Framework Empowering Network Defense*) est un référentiel structuré qui cartographie les techniques défensives et établit un langage commun pour décrire le fonctionnement des mesures de sécurité. D3FEND dispose de sa propre matrice, qui se divise en sept tactiques, chacune ayant ses techniques et identifiants associés.

Par exemple, la technique de rotation des identifiants (**Credential Rotation - D3-CRO**) met l'accent sur le changement régulier des mots de passe pour empêcher les attaquants de réutiliser des identifiants volés. D3FEND explique le fonctionnement de cette défense, les éléments à prendre en compte lors de sa mise en œuvre, ainsi que ses liens avec des artefacts numériques spécifiques et des techniques ATT&CK. Cela vous aide à visualiser les deux perspectives : le mouvement de l'attaquant et la contre-mesure du défenseur.

### Rotation des identifiants (*Credential Rotation*)

**ID :** D3-CRO

### Définition

La rotation des identifiants est une procédure de sécurité dans laquelle les données d'authentification, telles que les mots de passe, les clés d'API ou les certificats, sont régulièrement modifiées ou remplacées afin de minimiser le risque d'accès non autorisé.

### Fonctionnement

Les identifiants peuvent être modifiés de manière systématique à des intervalles prédéfinis ou en fonction d'événements spécifiques. Si les identifiants tels que les mots de passe des utilisateurs peuvent être modifiés manuellement, il est de plus en plus courant d'utiliser un système automatisé pour gérer la rotation des mots de passe, des certificats et des clés à l'échelle de l'entreprise.

### Relations avec les artefacts numériques

*Cette technique défensive est liée à des artefacts numériques spécifiques. Cliquez sur le nœud de l'artefact pour plus d'informations.*

```text
                  ┌──────────────┐          ┌──────────────┐
                  │  use-limits  ├─────────►│ Mot de passe │
                  └──────────────┘          └──────────────┘
                  ┌──────────────┐          ┌──────────────┐
                  │  regenerates ├─────────►│ Identifiant  │
┌────────────────┐└──────────────┘          └──────────────┘
│  Rotation des  │┌──────────────┐           
│  Identifiants  ││   hardens    ├─────────►┌──────────────┐
└────────────────┘└──────────────┘          │              │
                  ┌──────────────┐          │ Certificat   │
                  │  regenerates ├─────────►│              │
                  └──────────────┘          └──────────────┘

```

---

## Autres Projets de MITRE

Au-delà des référentiels et des outils abordés précédemment, MITRE propose plusieurs autres projets conçus pour aider les professionnels de la cybersécurité à renforcer leurs compétences, tester leurs défenses et déjouer les plans des attaquants. Dans cet exercice, nous allons explorer brièvement ces outils et la manière dont ils peuvent soutenir votre progression dans le domaine.

### Plans d'émulation (*Emulation Plans*)

La bibliothèque d'émulation d'adversaires de MITRE (*Adversary Emulation Library*), principalement maintenue et alimentée par le CTID (*Center for Threat Informed Defense*), est une ressource gratuite de plans d'émulation d'adversaires. La bibliothèque contient actuellement plusieurs émo-simulations qui reproduisent fidèlement des attaques réelles menées par des groupes de menaces connus. Ces plans d'émulation sont des guides étape par étape sur la façon d'imiter un groupe de menaces spécifique.

**Caldera** est un outil automatisé d'émulation d'adversaires conçu pour aider les équipes de sécurité à tester et améliorer leurs défenses. Il offre la possibilité de simuler le comportement d'un attaquant dans le monde réel en s'appuyant sur le référentiel ATT&CK. Cela permet aux défenseurs d'évaluer l'efficacité de leurs méthodes de détection et de s'entraîner à la réponse aux incidents dans un environnement contrôlé. Caldera prend en charge les opérations offensives et défensives, ce qui en fait un outil puissant pour les exercices de *Red Team* et *Blue Team*.

### Référentiels nouveaux et émergents

* **AADAPT** (*Adversarial Actions in Digital Asset Payment Technologies*) est une base de connaissances récemment publiée qui intègre sa propre matrice. Elle couvre les tactiques et techniques des adversaires liées aux systèmes de gestion des actifs numériques. AADAPT suit une structure similaire à celle du référentiel ATT&CK vu précédemment et vise à aider les défenseurs à comprendre et à atténuer les menaces ciblant les réseaux blockchain, les contrats intelligents (*smart contracts*), les portefeuilles numériques (*wallets*) et d'autres technologies d'actifs numériques.
* **ATLAS** (*Adversarial Threat Landscape for Artificial-Intelligence Systems*) est une base de connaissances et un référentiel comprenant une matrice dédiée aux menaces ciblant les systèmes d'intelligence artificielle et d'apprentissage automatique (*machine learning*). Il documente les techniques d'attaque du monde réel, les vulnérabilités et les mesures d'atténuation spécifiques aux technologies d'IA.
