## Introduction au SOC (Security Operations Center)

La technologie a rendu nos vies plus efficaces, mais cette efficacité s'accompagne d'une responsabilité accrue. Les craintes de l'ère moderne ont bien évolué depuis l'époque de l'exploitation des actifs physiques. Les données critiques, appelées **secrets**, ne sont plus stockées dans des dossiers papier. Les organisations transportent des tonnes de données confidentielles au sein de leurs réseaux et de leurs systèmes.

Toute interruption, perte ou modification non autorisée de ces données peut leur causer des dommages considérables. Chaque jour, des **acteurs malveillants** (threat actors) découvrent et exploitent de nouvelles vulnérabilités dans ces réseaux, ce qui représente une préoccupation majeure pour la cybersécurité.

Les pratiques de sécurité traditionnelles peuvent ne pas suffire à prévenir bon nombre de ces menaces. Il est donc devenu crucial de dédier une équipe entière à la gestion de la sécurité de votre organisation.

### Qu'est-ce qu'un SOC ?

Un **SOC** est une installation dédiée, pilotée par une équipe de sécurité spécialisée. L'objectif de cette équipe est de surveiller en continu le réseau et les ressources d'une organisation, et d'identifier toute activité suspecte afin de prévenir les dommages. Cette équipe travaille **24 heures sur 24, 7 jours sur 7**.
 

## Objectifs d'apprentissage

Ce module va approfondir certains concepts clés du SOC, l'un des domaines les plus importants de la sécurité défensive :

* **Établir une base de référence** pour le SOC.
* Comprendre la **détection et la réponse** au sein du SOC.
* Analyser le rôle des **Personnes, des Processus et de la Technologie**.

---
## Objectifs et Composants (Purpose and Components)

L'objectif principal de l'équipe SOC est de maintenir l'intégrité de la **Détection** et de la **Réponse**. Pour y parvenir, l'équipe dispose de ressources sous forme de solutions de sécurité. Ces outils intègrent l'ensemble du réseau et des systèmes de l'entreprise afin de les surveiller depuis un emplacement centralisé. Une surveillance continue est indispensable pour détecter tout incident de sécurité et y répondre.

### 1. La Détection (Detection)

* **Détecter les vulnérabilités :** Une vulnérabilité est une faiblesse qu'un attaquant peut exploiter pour effectuer des actions dépassant son niveau d'autorisation. Elle peut se trouver dans le logiciel d'un appareil (système d'exploitation ou programmes).
* *Exemple :* Le SOC peut découvrir un parc d'ordinateurs Windows devant être patchés contre une faille spécifique. Bien que la gestion des vulnérabilités ne soit pas strictement la responsabilité du SOC, des failles non corrigées affectent le niveau de sécurité global.


* **Détecter les activités non autorisées :** Si un attaquant dérobe les identifiants d'un employé, il est crucial de détecter cette connexion frauduleuse avant qu'elle ne cause des dégâts. Des indices comme la **géolocalisation** (connexion depuis un pays inhabituel) aident à cette détection.
* **Détecter les violations de politique :** Une politique de sécurité est un ensemble de règles visant à protéger l'entreprise. Les violations varient selon les entreprises, comme le téléchargement de fichiers piratés ou l'envoi non sécurisé de fichiers confidentiels.
* **Détecter les intrusions :** Cela désigne l'accès non autorisé aux systèmes. Par exemple, un attaquant exploitant une faille sur une application web ou un utilisateur visitant un site malveillant qui infecte son poste.

### 2. La Réponse (Response)

* **Soutien à la réponse aux incidents :** Une fois l'incident détecté, des étapes sont suivies pour y répondre, notamment pour **minimiser l'impact** et effectuer une **analyse de la cause profonde** (root cause analysis). L'équipe SOC assiste l'équipe de réponse aux incidents (CERT/CSIRT) dans ces démarches.

## Les Trois Piliers : PPT

Pour qu'un SOC soit mature et efficace, il doit reposer sur trois piliers indissociables : **Les Personnes, les Processus et la Technologie.**

> **Le saviez-vous ?** > Une technologie de pointe sans processus clair mène au chaos, et des processus parfaits sans personnel qualifié sont inutiles. L'équilibre entre ces trois éléments définit la maturité du SOC.

| Pilier | Rôle dans le SOC |
| --- | --- |
| **People (Personnes)** | L'expertise humaine pour analyser et prendre des décisions. |
| **Process (Processus)** | Les règles et protocoles qui dictent "qui fait quoi" et "comment". |
| **Technology (Technologie)** | Les outils (SIEM, EDR) qui collectent et traitent les données massivement. |

---
## Le Pilier "People" : L'Humain au Cœur du SOC

Peu importe l'évolution de l'automatisation des tâches de sécurité, l'élément humain dans un SOC restera toujours primordial. Une solution de sécurité peut générer de nombreux drapeaux rouges ("red flags"), créant un **bruit numérique** colossal.

> **L'analogie du pompier :**
> Imaginez que vous fassiez partie d'une brigade de pompiers disposant d'un logiciel centralisant toutes les alarmes incendie de la ville. Si vous recevez des dizaines d'alertes simultanées et que, sur place, votre équipe découvre qu'il ne s'agissait que de fumée de cuisine, vos efforts et vos ressources auraient été gaspillés.

Dans un SOC, sans intervention humaine, on finit par se concentrer sur des problèmes insignifiants. Ce sont les **analystes** qui aident les outils à identifier les activités réellement malveillantes et permettent une réponse rapide.

 

## Rôles et Responsabilités

L'équipe SOC est généralement structurée en plusieurs niveaux d'expertise :

### 1. Analyste SOC - Niveau 1 (L1) : Le Triage

C'est le **premier intervenant**. Toute alerte détectée par les outils passe d'abord entre ses mains.

* **Mission :** Effectuer le triage de base pour déterminer si une détection est réellement dangereuse ou s'il s'agit d'un faux positif.
* **Action :** Signaler les détections via les canaux appropriés.

### 2. Analyste SOC - Niveau 2 (L2) : L'Investigation

Il prend le relais quand une alerte nécessite une analyse plus poussée.

* **Mission :** Corréler les données provenant de multiples sources pour comprendre l'ampleur d'une attaque.
* **Action :** Approfondir les recherches que le Niveau 1 ne peut pas finaliser.

### 3. Analyste SOC - Niveau 3 (L3) : L'Expertise et la Chasse

Ce sont des professionnels expérimentés qui agissent de manière proactive.

* **Mission :** Pratiquer le **Threat Hunting** (chasse aux menaces) et soutenir la réponse aux incidents critiques.
* **Action :** Gérer le confinement, l'éradication et la récupération après une attaque majeure.

### 4. Ingénieur Sécurité (Security Engineer)

Les analystes utilisent des outils, mais ces outils doivent être installés et entretenus.

* **Mission :** Déployer, configurer et maintenir les solutions de sécurité pour garantir leur bon fonctionnement.

### 5. Ingénieur de Détection (Detection Engineer)

La détection repose sur des règles logiques (le "cerveau" des outils).

* **Mission :** Créer et affiner les règles de détection pour identifier les comportements malveillants. Ce rôle est parfois rempli par les analystes L2/L3.

### 6. Responsable SOC (SOC Manager)

Le chef d'orchestre de l'équipe.

* **Mission :** Gérer les processus suivis par l'équipe et assurer le lien avec le **CISO** (Responsable de la Sécurité des Systèmes d'Information - RSSI).
* **Action :** Rapporter l'état de la posture de sécurité et les efforts fournis par le SOC à la direction.

 

### Résumé des niveaux d'intervention

| Rôle | Focus Principal |
| --- | --- |
| **L1** | Réception & Triage (Vrai ou Faux ?) |
| **L2** | Analyse & Corrélation (Comment et Pourquoi ?) |
| **L3** | Chasse & Réponse Incident (Où se cachent-ils ?) |

---

## Le Pilier "Process" : La Méthodologie du SOC

Nous avons vu les rôles ; voyons maintenant comment ils collaborent. Chaque rôle suit des **processus** précis. Par exemple, l'analyste de Niveau 1 suit un protocole strict pour le triage des alertes.

### 1. Le Triage des Alertes (Alert Triage)

Le triage est la base du travail en SOC. C'est la première réponse à toute alerte. Son but est d'analyser l'alerte pour déterminer sa **gravité** et définir sa **priorité**.

Le triage repose sur la méthode des **5 W** (les 5 questions "Qui, Quoi, Où, Quand, Pourquoi").

#### Exemple de Triage

**Alerte :** *Malware détecté sur l'hôte : GEORGE PC*

| Question | Question (FR) | Réponse de l'analyse |
| --- | --- | --- |
| **What?** | **Quoi ?** | Un fichier malveillant a été détecté sur un hôte du réseau. |
| **When?** | **Quand ?** | Le fichier a été détecté à 13h20, le 5 juin 2024. |
| **Where?** | **Où ?** | Dans un répertoire de l'ordinateur "GEORGE PC". |
| **Who?** | **Qui ?** | Le fichier est lié à la session de l'utilisateur "George". |
| **Why?** | **Pourquoi ?** | L'utilisateur a téléchargé le fichier depuis un site de logiciels piratés pour obtenir un logiciel gratuitement. |

 
### 2. Le Reporting (Signalement)

Lorsqu'une alerte est confirmée comme étant nuisible, elle doit être **escaladée** aux analystes de niveaux supérieurs pour une résolution rapide.

* Les alertes sont transformées en **tickets** et assignées aux personnes concernées.
* Le rapport doit inclure les **5 W**, une analyse approfondie et des **captures d'écran** servant de preuves de l'activité suspecte.

 
### 3. Réponse aux Incidents et Forensics (Analyse de preuves)

Parfois, les détections signalent des activités critiques. Dans ce cas, les équipes de haut niveau déclenchent une **Réponse aux Incidents (IR)**.

* **Incident Response :** Un processus structuré pour contenir et éradiquer la menace.
* **Forensics (Informatique légale) :** Une activité détaillée visant à déterminer la **cause profonde** (root cause) de l'incident en analysant les traces numériques (*artifacts*) laissées sur le système ou le réseau.

---
## Le Pilier "Technology" : L'Arsenal du SOC

Disposer des meilleures **personnes** et des meilleurs **processus** ne suffirait pas sans solutions de sécurité pour la détection et la réponse. Le pilier technologique désigne l'ensemble des solutions logicielles qui permettent de réduire considérablement l'effort manuel nécessaire pour identifier et contrer les menaces.

Dans un réseau d'entreprise composé de milliers d'appareils et d'applications, surveiller chaque élément individuellement serait impossible. La technologie permet de **centraliser** les informations et d'**automatiser** une partie de la détection.

 
## Les Outils Majeurs du SOC

### 1. Le SIEM (Security Information and Event Management)

Le **SIEM** est l'outil central de presque tous les SOC.

* **Fonctionnement :** Il collecte les journaux (logs) de divers équipements réseau (les "sources de logs").
* **Détection :** On y configure des **règles de corrélation** (logique permettant d'identifier une activité suspecte en croisant les données).
* **Évolution :** Les SIEM modernes utilisent l'apprentissage automatique (Machine Learning) et l'analyse du comportement des utilisateurs (UEBA) pour détecter des menaces complexes.

> **Note importante :** Dans un environnement SOC, le SIEM sert principalement à la **Détection**.

### 2. L'EDR (Endpoint Detection and Response)

L'**EDR** offre une visibilité détaillée, en temps réel et historique, sur l'activité des terminaux (ordinateurs, serveurs).

* **Niveau d'action :** Il opère directement sur l'hôte (endpoint).
* **Capacité :** Il permet d'enquêter minutieusement sur un incident et de lancer des actions de réponse (comme isoler un ordinateur du réseau) en quelques clics.

### 3. Le Pare-feu (Firewall)

Le **Firewall** est une barrière de sécurité réseau entre votre réseau interne et l'extérieur (Internet).

* **Rôle :** Il surveille le trafic entrant et sortant et filtre tout trafic non autorisé.
* **Prévention :** Grâce à ses propres règles de détection, il bloque le trafic suspect avant même qu'il ne pénètre dans le réseau interne.

 

## Autres solutions courantes

Selon la surface d'attaque et les ressources de l'organisation, d'autres outils peuvent être déployés :

* **IDS/IPS :** Systèmes de détection et de prévention d'intrusion.
* **SOAR :** Outil d'orchestration et d'automatisation de la réponse (pour lier les outils entre eux).
* **XDR :** Extension de l'EDR qui englobe plus de sources de données (réseau, cloud, email).

 
### Synthèse des Piliers (PPT)

| Composant | Rôle Clé |
| --- | --- |
| **People** | Prise de décision, analyse critique et expertise. |
| **Process** | Structure, cohérence et méthodologie d'enquête. |
| **Technology** | Centralisation, visibilité et automatisation de la détection. |

---

