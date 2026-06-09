## Introduction à l'Informatique Légale (Digital Forensics)

La **forensics** (science légale) est l'application de méthodes et de procédures pour enquêter et résoudre des crimes. 
La branche qui étudie les crimes informatiques est appelée la **Digital Forensics** (ou informatique légale).

Un **cybercrime** désigne toute activité criminelle menée sur ou via un appareil numérique. 
Divers outils et techniques sont utilisés pour examiner minutieusement ces appareils après un crime, afin de trouver et d'analyser des preuves en vue d'une action en justice.

 

### L'évolution de la criminalité

Si les appareils numériques ont facilité la communication mondiale, leur usage massif a également entraîné une augmentation des crimes numériques.

#### Étude de cas : Le cambrioleur de banque

Imaginons que les forces de l'ordre perquisitionnent le domicile d'un braqueur de banque. Ils saisissent un ordinateur portable, un téléphone mobile, un disque dur et une clé USB. L'affaire est confiée à l'équipe de **Digital Forensics**, qui mène l'enquête dans un laboratoire spécialisé.

**Voici les preuves extraites des appareils :**

* **Sur l'ordinateur :** Une carte numérique de la banque utilisée pour planifier le braquage et des photos/vidéos d'anciens méfaits.
* **Sur le disque dur :** Un document détaillant les issues de secours et une liste des dispositifs de sécurité physique de la banque avec des plans pour les contourner.
* **Sur le téléphone :** Des historiques d'appels et des discussions dans des groupes de messagerie illégaux liés au braquage.

Toutes ces preuves permettent d'étayer le dossier lors des procédures judiciaires. Pour être valables, ces preuves doivent être collectées, stockées et analysées selon des protocoles très stricts.

 

## Objectifs d'apprentissage

Ce module explore les procédures rigoureuses suivies par les experts en informatique légale :

* **Les phases de l'informatique légale** (le cycle de vie d'une investigation).
* **Les types d'informatique légale** (réseau, mémoire, disque, etc.).
* **La procédure d'acquisition des preuves** (comment copier des données sans les altérer).
* **La "Windows Forensics"** (spécificités du système Windows).
* **Résolution d'un cas pratique.**

---
## Méthodologie de l'Informatique Légale

Bien que chaque affaire soit unique, le **NIST** (National Institute of Standards and Technology) a défini un cadre universel en quatre phases pour structurer toute investigation numérique.

### Les 4 Phases du NIST

1. **La Collecte (Collection) :**
C’est la phase initiale. L'enquêteur doit identifier tous les supports potentiels (PC, caméras, clés USB, etc.).
* **Point critique :** Il est impératif de garantir que les données originales ne sont pas altérées (**intégrité**) et de tenir un registre précis (chaîne de responsabilité) de chaque objet saisi.


2. **L'Examen (Examination) :**
Le volume de données collectées peut être colossal. Cette phase consiste à filtrer et extraire les données pertinentes.
* *Exemple :* Si vous saisissez une caméra, vous ne garderez peut-être que les photos prises à une date précise, ou seulement les fichiers d'un utilisateur spécifique sur un ordinateur multi-comptes.


3. **L'Analyse (Analysis) :**
Phase cruciale où l'enquêteur fait parler les données. Il s'agit de corréler les indices pour tirer des conclusions et reconstituer la **chronologie des événements** (timeline) liés au crime.
4. **Le Rapport (Reporting) :**
La phase finale consiste à rédiger un document détaillé expliquant la méthodologie et les découvertes.
* **Conseil :** Le rapport doit inclure un **résumé décisionnel** (executive summary) accessible aux non-experts (juges, direction), car tout le monde n'a pas un profil technique.


## Les Spécialités de la Digital Forensics

Selon le support ou l'environnement, les techniques varient. Voici les types les plus courants :

| Type | Périmètre d'action |
| --- | --- |
| **Computer Forensics** | Enquête sur les ordinateurs et stations de travail (le plus fréquent). |
| **Mobile Forensics** | Extraction de SMS, journaux d'appels, localisations GPS et applications mobiles. |
| **Network Forensics** | Analyse du trafic réseau et des logs pour comprendre comment une attaque s'est propagée. |
| **Database Forensics** | Investigation sur les bases de données pour détecter des vols ou modifications de données. |
| **Cloud Forensics** | Analyse des données stockées sur le Cloud. Complexe car l'enquêteur a moins de contrôle direct sur l'infrastructure. |
| **Email Forensics** | Analyse des courriels pour identifier des campagnes de **phishing** ou des fraudes internes. |

---
## L'Acquisition des Preuves (Evidence Acquisition)

L'acquisition est une tâche critique : l'équipe de forensics doit collecter toutes les preuves de manière sécurisée sans jamais altérer les données originales. Bien que les méthodes varient selon l'appareil, certaines pratiques générales sont incontournables.

### 1. L'Autorisation Appropriée (Proper Authorization)

Avant de collecter la moindre donnée, l'équipe doit obtenir l'autorisation des autorités compétentes (mandat de perquisition, accord de la direction, etc.).

* **Pourquoi ?** Une preuve collectée sans approbation préalable peut être déclarée **irrecevable** devant un tribunal. Comme les preuves numériques contiennent des données privées et sensibles, l'autorisation garantit que l'enquête reste dans les limites de la loi.

### 2. La Chaîne de Responsabilité (Chain of Custody)

Imaginez que des preuves disparaissent ou soient modifiées après quelques jours, mais que personne ne puisse être tenu pour responsable faute de suivi. Pour éviter cela, on utilise un document de **Chaîne de Responsabilité**.
C'est un document formel qui trace tout l'historique de la preuve. Il contient généralement :

* La **description** de la preuve (nom, type, numéro de série).
* L'**identité** des personnes ayant collecté la preuve.
* La **date et l'heure** précises de la collecte.
* Le **lieu de stockage** sécurisé.
* L'historique des accès (qui a consulté la preuve, quand et pourquoi).

> **L'enjeu :** Ce document prouve l'**intégrité** et la **fiabilité** de la preuve devant une cour de justice. Il garantit que la preuve présentée au juge est exactement la même que celle saisie sur la scène du crime.

### 3. L'utilisation de Bloqueurs d'Écriture (Write Blockers)

Les bloqueurs d'écriture sont des outils indispensables.

* **Le problème :** Si vous branchez le disque dur d'un suspect directement sur votre ordinateur de travail, votre système d'exploitation peut modifier automatiquement les dates d'accès aux fichiers ou créer des fichiers cachés, altérant ainsi la preuve.
* **La solution :** Un **bloqueur d'écriture** (physique ou logiciel) s'interpose entre le disque suspect et l'ordinateur de l'enquêteur. Il permet de lire et de copier les données tout en bloquant physiquement toute commande d'écriture. Le disque du suspect reste ainsi dans son état d'origine exact.

 

### Récapitulatif du matériel de l'enquêteur

| Outil / Concept | Rôle |
| --- | --- |
| **Mandat / Autorisation** | Cadre légal de l'action. |
| **Chaîne de Responsabilité** | Document de suivi "qui a touché à quoi". |
| **Bloqueur d'écriture** | Protection physique contre l'altération des données. |
| **Hachage (Hashing)** | (Souvent couplé à l'acquisition) Signature numérique pour vérifier l'intégrité. |

---

