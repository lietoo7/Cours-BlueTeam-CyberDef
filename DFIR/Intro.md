## Introduction à la Réponse aux Incidents (Incident Response)

Imaginez que vous viviez dans une rue très peu sûre et que vous possédiez des objets de grande valeur chez vous. Vous penseriez naturellement à engager un agent de sécurité, à installer des caméras de surveillance (CCTV) ou même à cacher vos biens les plus précieux dans une pièce secrète au sous-sol. Ce sont des mesures **proactives** que vous planifiez avant même qu'une attaque ne survienne.

Mais avez-vous déjà réfléchi à ce qu'il se passerait si quelqu'un réussissait à contourner toutes vos sécurités extérieures pour entrer chez vous ? Vous devez également prévoir des mesures à prendre **après** que votre domicile a été attaqué.

### Le passage au monde numérique

Dans le domaine digital, les attaques causant des pertes de milliers de dollars sont quotidiennes. On appelle cela des **Incidents de Cybersécurité**. Tout comme pour la sécurité de votre maison, ces incidents nécessitent une planification et des ressources spécifiques pour éviter des pertes colossales.

La **Réponse aux Incidents** consiste à gérer un incident de son début à sa fin. C'est un ensemble de directives complètes qui vont du déploiement de la sécurité pour prévenir les intrusions jusqu'à la lutte active contre l'attaque et la minimisation de son impact.

 

## Objectifs d'apprentissage

Ce module vous aidera à comprendre les concepts critiques de la réponse aux incidents et vous donnera l'occasion de résoudre votre premier cas pratique :

* **Vue d'ensemble des incidents** et de leurs niveaux de **sévérité**.
* Les **types d'incidents** les plus courants.
* Les **phases de la Réponse aux Incidents** selon les frameworks **SANS** et **NIST**.
* Les outils de détection et de réponse, ainsi que le rôle des **Playbooks** (guides de procédures).
* L'élaboration d'un **Plan de Réponse aux Incidents**.

---

## Qu'est-ce qu'un Incident ?

Sur vos appareils numériques (ordinateurs, téléphones), de nombreux processus s'exécutent en permanence. Certains sont **interactifs** (quand vous jouez à un jeu), d'autres sont **non-interactifs** et tournent en arrière-plan pour le bon fonctionnement du système.

Tous ces processus génèrent des **événements**. Chaque action effectuée est enregistrée (loguée). Comme ces événements sont produits en quantités massives, nous utilisons des solutions de sécurité pour les analyser et y détecter des activités suspectes. C'est là que le défi commence.

### 1. Alertes, Faux Positifs et Vrais Positifs

Lorsqu'un outil de sécurité détecte un comportement suspect, il déclenche une **alerte**. L'équipe de sécurité doit alors qualifier cette alerte :

* **Faux Positif (False Positive) :** L'alerte semble dangereuse mais ne l'est pas.
* *Exemple :* Une alerte se déclenche pour un transfert massif de données vers l'extérieur. Après analyse, il s'avère qu'il s'agissait d'une **sauvegarde planifiée** vers le cloud. C'est inoffensif.


* **Vrai Positif (True Positive) :** L'alerte signale une activité réellement malveillante.
* *Exemple :* Une alerte signale une tentative de **phishing**. L'analyse confirme qu'un mail malveillant a été envoyé pour compromettre un utilisateur. C'est un danger réel.


### 2. Définition de l'Incident

Un **Vrai Positif** est ce que l'on appelle un **Incident**. Une fois l'incident confirmé, il faut lui attribuer un niveau de priorité.

### 3. La Sévérité des Incidents (Severity)

Si vous recevez plusieurs incidents en même temps, comment choisir lequel traiter en premier ? On utilise pour cela des niveaux de sévérité basés sur l'**impact** potentiel :

| Niveau | Priorité | Description |
| --- | --- | --- |
| **Critique** | **1** | Impact immédiat et majeur sur l'entreprise (ex: Ransomware en cours). |
| **Élevé (High)** | **2** | Menace sérieuse nécessitant une intervention rapide. |
| **Moyen (Medium)** | **3** | Activité suspecte nécessitant une investigation, mais sans danger immédiat. |
| **Faible (Low)** | **4** | Violation mineure ou incident à faible impact. |

> **L'analyste dit :** La gestion de la sévérité est une question de **Triage**. On traite toujours le "Critique" avant le "Faible" pour limiter les dégâts au maximum.

---
## Les Types d'Incidents

En cybersécurité, on évite le terme trop vague de "piratage". Les incidents sont classés par catégories selon la nature de l'attaque. Plusieurs types d'incidents peuvent survenir de manière indépendante ou se combiner lors d'une même attaque.

### 1. Infections par Logiciels Malveillants (Malware)

Le **malware** est un programme conçu pour endommager un système, un réseau ou une application. C'est la cause de la majorité des incidents.

* **Vecteurs :** Fichiers textes, documents Office, exécutables, etc.
* **Variété :** Il existe de nombreux types (Ransomwares, chevaux de Troie, spywares), chacun ayant un potentiel de nuisance unique.

### 2. Violations de Sécurité (Security Breaches)

On parle de **violation** (ou brèche) lorsqu'une personne non autorisée accède à des données confidentielles.

* **Enjeu :** Pour beaucoup d'entreprises, la confidentialité est vitale. Si un tiers accède à des secrets industriels ou des fichiers clients, l'impact est immédiat.

### 3. Fuites de Données (Data Leaks)

C'est l'exposition d'informations confidentielles à des entités non autorisées.

* **Différence avec la brèche :** Contrairement à une violation (souvent intentionnelle), une fuite peut être causée par une **erreur humaine** ou une **mauvaise configuration** (ex: une base de données laissée ouverte sur internet sans mot de passe).
* **Conséquence :** Atteinte à la réputation ou chantage de la part d'attaquants.

### 4. Attaques Internes (Insider Attacks)

Ces incidents proviennent de l'intérieur de l'organisation.

* **Exemple :** Un employé mécontent qui infecte le réseau avec une clé USB lors de son dernier jour de travail.
* **Danger :** Ces attaques sont redoutables car l'auteur possède déjà des accès légitimes et une connaissance du réseau bien supérieure à celle d'un attaquant externe.

### 5. Attaques par Déni de Service (DoS / DDoS)

L'**Accessibilité** (Availability) est un pilier de la sécurité. Une donnée protégée est inutile si elle n'est pas accessible.

* **Méthode :** L'attaquant inonde un système ou un site web de fausses requêtes jusqu'à épuisement des ressources (processeur, bande passante).
* **Résultat :** Le service devient indisponible pour les utilisateurs légitimes.

 

## L'Impact : Une notion relative

L'impact d'un type d'incident varie d'une entreprise à l'autre. Il n'y a pas de hiérarchie fixe entre ces catégories :

> **Exemple comparatif :**
> * **Entreprise A (Stockage de données publiques) :** Une **fuite de données** aura peu d'impact car ses infos sont déjà publiques. Par contre, un **Déni de Service (DoS)** sera désastreux car ses revenus dépendent de la disponibilité de son site.
> * **Entreprise B (Cabinet d'avocats) :** Un **DoS** de quelques heures est gênant, mais une **fuite de données** confidentielles de clients serait une catastrophe fatale pour l'entreprise.
> 
> 

---
## Techniques de Réponse aux Incidents

Identifier manuellement un incident est une tâche titanesque. Heureusement, plusieurs solutions de sécurité automatisent la détection et, pour certaines, une partie de la réponse (confinement, éradication).

### 1. Les Solutions Technologiques de l'IR

| Outil | Rôle dans la Réponse aux Incidents |
| --- | --- |
| **SIEM** | Centralise et corrèle les logs pour **identifier** l'incident. |
| **Antivirus (AV)** | **Détecte et supprime** les programmes malveillants connus. |
| **EDR** | Offre une protection avancée sur chaque poste. Il peut **confiner** (isoler le poste) et **éradiquer** la menace à distance. |

 

### 2. Playbooks vs Runbooks : Vos guides de survie

Face à l'urgence, chaque seconde compte. Pour éviter les erreurs, les équipes utilisent des documents de référence.

#### Les Playbooks (Le "Quoi faire")

Un **Playbook** est une directive globale pour répondre à un type d'incident spécifique. C'est le plan d'ensemble.

**Exemple de Playbook : Incident de Phishing**

1. **Notifier** toutes les parties prenantes de l'incident.
2. **Déterminer** si l'email est malveillant (analyse de l'en-tête et du corps du mail).
3. **Analyser** les éventuelles pièces jointes.
4. **Vérifier** si des utilisateurs ont ouvert les pièces jointes ou cliqué sur les liens.
5. **Isoler** les systèmes infectés du réseau.
6. **Bloquer** l'expéditeur de l'email au niveau du serveur.

#### Les Runbooks (Le "Comment faire")

Le **Runbook** est une déclinaison plus technique et détaillée. Alors que le Playbook dit "Analysez l'en-tête", le Runbook expliquera précisément quelle commande taper ou quel outil ouvrir pour le faire. Ces étapes peuvent varier selon les outils dont dispose l'entreprise.

### Résumé de la différence

* **Playbook :** La stratégie globale pour un type d'attaque (ex: Phishing, Ransomware).
* **Runbook :** Les étapes techniques précises, clic par clic (ex: "Comment isoler un hôte sur CrowdStrike EDR").

---
## Techniques de Réponse aux Incidents

Comme nous l'avons vu dans la phase d'**Identification** (SANS) ou de **Détection et Analyse** (NIST), repérer manuellement des comportements anormaux est extrêmement difficile. C'est pourquoi le recours à des solutions de sécurité est indispensable.

### 1. Les Solutions Technologiques de Réponse

Certaines solutions ne se contentent pas de détecter ; elles peuvent aussi exécuter les phases de confinement et d'éradication :

* **SIEM (Security Information and Event Management) :** Il centralise tous les journaux (logs) importants en un seul lieu et les corrèle pour identifier des incidents complexes.
* **AV (Antivirus) :** Il détecte les programmes malveillants connus sur un système et effectue des scans réguliers pour les éliminer.
* **EDR (Endpoint Detection and Response) :** Déployé sur chaque machine, il protège contre les menaces avancées. Il permet d'isoler un hôte du réseau (**confinement**) et de supprimer la menace (**éradication**) à distance.

 

### 2. Playbooks vs Runbooks : Vos guides de survie

Une fois l'incident identifié, il faut agir vite. Avoir des instructions prêtes à l'emploi permet de gagner un temps précieux.

#### Les Playbooks (Le "Quoi faire")

Un **Playbook** est une directive globale pour une réponse complète. C'est la stratégie de haut niveau pour un type d'incident.

**Exemple de Playbook : Email de Phishing**

1. **Notifier** toutes les parties prenantes de l'incident de phishing.
2. **Déterminer** si l'email est malveillant (analyse de l'en-tête et du corps du mail).
3. **Analyser** les éventuelles pièces jointes de l'email.
4. **Vérifier** si des utilisateurs ont ouvert les pièces jointes.
5. **Isoler** les systèmes infectés du réseau.
6. **Bloquer** l'expéditeur de l'email.

#### Les Runbooks (Le "Comment faire")

À l'inverse, les **Runbooks** sont l'exécution détaillée, étape par étape, de points spécifiques. Par exemple, si le Playbook dit "Isoler le système", le Runbook expliquera précisément quelles commandes taper dans l'EDR pour effectuer cette isolation. Ces étapes varient selon les outils techniques dont dispose l'entreprise.

 

### Résumé de la différence

> * **Playbook** = La recette de cuisine (Les étapes générales).
> * **Runbook** = Les gestes techniques précis (La température exacte, le temps de cuisson, l'outil à utiliser).
> 
> 

---

 
