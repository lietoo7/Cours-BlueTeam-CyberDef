# INTRODUCTION

Dans ce module, nous allons découvrir comment la suite Elastic (ELK) est utilisée pour l'analyse de logs et les investigations numériques. 
Bien qu'ELK ne soit pas un SIEM traditionnel, de nombreuses équipes SOC (Security Operations Center) l'utilisent comme tel en raison de ses puissantes capacités de recherche et de visualisation de données. 
Nous explorerons les différents composants d'ELK, la manière d'y effectuer des analyses de logs, ainsi que la création de visualisations et de tableaux de bord (dashboards).

### Objectifs d'apprentissage

* Comprendre les composants d'ELK et leur utilité au sein d'un SOC.
* Explorer les différentes fonctionnalités d'ELK.
* Apprendre à rechercher et filtrer les données dans ELK.
* Enquêter sur des logs VPN pour identifier des anomalies.
* Se familiariser avec la création de visualisations et de tableaux de bord dans ELK.

---

## ELK : LES BASES

### Présentation de la suite (Stack Overview)

La suite Elastic (ELK) a été développée à l'origine pour stocker, rechercher et visualiser d'importants volumes de données. Les entreprises l'utilisaient pour surveiller les performances des applications et effectuer des recherches dans de grands ensembles de données. Au fil du temps, ses fonctionnalités l'ont également rendue populaire dans le domaine de la cybersécurité. Aujourd'hui, de nombreuses équipes SOC utilisent ELK comme une solution SIEM.

La suite Elastic est un ensemble de différents composants open-source qui collaborent pour collecter des données depuis n'importe quelle source, les stocker, permettre d'y effectuer des recherches et les visualiser en temps réel. Avant de passer à l'analyse des logs, examinons ses composants clés.

#### 1. Elasticsearch

Le premier composant, Elasticsearch, est un moteur de recherche plein texte (full-text) et d'analyse conçu pour les documents au format JSON. Il stocke, analyse et corrèle les données, et propose une API RESTful pour interagir avec lui.

#### 2. Logstash

Logstash est un moteur de traitement de données qui reçoit les données de différentes sources, les filtre ou les normalise, puis les envoie vers une destination (comme Kibana ou un port d'écoute). Un fichier de configuration Logstash se divise en trois parties :

* **Input (Entrée) :** L'utilisateur y définit la source d'où proviennent les données ingérées.
* **Filter (Filtre) :** L'utilisateur y spécifie les options de filtrage pour normaliser les logs ingérés.
* **Output (Sortie) :** La destination où les données filtrées doivent être envoyées (port d'écoute, interface Kibana, base de données Elasticsearch, fichier, etc.).

*Syntaxe de base :* `input {} , filter {}, output {}`

#### 3. Beats

Les Beats sont des agents légers installés sur les hôtes (data-shippers) qui transfèrent les données depuis les points de terminaison (endpoints) vers Elasticsearch ou Logstash. Chaque agent Beat est spécialisé dans l'envoi d'un type de données précis (ex: Winlogbeat pour les événements Windows, Packetbeat pour le trafic réseau).

#### 4. Kibana

Kibana est un outil de visualisation de données basé sur le web qui s'interface avec Elasticsearch pour analyser, examiner et visualiser les flux de données en temps réel. Il permet aux utilisateurs de créer de multiples visualisations et tableaux de bord pour une meilleure visibilité.

#### Fonctionnement global (Étape par étape)

1. **Collecte des données:** Étape 1 : Beats.
Les agents Beats collectent les données sur les machines (ex: Winlogbeat pour les logs d'événements Windows, Packetbeat pour le trafic réseau).


2. **Traitement et normalisation:** Étape 2 : Logstash.
Logstash centralise les données des Beats, de ports ou de fichiers, les analyse/normalise sous forme de paires clé-valeur (champs), puis les transmet.


3. **Stockage et indexation:** Étape 3 : Elasticsearch.
Elasticsearch reçoit les données, agit comme une base de données indexée et permet de rechercher et d'analyser rapidement les informations.


4. **Analyse et visualisation:** Étape 4 : Kibana.
Kibana extrait et met en forme visuellement les données stockées dans Elasticsearch sous forme de graphiques, chronologies ou infographies.


```text
       _ _ _ _ _ _     _ _ _ _ _ _     _ _ _ _ _ _     _ _ _ _ _ _     _ _ _ _ _ _
      (           )   (           )   (           )   (           )   (           )
     (    Beats    ) (   Logstash  ) (   Elastic   ) (  recherche  )  (    Kibana  )
     (   ☁️10110...)  (           )   (           )   (           )   (           )
      (_ _ _ _ _ _)   (_ _ _ _ _ )      (_ _ _ _ _)     (_ _ _ _ _)     (_ _ _ _ _)


        ┌─────────────┐               ┌─────────────┐               ┌─────────────┐
        │             │               │Entrée Data /│               │             │
        │ Collecte de │────>────>─┬─>─│ Filtrage /  │────>────>─┬─>─│ Indexation /│──<─>───┐
        │ Données     │           │   │ Traitement /│           │   │ Stockage    │        │
        │ (Agents)    │           │   │ Sortie      │           │   │             │        │
        └─────────────┘           │   └─────────────┘           │   └─────────────┘        │
                                  └──────────────>─────────────┬┘                          │
                                                               │                           │
                                                               │   ┌─────────────┐         │
                                                               └──>│  Analyse /  │<────────┘
                                                                   │Visualisation│
                                                                   │             │
                                                                   └─────────────┘

```

---

### Onglet Discover (Découvrir)

L'onglet **Discover** est l'espace de travail principal dans Kibana où les analystes SOC passent la majorité de leur temps pour explorer, rechercher et analyser les données brutes.

---

### Syntaxe KQL (Kibana Query Language)

Le **KQL** est le langage spécifique utilisé dans la barre de recherche de Kibana pour interroger les logs stockés dans Elasticsearch. 
Il existe deux méthodes principales pour effectuer des recherches :

#### 1. Recherche textuelle libre (Free text search)

Elle recherche un terme dans l'intégralité du document, indépendamment du champ.

* *Exemple :* Chercher `"United States"` retournera tous les documents contenant exactement cette expression.
* *Attention :* Chercher uniquement `United` ne retournera pas de résultat si le mot exact dans le document est "United States", car KQL cherche le mot entier.
* *Caractère générique (Wildcard) :* L'astérisque `*` permet de remplacer une partie de mot. La requête `United*` retournera "United", "United States", "United Nations", etc.

#### 2. Opérateurs logiques (AND | OR | NOT)

* **AND :** Retourne les logs contenant tous les termes spécifiés.
* *Requête :* `"United States" AND "Virginia"`


* **OR :** Retourne les logs contenant l'un ou l'autre des termes.
* *Requête :* `"United States" OR "England"`


* **NOT :** Exclut un terme spécifique des résultats.
* *Requête :* `"United States" AND NOT ("Florida")` *(Affiche tous les États américains sauf la Floride)*



#### 3. Recherche par champ (Field-based search)

Permet de cibler un champ précis en utilisant la syntaxe `Champ : Valeur`.

* *Exemple de requête :* `Source_ip : 238.163.231.224 AND UserName : Suleman`
* *Explication :* Kibana affichera uniquement les logs où l'adresse IP source est `238.163.231.224` et l'utilisateur est `Suleman`.

---

### Création de visualisations

L'onglet de visualisation permet de donner une forme graphique aux données (tableaux, graphiques en camembert, diagrammes en barres, etc.).

* **Créer une visualisation :** Vous pouvez y accéder directement depuis l'onglet *Discover* en cliquant sur un champ puis sur l'option de visualisation.
* **Corrélation de données :** Il est possible de croiser plusieurs champs. Par exemple, glisser-déposer le champ `Source_Country` en second plan permet de corréler les adresses IP sources (`Source_IP`) avec leur pays d'origine sous forme de graphique en camembert (Top 5 des pays) ou de tableau croisé.

#### Procédure de sauvegarde d'une visualisation

1. Créez votre visualisation et cliquez sur le bouton **Save** (Enregistrer) en haut à droite.
2. Ajoutez un **titre** et une **description** explicites.
3. Cliquez sur **Save and add to library** (Enregistrer et ajouter à la bibliothèque).

*Explication pratique :* Vous pouvez utiliser cette méthode pour générer un tableau croisant les utilisateurs et les adresses IP impliqués dans des tentatives de connexion échouées (`Failed Connection Attempts`).

---

### Création d'un tableau de bord personnalisé (Custom Dashboard)

Après avoir sauvegardé vos recherches et vos visualisations, vous pouvez les centraliser dans l'onglet Dashboard.

#### Étapes de création :

1. Allez dans l'onglet **Dashboard** et cliquez sur **Create dashboard**.
2. Cliquez sur **Add from Library** (Ajouter depuis la bibliothèque).
3. Sélectionnez vos visualisations et recherches sauvegardées pour les intégrer au tableau de bord.
4. Ajustez la taille et la disposition des éléments sur l'écran.
5. **Sauvegardez impérativement** le tableau de bord une fois terminé.

---

**Répondez aux questions ci-dessous**
*Créez le tableau de bord contenant les visualisations disponibles.*

---
