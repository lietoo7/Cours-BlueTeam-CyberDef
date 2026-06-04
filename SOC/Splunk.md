# INTRODUCTION

 Splunk repose sur une architecture distribuée et modulaire capable d'absorber n'importe quel type de données structurées, semi-structurées ou non structurées (logs web, événements Windows, Sysmon, flux réseau, bases de données, etc.). Lors de l'ingestion, ces données brutes sont transformées en une série d'événements horodatés et indexés.

---

## The BASICS

### Les Composants

L'architecture fondamentale de Splunk s'appuie sur trois composants interconnectés, chacun ayant un rôle précis dans la chaîne de traitement de l'information :

* **Le Forwarder**
  Le *Splunk Forwarder* est un agent léger installé directement sur les points de terminaison (endpoints) ou serveurs à surveiller (serveurs web, contrôleurs de domaine Windows, serveurs Linux, bases de données). Sa fonction principale est de collecter les logs locaux à la source et de les acheminer de manière sécurisée et continue vers l'instance de traitement Splunk. Conçu pour être minimaliste, il consomme très peu de ressources afin de ne pas impacter les performances de la machine hôte.

* **L'Indexer**
  Le *Splunk Indexer* est le moteur central de stockage et de transformation. Il reçoit les données brutes envoyées par les *Forwarders*, les analyse, les normalise (extraction automatique sous forme de paires clé-valeur) et détermine leur type de source (*sourcetype*). Il segmente ensuite ces données en événements distincts, leur associe un horodatage précis et les stocke sur le disque sous forme d'index chiffrés et optimisés pour la recherche rapide.

* **Le Search Head**
  Le *Splunk Search Head* constitue l'interface utilisateur et l'environnement analytique centralisé (via notamment l'application native *Search & Reporting*). Lorsqu'un analyste SOC ou un administrateur soumet une requête en langage **SPL** (Splunk Search Processing Language), le *Search Head* distribue la requête aux *Indexers*, récupère les résultats filtrés et les présente. Il permet également de traduire ces données brutes en tableaux de bord dynamiques, en alertes et en visualisations graphiques (diagrammes circulaires, histogrammes, etc.).

### La navigation 

L'accès à l'interface web de Splunk s'effectue par défaut via un navigateur sur un port dédié (généralement `8000`). La page d'accueil s'articule autour de plusieurs zones clés :

1. **La barre Splunk (Splunk Bar) :** Située tout en haut, elle offre une vue globale du système. Elle permet d'accéder aux messages d'alerte système (*Messages*), à la configuration et à l'administration de l'instance (*Settings*), au suivi des tâches de recherche en cours (*Activity*), à l'aide en ligne (*Help*) et à un outil de recherche rapide (*Find*). C'est aussi un moyen rapide de basculer d'une application à une autre.
2. **Le panneau des applications (Apps Panel) :** Situé sur la partie gauche de l'écran, il liste l'ensemble des modules d'extension et applications installés sur l'instance. L'application standard et indispensable pour tout analyste est **Search & Reporting**.
3. **La zone d'exploration (Explore Splunk) :** Située au centre, elle propose des raccourcis intuitifs pour interagir rapidement avec l'outil, notamment pour ajouter de nouvelles sources de données, installer des applications tierces (via Splunkbase) ou consulter la documentation officielle.
4. **Le tableau de bord d'accueil (Home Dashboard) :** Zone personnalisable permettant d'épingler des graphiques et des indicateurs de performance (KPI) pertinents pour l'utilisateur ou l'équipe de sécurité.
 
### Ajouter des DATA

L'ingestion de données est le point de départ de toute investigation. Dans le scénario pratique traité (analyse des logs VPN), le processus suit une méthodologie standardisée en 5 étapes via l'option **Upload** (chargement d'un fichier local) :

1. **Select Source :** Sélection et importation du fichier de logs brut (ex: `VPN_logs`).
2. **Select Source Type :** Spécification de la nature des logs pour guider l'extraction automatique de Splunk (reconnaissance du format de date, des délimiteurs, etc.).
3. **Input Settings :** Configuration des métadonnées essentielles. C'est à cette étape que l'on définit la machine d'origine (*host*) et, surtout, que l'on crée ou sélectionne l'**Index** de destination (qui cloisonne logiquement les données, par exemple l'index dédié `VPN_Logs`).
4. **Review :** Vérification globale des paramètres d'importation avant validation.
5. **Done :** Confirmation du succès de l'opération. Les données sont immédiatement prêtes à être interrogées dans l'application *Search & Reporting*.

 sateur associé au nom de **Smith**.
* **Filtrage par exclusion géographique :** Pour dénombrer les événements hors de la France, l'utilisation de l'opérateur d'inégalité `!=` via la requête `Source_Country!="France"` retourne un total de **2 814** événements.
* **Analyse de trafic suspect par adresse IP :** La recherche isolée `Source_ip="107.3.206.58"` démontre que cette adresse IP spécifique a initié exactement **14** événements VPN.
