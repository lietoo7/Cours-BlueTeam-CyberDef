### Synthèse Technique : Opération PicoSecure (Room Summit)
Source : TryHackMe, Summit Room : https://tryhackme.com/room/summit  

L'exercice consiste à analyser des journaux d'activité (logs) sur un outil de gestion des alertes et à configurer un pare-feu/EDR fictif pour bloquer l'attaquant à chaque étape.

#### Étape 1 : Les Hashes de Fichiers (Niveau : Trivial)

* **Analyse des logs :** L'examen des fichiers récemment exécutés ou téléchargés révèle un exécutable suspect dans les répertoires temporaires des utilisateurs.
* **Extraction :** Identification du hash SHA256 du malware (par exemple, un binaire malveillant utilisé pour l'accès initial).
* **Action corrective :** Ajout du hash dans la liste de blocage de l'EDR (*Malware Hashes*).
* **Résultat :** L'attaquant voit son binaire initial bloqué, le forçant à modifier son fichier pour changer le hash.

#### Étape 2 : Les Adresses IP (Niveau : Facile)

* **Analyse des logs :** Une fois le premier binaire bloqué, l'attaquant utilise une autre méthode qui génère du trafic réseau direct vers une adresse IP externe non répertoriée (connexion C2 brute).
* **Extraction :** Identification de l'adresse IP malveillante via les connexions sortantes suspectes.
* **Action corrective :** Configuration d'une règle de pare-feu (*Network Connections*) pour interdire tout flux sortant vers cette IP.
* **Résultat :** Le canal de communication direct est coupé, forçant l'attaquant à utiliser une résolution de nom (DNS).

#### Étape 3 : Noms de Domaine (Niveau : Simple)

* **Analyse des logs :** Privé d'IP fixe, l'attaquant configure un sous-domaine dynamique (ex: `exfiltrer.picosym.thm` ou similaire) pour relancer son infrastructure de Command & Control. Les logs DNS montrent des requêtes répétitives vers ce domaine.
* **Extraction :** Identification du FQDN (Fully Qualified Domain Name) malveillant.
* **Action corrective :** Ajout du domaine dans le filtre de requêtes DNS de l'entreprise (*DNS Filter*).
* **Résultat :** L'infrastructure réseau de l'attaquant est de nouveau aveugle. Il doit modifier ses indicateurs réseau.

#### Étape 4 : Artéfacts Réseau et d'Hôte (Niveau : Agaçant)

* **Analyse des logs :** L'attaquant parvient à s'exécuter localement mais laisse des traces spécifiques : création d'une clé de registre persistante bien précise ou modification d'un fichier de configuration local (`.ini`, `.bat`).
* **Extraction :** Identification du chemin exact de la clé de registre ou du fichier créé par le script de l'attaquant.
* **Action corrective :** Configuration d'une règle de surveillance/blocage sur l'hôte (*Host Artifacts*) ciblant cet emplacement précis.
* **Résultat :** L'attaquant ne peut plus maintenir sa persistance sous cette forme.

#### Étape 5 : Outils (Niveau : Difficile)

* **Analyse des logs :** L'attaquant déploie un outil connu de l'arsenal offensif (par exemple, une version modifiée de *PsExec* ou un script *PowerShell* spécifique d'exfiltration) pour automatiser ses tâches, en le renommant pour échapper aux filtres basiques.
* **Extraction :** Analyse du comportement de l'outil (arguments de ligne de commande spécifiques, chaînes de caractères uniques en mémoire).
* **Action corrective :** Définition d'une règle de détection basée sur la signature comportementale ou les arguments de l'outil (*Tools*).
* **Résultat :** L'utilitaire est neutralisé, obligeant l'attaquant à réécrire ses propres scripts ou à changer de framework.

#### Étape 6 : Tactiques, Techniques & Procédures - TTPs (Niveau : Douloureux)

* **Analyse des logs :** L'attaquant tente sa dernière chance en combinant l'utilisation du Planificateur de tâches Windows (*Scheduled Tasks*) et le détournement de processus légitimes pour exfiltrer des données à des intervalles de temps stricts.
* **Extraction :** Compréhension globale de la tactique : l'attaquant abuse d'une fonctionnalité native du système (Living off the Land).
* **Action corrective :** Création d'une règle globale interdisant la création de tâches planifiées pointant vers des répertoires non signés ou exécutant du code obscurci (*TTPs*).
* **Résultat :** Le coût de modification est trop élevé pour l'attaquant, le vecteur d'attaque est structurellement fermé. **Obtention du Flag final.**

  
