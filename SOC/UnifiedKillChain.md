# INTRODUCTION

Comprendre les comportements, les objectifs et les méthodologies d'une cybermenace est une étape vitale pour établir une défense solide (appelée **posture de cybersécurité**).

Dans ce module, vous découvrirez le framework **UKC (Unified Kill Chain)**, utilisé pour analyser et comprendre le déroulement des cyberattaques.

### Objectifs d'apprentissage :

* Comprendre pourquoi les frameworks comme l'UKC sont essentiels pour établir une bonne posture de cybersécurité.
* Utiliser l'UKC pour décoder les motivations, les méthodologies et les tactiques d'un attaquant.
* Maîtriser les différentes phases de l'UKC.
* Découvrir comment l'UKC s'utilise en complément d'autres frameworks, comme le MITRE ATT&CK.

---

## La Kill Chain (Chaîne d'attaque)

Originaire du milieu militaire, le terme « Kill Chain » désigne les différentes étapes d'une offensive. En cybersécurité, elle décrit la méthodologie et le cheminement horizontal ou vertical empruntés par des attaquants (hackers, groupes APT) pour approcher et infiltrer une cible.

> **Exemple de Kill Chain :** Un attaquant scanne un système, exploite une vulnérabilité web, puis élève ses privilèges.

L'objectif de la défense est de calquer ses mesures sur cette chaîne pour bloquer l'attaquant le plus tôt possible, soit en protégeant le système de manière préventive, soit en perturbant sa progression.

---

## Qu'est-ce que la « Modélisation des menaces » (Threat Modelling) ?

Dans un contexte de cybersécurité, la modélisation des menaces est une suite de processus visant à améliorer la sécurité d'un système en identifiant ses risques. Elle se résume à quatre piliers :

1. **Identifier** les systèmes et applications à sécuriser et comprendre leur rôle (ex: ce système est-il critique pour l'activité ? Contient-il des données sensibles comme des coordonnées bancaires ou des adresses ?).
2. **Évaluer** les vulnérabilités et faiblesses de ces composants et la manière dont elles pourraient être exploitées.
3. **Créer un plan d'action** pour corriger les failles mises en évidence.
4. **Mettre en place des politiques** pour éviter que ces vulnérabilités ne se reproduisent (ex: intégrer un cycle de vie de développement logiciel sécurisé [SDLC] ou former les employés au phishing).

La modélisation des menaces offre une vue d'ensemble (macro) des actifs IT (logiciels et matériels) d'une organisation. L'UKC s'intègre parfaitement dans cette démarche puisqu'il aide à cartographier les surfaces d'attaque potentielles.

*Note : STRIDE, DREAD ou le CVSS sont d'autres frameworks dédiés à la modélisation et à l'évaluation des risques.*

---

## Présentation de l'Unified Kill Chain (UKC)

Développée par Paul Pols et publiée en 2017, l'**Unified Kill Chain** (chaîne d'attaque unifiée) est née pour compléter (et non concurrencer) les frameworks existants comme ceux de Lockheed Martin ou le MITRE ATT&CK.

L'UKC structure une attaque autour de **18 phases**, allant de la reconnaissance initiale jusqu'à l'exfiltration des données et l'analyse du mobile de l'attaquant. Pour des raisons de clarté, ces phases sont ici regroupées par grands objectifs.

### Les forces de l'UKC face aux modèles traditionnels :

* **Modernité :** Sorti en 2017 et mis à jour en 2022, il colle aux réalités du cloud et du travail moderne.
* **Granularité :** 18 phases précises, là où les anciens modèles n'en comptent qu'une poignée.
* **Couverture de bout en bout :** Il englobe l'avant, le pendant et l'après-exploitation.

```text
L'Unified Kill Chain (18 phases)

1. Reconnaissance         Recherche, identifie et sélectionne les cibles (active ou passive).
2. Armement               Activités préparatoires pour monter l'infrastructure d'attaque.
3. Livraison              Techniques de transmission de l'élément malveillant vers la cible.
4. Ingénierie Sociale     Manipulation psychologique pour pousser à une action dangereuse.
5. Exploitation           Exploitation d'une faille pour obtenir une exécution de code.
6. Persistance            Action maintenant un accès durable dans le système.
7. Évasion de Défense     Techniques pour contourner la détection et les antivirus/pare-feu.
8. Command & Control (C2) Canaux de communication entre l'attaquant et les machines compromises.
9. Pivotement (Pivoting)  Faire transiter du trafic via une machine compromise pour en atteindre d'autres.
10. Découverte            Collecte d'informations internes sur le réseau et l'environnement.
11. Élévation de Privilèges Obtenir des droits supérieurs (Admin, Root, SYSTEM).
12. Exécution             Lancement du code malveillant sur une machine locale ou distante.
13. Accès aux Identifiants Vol de mots de passe, hashs ou jetons de session.
14. Déplacement Latéral   Se déplacer horizontalement vers d'autres machines du réseau.
15. Collecte              Centralisation des données d'intérêt avant de les exfiltrer.
16. Exfiltration          Extraction des données en dehors du réseau de l'entreprise.
17. Impact                Manipulation, interruption ou destruction des données/systèmes.
18. Objectifs             Atteinte du but stratégique final (financier, politique, espionnage).

```

### Tableau comparatif des frameworks

| Avantages de l'Unified Kill Chain (UKC) | Comparaison avec les autres frameworks |
| --- | --- |
| **Moderne** (créé en 2017, mis à jour en 2022). | Certains modèles comme le MITRE initial sont nés en 2013, à une époque où le paysage des menaces était différent. |
| **Extrêmement détaillé** (18 phases). | Les frameworks traditionnels se limitent souvent à 7 ou 8 étapes linéaires. |
| **Couverture complète** (de la reconnaissance à la post-exploitation, incluant la motivation). | Les autres modèles se focalisent souvent sur un seul segment (ex: uniquement l'intrusion ou uniquement le réseau local). |
| **Scénario d'attaque réaliste** (modèle non linéaire). Les attaquants reviennent souvent en arrière (ex: après un pivot, retour à la phase de reconnaissance). | Les anciens frameworks n'intègrent pas nativement ces allers-retours indispensables lors d'une vraie attaque. |

---

## Objectif 1 : In (Le Point d'Ancrage Initial)

```text
Cycle d'intrusion (sens horaire) :
1. Reconnaissance
2. Armement
3. Livraison
4. Ingénierie Sociale
5. Exploitation
6. Persistance
7. Évasion de Défense
8. Command & Control

Étape de transition :
9. Pivotement (voie de sortie vers le réseau interne)

```

L'enjeu de ce premier bloc est de **pénétrer le système**. L'attaquant cherche les failles de périmètre (ex: services exposés sur Internet) pour obtenir un premier accès, s'y maintenir (persistance) et s'assurer qu'il peut communiquer avec sa cible (C2) malgré les défenses.

### Focus sur les phases de l'étape « IN » :

* **1. Reconnaissance (Tactique MITRE TA0043) :** Collecte d'informations sur la cible (scans de ports pour trouver les versions des logiciels, extraction de l'organigramme de l'entreprise sur LinkedIn pour préparer un phishing, cartographie réseau).
* **2. Armement (Tactique MITRE TA0001) :** Configuration de l'infrastructure de l'attaquant. Il achète des noms de domaine, monte ses serveurs de Command & Control (C2) et prépare ses charges utiles (*payloads*).
* **3. Ingénierie Sociale (Tactique MITRE TA0001) :** Manipulation des collaborateurs. Cela va de l'email d'hameçonnage visant à faire ouvrir une pièce jointe piégée à l'appel téléphonique en se faisant passer pour le support informatique afin de forcer une réinitialisation de mot de passe.
* **4. Exploitation (Tactique MITRE TA0002) :** L'exploitation pure de la vulnérabilité technique pour forcer l'exécution de code (ex: téléverser un *reverse shell* via une faille d'upload sur un site web).
* **5. Persistance (Tactique MITRE TA0003) :** Garantir que l'accès reste actif même si la machine redémarre (création d'une tâche planifiée, ajout d'un service système malveillant ou création d'un compte utilisateur caché).
* **6. Évasion de Défense (Tactique MITRE TA0005) :** Contournement de la sécurité en place. L'attaquant modifie la signature de ses fichiers pour tromper l'antivirus, chiffre ses scripts pour passer sous les radars des pare-feux applicatifs (WAF) ou efface ses logs d'activité.
* **7. Command & Control (Tactique MITRE TA0011) :** Activation du canal de communication bidirectionnel. La machine compromise « appelle » le serveur de l'attaquant pour attendre et exécuter ses ordres.
* **8. Pivotement (Tactique MITRE TA0008) :** Utiliser la première machine compromise comme une passerelle (tunnel) pour attaquer des machines internes qui ne sont pas directement accessibles depuis Internet.

---

## Objectif 2 : Through (La Propagation Réseau)

Une fois le premier pied dans la place, si l'attaquant n'est pas directement sur la machine qui l'intéresse, il doit naviguer au sein de l'infrastructure interne de l'entreprise. C'est la phase d'extension et de mouvement horizontal.

```text
Phases du bloc « THROUGH » :
1. Pivotement
2. Découverte
3. Élévation de Privilèges
4. Exécution
5. Accès aux Identifiants
6. Déplacement Latéral
7. Accès aux objectifs (voie de sortie)

```

* **1. Pivotement (Tactique MITRE TA0008) :** La machine compromise initiale devient la base opérationnelle avancée. Tout le trafic d'attaque va transiter par elle pour s'enfoncer dans le réseau interne.
* **2. Découverte (Tactique MITRE TA0007) :** Cartographie de l'environnement interne. L'attaquant cherche à savoir où il a atterri : quels sont les partages réseaux accessibles, quels sont les logiciels installés et quels comptes utilisateurs sont actifs.
* **3. Élévation de Privilèges (Tactique MITRE TA0004) :** Passage d'un compte utilisateur standard à un compte à hauts privilèges (SYSTEM, ROOT, Administrateur du Domaine) en exploitant des mauvaises configurations ou des failles de noyaux locaux.
* **4. Exécution (Tactique MITRE TA0002) :** Déploiement et exécution de scripts C2, chevaux de Troie ou tâches planifiées à distance sur les nouvelles machines cibles du réseau.
* **5. Accès aux Identifiants (Tactique MITRE TA0006) :** Vol de mots de passe ou de clés via des enregistreurs de frappe (*keylogging*) ou du vidage de mémoire (*credential dumping* comme avec Mimikatz). Utiliser de vrais identifiants volés rend l'attaquant presque invisible pour les outils de surveillance.
* **6. Déplacement Latéral (Tactique MITRE TA0008) :** L'attaquant saute de machine en machine en utilisant ses privilèges fraîchement acquis jusqu'à atteindre le cœur du système (par exemple, le contrôleur de domaine Active Directory).

---

## Objectif 3 : Out (Actions sur les Objectifs)

Le bloc « OUT » représente l'aboutissement de l'attaque. L'intrus est désormais positionné sur les serveurs critiques et passe à l'action. Ces tactiques visent généralement à briser la triade **C-I-A** (Confidentialité, Intégrité, Disponibilité des données).

```text
Phases du bloc « OUT » :
1. Collecte
2. Exfiltration
3. Impact
4. Objectifs

```

* **1. Collecte (Tactique MITRE TA0009) :** L'attaquant localise et centralise toutes les données de valeur (fichiers clients, secrets industriels, bases de données de cartes bancaires). Cette phase cible la **confidentialité** des informations.
* **2. Exfiltration (Tactique MITRE TA0010) :** Extraction des données collectées hors du réseau de la victime. Pour ne pas lever d'alertes, l'attaquant compresse, fragmente et chiffre ces données avant de les faire sortir via ses tunnels C2.
* **3. Impact (Tactique MITRE TA0040) :** Altération de l'**intégrité** ou de la **disponibilité** des données. C'est ici qu'interviennent les attaques par Ransomware (chiffrement des disques), le sabotage, la dégradation de sites web (*defacement*) ou le déni de service (DoS) pour bloquer l'activité de l'entreprise.
* **4. Objectifs :** Accomplissement du but stratégique global. Si la motivation est financière, c'est l'étape de la demande de rançon (double extorsion : payer pour déchiffrer ET payer pour éviter que les données exfiltrées soient publiées). S'il s'agit d'un concurrent ou d'un État, l'objectif sera plutôt l'espionnage à long terme ou la destruction de la réputation de l'entreprise.
