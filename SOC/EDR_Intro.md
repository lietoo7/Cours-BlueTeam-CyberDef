# Introduction
La détection et la réponse des terminaux (EDR — Endpoint Detection and Response) est une solution de sécurité conçue pour 
surveiller, détecter et répondre aux menaces avancées au niveau des terminaux. 

En tant qu'analyste SOC, il est essentiel de comprendre le fonctionnement d'un EDR, car c'est une solution largement adoptée par les organisations pour protéger leurs terminaux. Dans cette salle, nous verrons en quoi un EDR diffère d'un antivirus traditionnel et quelles données il collecte depuis les terminaux. 
Nous discuterons également des capacités de détection et de réponse qu'il fournit.

## Objectifs d'apprentissage
- Comprendre les bases de l'EDR et son mode de fonctionnement
- Distinguer l'EDR des solutions antivirus traditionnelles
- Examiner l'architecture d'une solution EDR
- Analyser les types de télémétrie qu'elle collecte depuis les terminaux
- Comprendre les capacités de détection et de réponse d'un EDR
- Étudier une alerte réaliste dans l'EDR
  
## Qu'est ce qu'un EDR ?
L’augmentation de l’utilisation des appareils numériques est indéniable. La plupart des fonctions essentielles des entreprises reposent sur ces appareils. Les cybermenaces, quant à elles, augmentent chaque jour. Pour protéger ces appareils, les organisations mettent en place plusieurs mesures de sécurité, principalement pour protéger le réseau sur lequel fonctionnent ces appareils numériques. Cependant, l’adoption rapide du télétravail a exposé ces appareils hors du périmètre de protection déployé sur le réseau de l’organisation.

Pour garantir la protection de ces postes même en dehors du réseau, nous avons besoin d’une solution de sécurité qui protège tous les appareils dans différents environnements et soit capable de lutter contre des menaces avancées. La détection et la réponse des terminaux (EDR — Endpoint Detection and Response) est une solution de sécurité qui offre une protection approfondie des terminaux. Où qu’ils se trouvent, l’EDR s’assure qu’ils sont constamment surveillés et que les menaces sont détectées.

Voici quelques solutions EDR disponibles sur le marché :
- CrowdStrike Falcon
- SentinelOne ActiveEDR
- Microsoft Defender for Endpoint
- OpenEDR
- Symantec EDR

D’autres solutions EDR existent sur le marché. Leurs architectures sous-jacentes sont pour la plupart similaires, mais les fonctionnalités peuvent varier.

Regardons maintenant les fonctionnalités principales d’un EDR. Nous utiliserons des captures d’écran de CrowdStrike Falcon EDR pour illustrer les fonctionnalités principales.

## Fonctionnalités de l’EDR
Un EDR repose sur trois fonctionnalités principales, que l’on peut aussi appeler les trois piliers d’une solution EDR.

* Visibilité
Une bonne analyse dépend souvent du niveau de visibilité disponible. C’est l’une des caractéristiques qui distingue l’EDR des autres solutions de sécurité pour terminaux. Le niveau de visibilité fourni par un EDR est impressionnant. Il collecte des données détaillées depuis les terminaux : modifications de processus, modifications du registre, modifications de fichiers et dossiers, actions des utilisateurs, et bien plus encore. Il présente ensuite ces informations de manière structurée à l’analyste. L’analyste peut voir l’arbre des processus complet avec une chronologie détaillée des actions. Il peut aussi accéder aux données historiques de n’importe quel terminal pour le threat hunting ou toute autre analyse. Toute détection dans l’EDR arrive avec un contexte complet.

Modifications de processus — Modifications du registre — Modifications de fichiers et dossiers — Actions utilisateur — Et plus encore

La capture d’écran suivante montre une représentation graphique d’un arbre de processus : on peut voir quels processus ont été lancés sur le terminal. Chaque nœud représente un processus; les lignes montrent leurs relations. En cliquant sur l’icône + associée à chaque processus, on peut voir toutes les connexions réseau, les modifications du registre, les changements de fichiers, etc., liés à ce processus.

* Détection
La fonctionnalité de détection de l’EDR surpasse les capacités de détection traditionnelles. Elle combine des détections basées sur des signatures et des détections comportementales, comme des activités utilisateur inattendues. Grâce au machine learning moderne, elle identifie toute déviation par rapport au comportement de référence et la signale immédiatement. Elle peut aussi détecter des malwares sans fichiers résidant en mémoire. Il est également possible d’alimenter l’EDR avec des IOC personnalisés pour la détection des menaces.

La capture d’écran suivante montre un tableau de bord récapitulant les détections sur différents terminaux. Chaque détection apparaît sur une ligne avec plusieurs champs : sévérité, heure, fichier déclencheur, nom d’hôte, nom d’utilisateur, etc. Le champ « Tactic via Technique » relie la détection au cadre MITRE. En cliquant sur une détection, on accède à des détails riches aidant l’analyste SOC dans son investigation.

* Réponse
L’EDR permet aussi aux analystes d’agir sur les menaces détectées. Ces actions peuvent être lancées sur n’importe quel terminal depuis la console centrale de l’EDR. Lorsqu’une détection fournit des détails complets (quand, où, quoi), l’analyste choisit la meilleure action : isoler un terminal, terminer un processus, mettre en quarantaine des fichiers, etc. Il est aussi possible de se connecter à distance à l’hôte et d’exécuter des actions depuis la console.

La capture d’écran suivante montre les actions disponibles après connexion à un hôte (console RTR — Real Time Response).

Plusieurs autres actions sont possibles pendant l’investigation.

Remarque : dans la tâche n°6, nous aborderons plus en détail les capacités de détection et de réponse d’un EDR.

Avec une visibilité, une détection et une réponse avancées, l’EDR devient un outil très puissant. Il est toutefois important de rappeler qu’un EDR est une solution de sécurité centrée sur l’hôte et ne détecte pas les menaces au niveau réseau.

## Au-delà de l’antivirus
Avant d’expliquer le fonctionnement interne d’un EDR, répondons à une question courante : pourquoi un EDR si un antivirus (AV) est déjà installé sur les terminaux ?

Bien que ces deux solutions visent à protéger le terminal, elles diffèrent par le niveau de protection. Imaginons qu’un aéroport représente un terminal à protéger. Une couche de protection consiste à vérifier les passeports des personnes à l’immigration. Le contrôle d’immigration (AV) compare les passeports à une liste de criminels connus : s’il y a correspondance, l’entrée est bloquée.

Cela paraît efficace, n’est‑ce pas ?

Mais si quelqu’un de parfaitement inconnu et apparemment inoffensif tente d’entrer ? Le contrôle d’immigration le laissera passer. Si cette personne est en réalité un voleur professionnel entraîné à contourner les contrôles de base, l’aéroport se retrouve avec une menace indétectée à l’intérieur.

C’est là qu’intervient l’EDR.

Dans cette analogie, l’EDR correspond aux agents de sécurité présents à l’intérieur de l’aéroport (le terminal). Ces agents surveillent en permanence les caméras et les détecteurs de mouvement (le terminal). Comparés au contrôle d’immigration (AV), les agents (EDR) renforcent la protection grâce à la vidéosurveillance et aux capteurs. Même si quelqu’un échappe au contrôle d’immigration, les agents surveilleront ses actions, par exemple :
- Se promène‑t‑il près de zones restreintes ?
- Son comportement est‑il suspect ?
- Laisse‑t‑il des sacs sans surveillance ?

Les agents peuvent aussi intervenir ou alerter la direction avec des détails complets sur l’incident.

L’antivirus peut détecter des menaces basiques, mais pour repérer des menaces avancées qui contournent les signatures, il faut un EDR. Contrairement aux AV basés principalement sur des signatures, l’EDR surveille et enregistre les comportements du terminal. Il fournit aussi une visibilité à l’échelle de l’organisation : si un fichier suspect est détecté sur un terminal, l’EDR le recherche sur tous les autres terminaux.

Examinons une attaque avancée étape par étape et comparons la réponse d’un AV et d’un EDR.

Scénario — Déroulement
Étape 1 : Un utilisateur reçoit un e‑mail de phishing contenant un document Word avec une macro malveillante (VBA)
Étape 2 : L’utilisateur télécharge le document et l’ouvre
Étape 3 : La macro malveillante s’exécute silencieusement et lance PowerShell
Étape 4 : La macro exécute une commande PowerShell obfusquée pour télécharger une charge utile secondaire sophistiquée
Étape 5 : La charge utile est injectée dans un svchost.exe légitime
Étape 6 : L’attaquant obtient un accès distant au système

Comparaison Antivirus vs EDR

- Étape 1
  - AV : Ne réagit pas si le fichier n’a pas de signature connue
  - EDR : Journalise le téléchargement du fichier et le surveille
- Étape 2
  - AV : Ne réagit pas à l’ouverture (winword.exe est légitime)
  - EDR : Enregistre l’exécution de winword.exe et continue la surveillance
- Étape 3
  - AV : Ne réagit pas si la macro n’a pas de signature connue
  - EDR : Détecte et signale l’exécution de la macro en raison de la relation parent‑enfant inhabituelle entre winword.exe et PowerShell.exe
- Étape 4
  - AV : En général, ne détecte pas les scripts PowerShell obfusqués
  - EDR : Signale l’exécution du script obfusqué
- Étape 5
  - AV : Ne signale pas l’injection en mémoire dans svchost.exe (ne surveille pas les injections mémoire)
  - EDR : Détecte l’injection de processus dans svchost.exe
- Étape 6
  - AV : Manque de visibilité au niveau réseau
  - EDR : Signale le comportement inattendu de svchost.exe établissant une connexion sortante

Action finale
- AV : Peut considérer l’activité comme propre
- EDR : Génère une alerte avec la chaîne d’attaque complète et permet à l’analyste d’agir depuis la console EDR

Remarque : certains antivirus modernes offrent une visibilité et des détections améliorées, mais l’EDR reste généralement en avance en apportant une détection et une réponse renforcées sur l’hôte.

## Comment fonctionne un EDR ?
Savez‑vous :

- Comment un EDR obtient‑il autant de visibilité sur les terminaux ?
- Comment détecte‑t‑il des menaces avancées ?
- Comment quelques clics peuvent‑ils éradiquer une menace sur un terminal ?

```text
 ┌───────────────┐   ┌───────────────┐   ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
 │   EDR AGENT   │   │   EDR AGENT   │   │   EDR AGENT   │   │   EDR AGENT   │   │   EDR AGENT   │
 │     (👁️)      │   │     (👁️)      │  │     (👁️)     │    │     (👁️)     │   │     (👁️)      │
 ├───────────────┤   └───────┬───────┘   ├───────────────┤   └───────┬───────┘   ├───────────────┤
          │                   │                   │                   │                   │
         │                   │                   │                   │                   │
         ▼                   ▼                   ▼                   ▼                   ▼
          \                  │                   │                  │                  /
           \                 │                   │                  │                 /
            \                │                   │                  │                /
             ▼               ▼                   ▼                  ▼               ▼
                                 ┌───────────────────────────────┐
                                 │          EDR CONSOLE          │
                                 ├───────────────────────────────┤
                                 │  (👁️)  🔔    ☰  • • •   📊  │
                                 │                             │
                                 └───────────────┬───────────────┘
 ```

Agents
On intègre plusieurs terminaux à un EDR et on les gère depuis une console centralisée. 
Des agents EDR (ou capteurs) sont déployés sur ces terminaux : ce sont les yeux et les oreilles de l’EDR. 
Ils surveillent localement toutes les activités et envoient des informations détaillées en temps réel à la console centrale. 
Les agents peuvent aussi effectuer des détections basiques (signatures et comportements) et signaler ces événements à la console, qui déclenche des alertes.

Console EDR
Les données détaillées envoyées par les agents sont corrélées et analysées dans la console via des règles, de la logique et des algorithmes de machine learning. Les renseignements sur les menaces sont croisés avec les données collectées. L’EDR agit comme un cerveau qui relie les éléments pour former une détection (alerte). La console fournit un tableau de bord donnant une vue d’ensemble des détections et du statut des terminaux.

Que se passe‑t‑il après une détection ?
Lorsqu’une détection apparaît, l’analyste SOC doit la reconnaître et la prioriser : l’EDR assigne une sévérité (Critique, Élevée, Moyenne, Faible, Informatif). L’alerte la plus sévère est traitée en priorité. En cliquant sur une alerte, l’analyste accède à tous les détails (fichiers exécutés, processus, connexions réseau, modifications du registre, etc.). Avec ces éléments, l’analyste détermine si l’alerte est un faux positif ou un vrai incident. En cas de vrai incident, il peut exécuter des actions depuis la console (isoler l’hôte, terminer un processus, mettre en quarantaine un fichier, connexion distante, etc.).

EDR et autres outils
Un EDR standalone fournit beaucoup d’informations, mais il s’intègre dans un écosystème de sécurité plus large : pare‑feux, DLP, passerelles de messagerie, IAM, SIEM, etc. Ces solutions sont souvent corrélées dans un SIEM pour centraliser les enquêtes et automatiser les réponses ; nous aborderons le SIEM dans les prochaines sections.

## Télémétrie EDR

Qu’est‑ce que la télémétrie ?
La télémétrie est l’ensemble des données collectées par les agents EDR sur un terminal et envoyées à la console centrale : c’est la « boîte noire » du poste, contenant tout le nécessaire pour la détection et l’investigation.
```text
┌───────────────┐   ┌───────────────┐   ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
 │   EDR AGENT   │   │   EDR AGENT   │   │   EDR AGENT   │   │   EDR AGENT   │   │   EDR AGENT   │
 │     (👁️)      │   │     (👁️)      │   │     (👁️)      │   │     (👁️)      │   │     (👁️)      │
 └───────────────┘   └───────────────┘   └───────────────┘   └───────────────┘   └───────────────┘
         │                   │                   │                   │                   │
         │                   │                   │                   │                   │
         ▼                   ▼                   ▼                   ▼                   ▼
          \                  │                   │                  │                  /
           \                 │                   │                  │                 /
    Process \                │              File Modified           │                / Network
    Executed \               ▼                   ▼                  ▼               /  Connection
              ▼       Command Executed                    Registry Modified        ▼
                                                                             Scheduled Task
                               ┌───────────────────────────────┐                 Created
                               │          EDR CONSOLE          │
                               ├───────────────────────────────┤
                               │  (👁️)  🔔    ☰  • • •   📊  │
                               │                               │
                               └───────────────────────────────┘
```
Télémétrie collectée (principales catégories)
- Exécutions et terminaisons de processus  
  - Historique des processus, relations parent‑enfant, processus suspects ou exécutables non habituels.  
- Connexions réseau  
  - Connexions sortantes/entrantes, ports utilisés, communications vers des C2, mouvements latéraux, exfiltration.  
- Activité en ligne de commande  
  - Commandes CMD/PowerShell/terminal (scripts obfusqués, commandes post‑exploitation).  
- Modifications de fichiers et dossiers  
  - Créations, écritures, suppressions, déplacement de fichiers (staging, déploiement de charges, chiffrement).  
- Modifications du registre (Windows)  
  - Clés/valeurs créées, modifiées ou supprimées (persistence, configurations malveillantes).  
- Autres sources courantes  
  - Modules/driver chargés, hooks, handles ouverts, événements d’authentification, services installés, snapshots mémoire, captures de DLL chargées.

Pourquoi cette télémétrie est‑elle importante ?
- Corrélation : des actions isolées peuvent sembler bénignes ; leur corrélation révèle des chaînes d’attaque.  
- Détection avancée : permet la détection comportementale, l’identification d’anomalies et le repérage de malwares « sans fichier ».  
- Investigation : reconstruction de la chronologie, détermination de la cause racine et choix d’actions de remédiation appropriées.

## Détection et capacité de réponse

Détection
- Détection comportementale : observe le comportement complet d’un fichier/processus (ex. : winword.exe lançant PowerShell.exe est inhabituel et sera signalé).
- Détection d’anomalies : l’EDR apprend le comportement de référence des terminaux ; toute déviation est signalée (peut générer des faux positifs, mais le contexte aide l’analyste).
- Correspondance d’IOC : croise les activités avec des indicateurs de compromission connus fournis par les flux de renseignement (ex. : hash d’un exécutable associé à une attaque).
- Mappage MITRE ATT&CK : les activités signalées sont indexées selon la tactique et la technique MITRE (ex. : création d’une tâche planifiée → Tactic : Persistence, Technique : Scheduled Task/Job).
- Algorithmes de machine learning : modèles entraînés sur de larges jeux de données pour détecter des schémas complexes (utile contre les attaques sans fichier ou multi‑étapes).

Réponse
- Isolation de l’hôte : couper le terminal du réseau pour contenir la menace et prévenir la propagation latérale.
- Terminaison de processus : arrêter un processus malveillant quand l’isolation n’est pas souhaitable (à utiliser prudemment pour éviter les interruptions métier).
- Quarantaine : déplacer un fichier malveillant vers un emplacement isolé empêchant son exécution, pour examen ultérieur.
- Accès distant (RTR) : ouvrir une session shell distante pour actions personnalisées, exécution de scripts ou collecte d’informations quand les réponses natives sont insuffisantes.
- Collecte d’artefacts : extraire à distance des éléments pour forensique ou preuves légales (ex. : dump mémoire, journaux d’événements, contenus de dossiers spécifiques, ruches du registre).

Remarque : les capacités exactes varient selon les solutions EDR, mais l’objectif commun est d’accélérer la détection, fournir un contexte d’investigation riche et permettre des actions de remédiation efficaces depuis la console centrale.
