# Introduction

Comme pour n'importe quel autre département, l'efficacité d'une équipe SOC peut être mesurée à l'aide de différents indicateurs et métriques. Ce module explore les approches d'évaluation les plus courantes, telles que le MTTD et le MTTR, et décrit à la fois les méthodes pour améliorer ces indicateurs et les conséquences potentielles si on choisit de les ignorer.

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :

* Découvrir les concepts de SLA, MTTD, MTTA et MTTR.
* Comprendre l'importance du taux de Faux Positifs (*False Positive rate*).
* Apprendre pourquoi et comment améliorer ces métriques en tant qu'analyste L1.
* Vous exercer à la gestion des indicateurs de performance d'une équipe SOC.

---

## Métriques fondamentales (*Core Metrics*)

Pour commencer, rappelons l'objectif principal d'un SOC : protéger la confidentialité, l'intégrité et la disponibilité des actifs numériques de l'organisation. L'équipe du SOC remplit cette mission en développant, recevant et triant des alertes. Dans ce processus, le rôle de l'analyste L1 est de remonter de manière fiable les *Vrais Positifs* au niveau supérieur (le L2).

Cette dynamique nous amène aux quatre premières métriques clés :

| Métrique | Formule | Ce qu'elle mesure |
| --- | --- | --- |
| **Volume d'alertes**<br><br>*(Alerts Count - AC)* | $AC = \text{Nombre total d'alertes reçues}$ | La charge de travail globale des analystes du SOC. |
| **Taux de Faux Positifs**<br><br>*(False Positive Rate - FPR)* | $FPR = \frac{\text{Faux Positifs}}{\text{Total des alertes}}$ | Le niveau de bruit de fond au sein des alertes. |
| **Taux d'escalade**<br><br>*(Alert Escalation Rate - AER)* | $AER = \frac{\text{Alertes escaladées}}{\text{Total des alertes}}$ | Le niveau d'expérience et d'autonomie des analystes L1. |
| **Taux de détection des menaces**<br><br>*(Threat Detection Rate - TDR)* | $TDR = \frac{\text{Menaces détectées}}{\text{Total des menaces réelles}}$ | La fiabilité globale de l'équipe SOC. |

### Volume d'alertes (*Alerts Count*)

*Une loupe qui cherche des aiguilles dans un océan de Faux Positifs.*

Imaginez que vous preniez votre service et que vous découvriez 80 alertes non résolues dans la file d'attente. C'est une situation oppressante, propice aux erreurs, où une menace réelle peut facilement se dissimuler derrière ce flux incessant de bruit.

À l'inverse, imaginez une semaine entière sans la moindre alerte. Cela semble idéal à première vue, mais c'est en réalité très inquiétant : un volume trop faible indique souvent un dysfonctionnement du SIEM ou un manque cruel de visibilité, synonyme de compromissions non détectées. La valeur idéale dépend de la taille de l'entreprise, mais on considère généralement qu'un volume de **5 à 30 alertes par jour et par analyste L1** constitue un bon équilibre.

### Taux de Faux Positifs (*False Positive Rate*)

Si 75 des 80 alertes reçues (94 %) s'avèrent être des Faux Positifs (du bruit système ou de l'activité informatique légitime), c'est un très mauvais signal pour votre équipe. Face à un tel bruit visuel, les analystes ont tendance à baisser leur vigilance. Ils finissent par traiter chaque nouvelle alerte comme un "simple spam de plus", risquant de passer à côté d'une véritable attaque.

Un taux de Faux Positifs de 0 % est un idéal impossible à atteindre, mais un taux **égal ou supérieur à 80 % constitue un problème sérieux**. On le corrige par un travail de nettoyage des outils et des règles de détection, un processus appelé la *"Remédiation des Faux Positifs"*.

### Taux d'escalade des alertes (*Alert Escalation Rate*)

*Une loupe focalisée sur une seule menace, tandis que d'autres restent invisibles par manque d'expérience ou à cause d'un SIEM mal configuré.*

Les analystes L2 comptent sur le L1 pour filtrer le bruit et n'escalader que les alertes pertinentes qui nécessitent une action. En même temps, en tant que L1, vous devez éviter l'excès de confiance et ne pas clore seul des alertes que vous ne comprenez pas totalement sans solliciter un profil senior.

Le taux d'escalade permet d'évaluer l'autonomie des analystes L1 et la fréquence à laquelle ils passent la main. On cible généralement un taux d'escalade **inférieur à 50 %, l'idéal étant de se situer sous la barre des 20 %**.

### Taux de détection des menaces (*Threat Detection Rate*)

Imaginons que sur six attaques survenues au cours de l'année, votre SOC en ait détecté et bloqué quatre. La cinquième a été manquée à cause d'une règle de détection défaillante, et la sixième parce qu'un analyste L1 a classé à tort l'intrusion en Faux Positif.

Le résultat est le suivant : $TDR = \frac{4}{6} = 67\%$. C'est un score critique et insuffisant. Le taux de détection des menaces **doit toujours être de 100 %**, car chaque menace manquée peut avoir des conséquences dévastatrices, comme le déploiement d'un rançongiciel (*ransomware*) ou l'exfiltration massive de données.

---

## Métriques de traitement (*Triage Metrics*)

Générer une alerte ne suffit pas à stopper une intrusion. Il est capital de la réceptionner, de la trier et d'y répondre à temps, avant que les attaquants n'atteignent leurs objectifs.

Les exigences de rapidité pour la détection et la remédiation sont formalisées dans un **SLA** (*Service Level Agreement* ou Accord de Niveau de Service). Il s'agit d'un contrat d'engagement signé entre l'équipe SOC et la direction de l'entreprise (ou entre un prestataire de SOC managé [MSSP] et ses clients).

Ce document impose une détection rapide (mesurée par le **MTTD**), une prise en compte rapide de l'alerte par le L1 (mesurée par le **MTTA**) et enfin, une neutralisation immédiate de la menace (mesurée par le **MTTR**) :

```text
       [ Début de l'Attaque ]
                 │
                 ▼  ◄─────── MTTD (Temps moyen de détection)
       [ Alerte Générée ]
                 │
                 ▼  ◄─────── MTTA (Temps moyen de prise en compte)
       [ Début du Tri L1 ]
                 │
                 ▼  ◄─────── MTTR (Temps moyen de réponse)
    [ Menace Contenue / Neutralisée ]

```

### Tableau de référence des SLAs courants :

> ⚠️ *Note : Les définitions ou formules peuvent varier d'un SOC à l'autre selon leurs priorités d'analyse. Pour les exercices, basez-vous strictement sur ce tableau standard :*

| Métrique | SLA Courant | Description |
| --- | --- | --- |
| **Disponibilité du SOC** | 24/7 | Horaires d'ouverture de la surveillance. Généralement en 8h-18h (5 jours/7) ou en mode continu (24/7/365). |
| **Mean Time to Detect (MTTD)** | 5 minutes | Temps moyen qui s'écoule entre le début de l'attaque et sa détection par les outils du SOC. |
| **Mean Time to Acknowledge (MTTA)** | 10 minutes | Temps moyen mis par un analyste L1 pour prendre en charge une nouvelle alerte et démarrer le tri. |
| **Mean Time to Respond (MTTR)** | 60 minutes | Temps moyen nécessaire au SOC pour appliquer les mesures correctives et stopper la propagation de la menace. |

---

## Améliorer les métriques

En tant qu'analyste L1, ces indicateurs vous concernent directement pour deux raisons. D'une part, ils garantissent l'efficacité collective du SOC face aux attaquants. D'autre part, ils servent souvent de base pour évaluer vos performances individuelles ; d'excellents résultats ouvrent la voie à une évolution de carrière vers un poste d'analyste L2.

Voici comment réagir et optimiser vos indicateurs face aux dérives les plus fréquentes :

### Guide d'optimisation des performances du SOC

| Problème constaté | Recommandations et actions correctives |
| --- | --- |
| Taux de Faux Positifs<br><br>supérieur à 80 % | Votre équipe subit trop de bruit de fond. <br><br><br>1. **Excluez les comportements légitimes** connus (comme les mises à jour logicielles de confiance) directement dans les règles de détection du SIEM ou de l'EDR.<br><br>2. **Automatisez le tri** des alertes les plus courantes et répétitives à l'aide d'un SOAR ou de scripts personnalisés. |
| MTTD (Détection)<br><br>supérieur à 30 minutes | Le SOC détecte les menaces avec un retard critique.<br><br><br>1. **Sollicitez les ingénieurs SOC** pour augmenter la fréquence d'exécution et optimiser les performances des règles de détection.<br><br>2. **Vérifiez la chaîne de collecte** afin de vous assurer que les logs remontent bien dans le SIEM en temps réel, sans latence technique. |
| MTTA (Prise en compte)<br><br>supérieur à 30 minutes | Les analystes mettent trop de temps à ouvrir les tickets d'alerte.<br><br><br>1. **Mettez en place des alertes visuelles ou sonores** en temps réel dès qu'une nouvelle alerte arrive dans la file d'attente.<br><br>2. **Équilibrez la charge de travail** en répartissant équitablement les alertes de la file d'attente entre tous les analystes présents sur le shift. |
| MTTR (Réponse)<br><br>supérieur à 4 heures | Le SOC ne parvient pas à contenir la faille à temps.<br><br><br>1. **En tant que L1, optimisez votre vitesse d'escalade** vers le niveau L2 dès qu'une menace réelle est confirmée.<br><br>2. **Assurez-vous que l'équipe dispose de playbooks documentés** et clairs pour chaque scénario d'attaque, afin de ne pas perdre de temps lors de la remédiation. |
