# Introduction

Bienvenue dans ce cours dédié au cœur opérationnel du SOC. 
Le SOC est la première ligne de défense d'une organisation, et comprendre comment y naviguer est essentiel pour tout analyste en cybersécurité.

## Objectifs pédagogiques

À la fin, vous serez capable de :

* Vous familiariser avec le concept d'alerte de sécurité au sein d'un SOC.
* Explorer les différents champs, statuts et classifications d'une alerte.
* Apprendre à effectuer le tri (*triage*) des alertes en tant qu'analyste L1.
* Vous exercer sur de vraies alertes et des flux de travail (*workflows*) réels du SOC.
* Vous préparer au simulateur SOC ainsi qu'à la certification SAL1.

## Événements & Alertes

Imaginez-vous en stage au sein d'un SOC. Vous êtes assis à côté de votre tuteur, un analyste L1 ou L2, les yeux rivés sur son écran. Devant vous, des centaines d'alertes apparaissent, changent de statut, puis finissent par disparaître du tableau de bord ou de la console de supervision.

En observant attentivement, vous remarquez une multitude d'alertes intitulées *"Email Marked as Phishing"* (E-mail signalé comme hameçonnage), quelques-unes baptisées *"Unusual Gmail Login Location"* (Connexion Gmail depuis un lieu inhabituel) et, tout en haut, une alerte beaucoup plus inquiétante dans une colonne rouge vif : *"Unapproved Mimikatz Usage"* (Utilisation non autorisée de Mimikatz).

Que signifient ces alertes ? Comment sont-elles générées et, surtout, que devons-nous en faire ? C'est précisément ce que nous allons découvrir !

## Propriétés d'une alerte

Pour traiter efficacement une alerte, un analyste doit d'abord savoir décoder les informations qu'elle contient. Chaque alerte générée par nos outils de détection (comme un SIEM ou un EDR) possède des propriétés standardisées qui permettent de l'identifier, de l'évaluer et de suivre sa résolution.

Voici la structure type des propriétés d'une alerte de sécurité :

| № | Propriété | Description | Exemples |
| --- | --- | --- | --- |
| **1** | **Heure de l'alerte**<br><br>*(Alert Time)* | Indique le moment où l'alerte a été créée. Elle se déclenche généralement quelques minutes après l'événement réel. | • Heure de l'alerte : 21 mars, 15h35<br><br>• Heure de l'événement : 21 mars, 15h32 |
| **2** | **Nom de l'alerte**<br><br>*(Alert Name)* | Fournit un résumé succinct de ce qui s'est passé, basé sur le nom de la règle de détection qui s'est déclenchée. | • Connexion depuis un lieu inhabituel<br><br>• E-mail signalé comme Phishing<br><br>• Attaque par force brute RDP Windows<br><br>• Exfiltration potentielle de données |
| **3** | **Sévérité de l'alerte**<br><br>*(Alert Severity)* | Définit le niveau d'urgence. Elle est initialement fixée par les ingénieurs de détection, mais l'analyste peut la modifier si l'investigation le justifie. | • (🟢) Faible / Informationnelle<br><br>• (🟡) Moyenne / Modérée<br><br>• (🟠) Haute / Sévère<br><br>• (🔴) Critique / Urgente |
| **4** | **Statut de l'alerte**<br><br>*(Alert Status)* | Indique si quelqu'un est déjà en train de traiter l'alerte ou si l'analyse est terminée. | • (🆕) Nouvelle / Non attribuée<br><br>• (🔄) En cours / En attente<br><br>• (✅) Clôturée / Résolue<br><br>*(Et d'autres statuts personnalisés selon le SOC)* |
| **5** | **Verdict de l'alerte**<br><br>*(Alert Verdict)* | Également appelé classification, il précise si l'alerte correspond à une menace réelle ou à du bruit de fond. | • (🔴) Vrai Positif (Menace réelle)<br><br>• (🟢) Faux Positif (Fausse alerte)<br><br>*(Et souvent d'autres verdicts personnalisés)* |
| **6** | **Responsable**<br><br>*(Alert Assignee)* | Indique l'analyste auquel l'alerte a été attribuée (ou qui s'est auto-attribué l'alerte). Le responsable prend la charge de l'investigation. | • Parfois appelé *Alert Owner* (propriétaire de l'alerte). |
| **7** | **Description**<br><br>*(Alert Description)* | Explique le contexte de l'alerte. Elle se compose généralement de trois sections : la logique de la règle, pourquoi cette activité est suspecte, et comment la traiter. | • Logique de la règle de détection.<br><br>• Pourquoi cette activité peut indiquer une attaque.<br><br>• (Optionnel) Guide de tri de l'alerte. |
| **8** | **Champs de l'alerte**<br><br>*(Alert Fields)* | Fournit les valeurs techniques précises qui ont déclenché la règle, ainsi que les commentaires des analystes. | • Nom de l'hôte affecté (*Hostname*)<br><br>• Ligne de commande exécutée<br><br>*(Et bien d'autres selon le type de détection)* |

## Choisir la bonne alerte

Chaque équipe SOC définit ses propres règles de priorité et les automatise généralement en configurant une logique de tri directement dans le SIEM ou l'EDR. Voici l'approche standard, la plus simple et la plus couramment utilisée dans l'industrie :

1. **Filtrer les alertes**
Assurez-vous de ne pas prendre une alerte sur laquelle un autre analyste a déjà travaillé ou qui est déjà en cours d'investigation par l'un de vos coéquipiers. Vous ne devez sélectionner que des alertes *nouvelles*, non résolues et qui n'ont pas encore été consultées.
2. **Trier par sévérité**
Commencez toujours par les alertes critiques, puis passez aux alertes hautes, moyennes, et enfin faibles. Les ingénieurs de détection conçoivent les règles pour que les alertes critiques aient une probabilité beaucoup plus élevée de représenter une menace majeure réelle, avec un impact potentiellement dévastateur pour l'entreprise.
3. **Trier par ancienneté**
À niveau de sévérité égal, commencez par les alertes les plus anciennes pour finir par les plus récentes. La logique est simple : si deux alertes cachent une véritable intrusion, l'attaquant de l'alerte la plus ancienne est probablement déjà en train de piller vos données, tandis que le "nouveau venu" commence à peine sa phase de reconnaissance.

## Tri des alertes (*Alert Triage*)

### Actions initiales

Ces premières étapes permettent de formaliser votre prise en charge de l'alerte. Cela évite que plusieurs analystes travaillent sur le même incident et vous assure d'avoir tous les éléments en main avant de plonger dans l'analyse technique.

* **Comment faire ?** Attribuez-vous l'alerte, passez son statut à *En cours* (*In Progress*), puis familiarisez-vous avec ses détails (nom, description et indicateurs clés).

### Investigation

C'est l'étape la plus complexe du processus. Elle vous demande de mobiliser vos compétences techniques et votre expérience pour disséquer l'activité suspecte et analyser sa légitimité à travers les journaux (*logs*) du SIEM ou de l'EDR. Pour guider les analystes L1, de nombreuses équipes formalisent des **Workbooks** (ou *playbooks* / *runbooks*). Il s'agit de guides pas-à-pas pour enquêter sur une catégorie d'alerte spécifique. Si vous n'avez pas de workbook sous la main, voici les recommandations fondamentales :

* **Identifier la cible :** Qui ou qu'est-ce qui est menacé ? (L'utilisateur, le nom de la machine, le service cloud, le segment réseau ou le site web impacté).
* **Analyser l'action :** Quelle est la nature de l'activité signalée ? (S'agit-il d'une connexion suspecte, d'un comportement de logiciel malveillant ou d'une tentative d'hameçonnage ?).
* **Étudier le contexte :** Examinez les événements environnants. Cherchez des actions suspectes survenues juste avant ou juste après le déclenchement de l'alerte.
* **Enrichir les données :** Utilisez les plateformes de *Threat Intelligence* (renseignement sur les menaces) ou toute autre ressource disponible pour valider vos hypothèses.

### Actions finales

Vos conclusions à ce stade vont déterminer si vous venez de stopper une cyberattaque ou si vous êtes passé à côté.  

* **Le verdict :** Décidez si l'alerte est malveillante (**Vrai Positif**) ou s'il s'agit d'un comportement légitime (**Faux Positif**).
* **La clôture :** Rédigez un commentaire détaillé expliquant votre démarche d'analyse et les raisons de votre verdict. Retournez ensuite sur le tableau de bord et passez le statut de l'alerte à **Clôturée** (*Closed*).

 
 
