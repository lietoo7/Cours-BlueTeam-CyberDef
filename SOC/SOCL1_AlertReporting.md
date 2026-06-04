# INTRODUCTION

Pendant ou après le tri d'une alerte, un analyste L1 peut éprouver des doutes sur la manière de la classifier. Cela nécessite parfois le soutien d'un analyste senior ou des informations complémentaires de la part du propriétaire du système affecté. De plus, le L1 peut être confronté à de véritables cyberattaques et à des compromissions qui exigent une attention immédiate et des mesures de remédiation.

Ce module traite de ces situations spécifiques en introduisant trois concepts clés : **le rapport d'alerte (*alert reporting*)**, **l'escalade (*escalation*)** et **la communication**.

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :

* Comprendre la nécessité du rapport d'alerte et de l'escalade au sein d'un SOC.
* Apprendre à rédiger correctement des commentaires d'alerte ou des rapports d'incident.
* Explorer les méthodes d'escalade et les meilleures pratiques de communication.
* Appliquer ces connaissances pour trier des alertes dans un environnement simulé.
* Gagner en confiance sur le simulateur SOC et pour l'obtention de la certification SAL1.

---

## Le cycle de l'alerte (*Alert Funnel*)

Dans le module précédent, vous avez appris à classifier et à trier les alertes. Mais vous vous demandez peut-être ce qu'il se passe ensuite. Comment votre travail de tri aide-t-il concrètement à neutraliser les menaces et à stopper les intrusions ? C'est ce que nous allons voir, mais rappelons d'abord le parcours type d'une alerte :

```text
  [ Alertes Brutes ] (SIEM / EDR)
          │
          ▼
   ┌─────────────┐
   │ Analyste L1 │ ──► Faux Positifs / Traitement standard (Clôture)
   └─────────────┘
          │
          ▼  (Escalade : Rapport d'alerte)
   ┌─────────────┐
   │ Analyste L2 │ ──► Remédiation des compromissions & Enquêtes complexes
   └─────────────┘

```

1. **La réception :** Les analystes L1 reçoivent les alertes via un SIEM, un EDR ou une plateforme de gestion des tickets.
2. **Le premier filtre :** La majorité des alertes sont clôturées en tant que *Faux Positifs* ou sont entièrement gérées au niveau L1.
3. **L'aiguillage :** Les alertes complexes et menaçantes sont transmises au niveau L2, qui se charge de remédier à la plupart des failles.

Pour transférer efficacement ces alertes aux niveaux supérieurs, vous devez maîtriser trois notions fondamentales :

* **Le rapport d'alerte (*Alert Reporting*) :** Avant de clôturer une alerte ou de la transférer au L2, vous devez parfois la consigner. Selon les standards de votre équipe et la sévérité de l'événement, un simple commentaire peut ne pas suffire. On attendra alors de vous une documentation détaillée de votre investigation, incluant toutes les preuves pertinentes. Cela est crucial pour les *Vrais Positifs* qui nécessitent une escalade.
* **L'escalade d'alerte (*Alert Escalation*) :** Si l'alerte qualifiée de *Vrai Positif* requiert des mesures correctives immédiates ou une investigation plus approfondie, vous devez l'escalader à un analyste L2 en suivant les procédures établies. C'est ici que votre rapport prend tout son sens : le L2 l'utilisera pour obtenir le contexte initial instantanément, lui évitant ainsi de reprendre l'analyse à zéro.
* **La communication :** Vous serez également amené à communiquer avec d'autres départements pendant ou après votre analyse. Par exemple, contacter l'équipe administrative IT pour vérifier s'ils ont bien accordé des privilèges spécifiques à un utilisateur, ou solliciter les RH pour obtenir des détails sur une nouvelle recrue.

---

## Guide de rédaction du rapport

Il est essentiel de comprendre pourquoi on demande à un analyste L1 de rédiger des rapports au lieu de simplement cocher la case *Vrai* ou *Faux Positif*. Cette tâche ne doit jamais être sous-estimée, car elle répond à plusieurs objectifs stratégiques :

| Objectif du rapport d'alerte | Explication |
| --- | --- |
| **Fournir du contexte pour l'escalade** | Un rapport bien structuré fait gagner un temps précieux aux analystes L2 et leur permet de comprendre immédiatement la situation. |
| **Conserver un historique des découvertes** | Les journaux bruts (*logs*) du SIEM sont souvent conservés entre 3 et 12 months, tandis que l'historique des alertes est gardé indéfiniment. Il est donc préférable de centraliser tout le contexte directement dans le ticket d'alerte. |
| **Améliorer vos compétences d'analyse** | *« Ce qui se conçoit bien s'énonce clairement »*. Si vous ne parvenez pas à expliquer une alerte simplement, c'est que vous ne l'avez pas totalement comprise. Rédiger des rapports est un excellent exercice pour faire progresser un analyste L1. |

### La méthode des 5 W (Qui, Quoi, Quand, Où, Pourquoi)

Mettez-vous à la place d'un analyste L2, d'un membre de l'équipe DFIR (Réponse aux incidents) ou d'un administrateur système qui doit traiter votre alerte. Quelles informations aimeriez-vous y trouver ? Nous vous recommandons d'adopter la méthode des **5 W** :

* **Who (Qui) :** Quel utilisateur s'est connecté, a exécuté la commande ou a téléchargé le fichier ?
* **What (Quoi) :** Quelle action exacte ou séquence d'événements a été réalisée ?
* **When (Quand) :** À quel moment précis l'activité suspecte a-t-elle commencé et s'est-elle terminée ?
* **Where (Où) :** Quel équipement, quelle adresse IP ou quel site web est impliqué dans l'alerte ?
* **Why (Pourquoi) :** Le "W" le plus important. Quelle est la logique sous-jacente qui justifie votre verdict final ?

---

## Escalade et support

Une fois votre verdict posé et votre rapport rédigé, vous devez décider s'il convient d'escalader l'alerte au niveau L2. Bien que les critères varient selon les entreprises, vous devez généralement escalader l'alerte si :

* L'alerte est l'indicateur d'une cyberattaque majeure nécessitant une expertise approfondie ou une intervention DFIR.
* Des mesures de remédiation immédiates sont requises (suppression de malware, isolation d'une machine du réseau, réinitialisation de mot de passe).
* Une communication externe est nécessaire (avec des clients, des partenaires, la direction ou les autorités judiciaires).
* Vous ne comprenez pas l'alerte et avez besoin de l'aide d'un analyste plus expérimenté.

### Processus d'escalade

Dans la plupart des SOC, le processus est très direct :

```text
┌────────────────────────┐      ┌──────────────────────┐      ┌─────────────────────┐
│ Tri & Rapport par le L1 │ ──►  │ Réassignation au L2  │ ──►  │ Notification / Ping │
│  (Statut: In Progress)  │      │   (Sur le shift)     │      │   (Chat ou oral)    │
└────────────────────────┘      └──────────────────────┘      └─────────────────────┘

```

Certaines structures formalisent toutefois ce processus via des formulaires de demande d'escalade contenant de nombreux champs obligatoires.

Peu importe l'organisation interne, le L2 recevra votre ticket, consultera votre rapport et reviendra vers vous en cas de doute. Une fois le contexte assimilé, le L2 approfondira l'analyse, validera s'il s'agit bien d'un *Vrai Positif*, fera le lien avec les autres départements et, pour les incidents majeurs, déclenchera le processus officiel de **Réponse aux Incidents** (*Incident Response*).

> 💡 **Solliciter le support L2**
> Il est tout à fait normal pour un analyste L1 de demander de l'aide si un élément reste flou. Surtout durant vos premiers mois, il est toujours préférable d'échanger sur une alerte et de clarifier les procédures du SOC plutôt que de clôturer aveuglément un incident que vous ne comprenez pas.

### Flux de travail sur le tableau de bord SOC

1. Passez l'alerte au statut **In Progress** et menez votre investigation.
2. Rédigez votre rapport d'alerte et définissez votre verdict (ex: *True Positive*).
3. Si l'escalade est nécessaire, assignez l'alerte à l'analyste L2 de garde.
4. Le L2 reçoit une notification et reprend l'enquête en s'appuyant sur votre rapport.

---

## Cas pratiques de communication

En théorie, l'escalade et le rapportage semblent simples et logiques. Cependant, la réalité du terrain réserve son lot d'imprévus. Vous devez être prêt à réagir face à des situations critiques. Si votre SOC ne dispose pas d'une procédure dédiée à la **Communication de Crise**, voici comment gérer les scénarios les plus fréquents :

* **Scénario 1 : L'alerte est critique et urgente, mais le L2 ne répond pas depuis 30 minutes.**
* *Action :* Assurez-vous de savoir où se trouve la liste des contacts d'urgence. Tentez d'appeler le L2 par téléphone, puis le L3, et enfin votre responsable de compte ou manager de SOC.


* **Scénario 2 : Une alerte indique le compromis d'un compte Slack ou Teams, vous devez valider la connexion avec l'utilisateur impacté.**
* *Action :* Ne contactez surtout pas l'utilisateur via la messagerie compromise. Utilisez un canal alternatif, comme un appel téléphonique direct.


* **Scénario 3 : Vous subissez une vague massive d'alertes simultanées, dont plusieurs sont critiques.**
* *Action :* Priorisez les alertes en suivant la logique standard (Sévérité -> Ancienneté), mais informez immédiatement le L2 d'astreinte de la situation d'engorgement.


* **Scénario 4 : Après quelques jours, vous réalisez que vous avez mal classifié une alerte et qu'une action malveillante a probablement été manquée.**
* *Action :* Contactez immédiatement votre L2 pour lui faire part de vos doutes. Les attaquants peuvent rester silencieux pendant des semaines avant de déclencher l'impact d'une attaque.


* **Scénario 5 : Vous ne pouvez pas terminer le tri d'une alerte car les logs du SIEM sont mal parsés ou corrompus.**
* *Action :* Ne passez pas l'alerte sous silence. Analysez tout ce qui est techniquement visible et signalez le problème de parsing au L2 de garde ou à l'ingénieur SOC chargé de la maintenance des flux.
