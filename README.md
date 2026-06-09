## INTRODUCTION
**la sécurité défensive**  s'articule autour de trois missions principales :

1. **Prévenir** les intrusions avant qu'elles ne se produisent.
2. **Détecter** les intrusions lorsqu'elles surviennent
3. et y **répondre** de manière appropriée.

Les *Blue Teams* constituent le cœur opérationnel de la sécurité défensive.

La sécurité défensive regroupe un large éventail de tâches indispensables au quotidien, notamment :

* **La sensibilisation des utilisateurs à la cybersécurité :** Former les collaborateurs aux bonnes pratiques de sécurité permet de dresser un rempart efficace contre les attaques ciblant leurs propres systèmes.
* **La cartographie et la gestion des actifs :** Il est impératif de connaître précisément les systèmes et les équipements présents dans l'entreprise pour pouvoir les gérer et les protéger adéquatement.
* **La mise à jour et le correctif des systèmes (*patching*) :** Veiller à ce que les ordinateurs, serveurs et équipements réseau soient correctement mis à jour permet de les prémunir contre les vulnérabilités (failles) connues.
* **Le déploiement d'équipements de sécurité préventive :** Les pare-feux (*firewalls*) et les systèmes de prévention des intrusions (IPS) sont des composants critiques de la sécurité préventive. Le pare-feu contrôle le trafic réseau entrant et sortant du système ou du réseau. L'IPS, quant à lui, bloque automatiquement tout trafic réseau correspondant à des règles prédéfinies ou à des signatures d'attaques connues.
* **La mise en place d'outils de journalisation (*logging*) et de supervision :** Une collecte adéquate des journaux et une surveillance réseau continue sont essentielles pour détecter les activités malveillantes et les intrusions. Si un nouvel équipement non autorisé apparaît sur notre réseau, nous devons être en mesure de le détecter immédiatement.

La sécurité défensive est un domaine extrêmement vaste. En plus des missions de premier niveau listées ci-dessus, nous aborderons en détail les disciplines spécialisées suivantes :

* **Le SOC (*Security Operations Center*) :** Le centre de pilotage et de surveillance continue de la sécurité.
* **La *Threat Intelligence* :** Le renseignement sur les cybermenaces pour anticiper les techniques des attaquants.
* **Le DFIR (*Digital Forensics and Incident Response*) :** L'analyse forensique numérique et la réponse aux incidents pour enquêter sur les attaques et les contenir.
 
## SOMMAIRE
### A) Cours sur le SOC
A.I) Les fondamentaux du SOC
Découvrez les compétences et outils d'un analyste SOC pour trier, classifier et escalader les alertes.
 - 1 [Le SIEM](SOC/SIEM.md) , [Le SOC](SOC/SOCIntroduction.md)
 - 2 [SOCL1 AlertTriage](SOC/SOCL1_AlertTriage.md)
 - 3 [SOCL1 AlertReporting](SOC/SOCL1_AlertReporting.md)
 - 4 [SOCL1 Workbooks](SOC/SOCL1_workbooks.md)
 - 5 [SOCL1 Metrics](SOC/SOCL1_metrics.md)
 - 6 [l'EDR](SOC/EDR_Intro.md)
 - 7 [Le SOAR (Security Orchestration, Automation, and Response)](SOC/SOAR.md)

A.II) Les Solutions pour le SOC
La compréhension des solutions de sécurité est essentielle pour les analystes SOC.
Ce module aborde les solutions SIEM, EDR, d'IDS/IPS et SOAR.
* Plateforme SIEM
 - 1 [Splunk](SOC/Splunk.md)
 - 2 [ELK stack](SOC/ELKstack.md)
 - 3 [MSsentinel]()
* Système de détection des intrusions (IDS/IPS)
 - 1 [Suricata]()
 - 2 [Snort]()
 - 3 [Zeek]()
* Gestion des journaux (Log Management)
 - 1 [Graylog]()
 - 2 [Datadog]()
 - 3 [New Relic]()
 - 4 [Splunk]()
* Le all-in-one
 - [Security Onion](https://github.com/Security-Onion-Solutions/securityonion)

A.III) CyberDefense Frameworks <br>
Comment les cadres de défense, tels que la Pyramid of Pain , la Cyber ​​Kill Chain ou encore MITRE, vous aident à comprendre les comportements adverses et à renforcer la détection, le tri et la réponse aux alertes.

 - 1 [Pyramid of Pain](SOC/POP.md)
 - 2 [Cyber KILLChain](SOC/CyberKillChain.md)
 - 3 [Unified KILLChain](SOC/UnifiedKillChain.md)
 - 4 [MITRE](SOC/MITRE.md)
