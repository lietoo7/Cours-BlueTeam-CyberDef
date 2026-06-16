## Chapitre 1 : Introduction à l'Écosystème DFIR

### 1.1 Définitions Clés : Informatique Légale vs Réponse aux Incidents

Le DFIR engobe deux disciplines complémentaires mais distinctes, souvent confondues dans la pratique opérationnelle.

#### **Informatique Légale (Digital Forensics)**

L'informatique légale est la science de l'acquisition, de la préservation et de l'analyse des preuves numériques dans un cadre où l'intégrité scientifique et la traçabilité légale sont déterminantes. Elle s'inscrit dans un processus judiciaire ou réglementaire où chaque étape est documentée et potentiellement contestable en tribunal.

**Caractéristiques clés :**
- Respect strict de la chaîne de custodie (*Chain of Custody*)
- Immuabilité des preuves
- Reproductibilité de l'analyse
- Admissibilité en cour

**Contextes d'application :**
- Investigations judiciaires (cybercriminalité, fraude)
- Enquêtes réglementaires (CNIL, ANSSI, autorités sectorielles)
- Contentieux civil ou pénal
- Conformité post-incident (RGPD, NIS2)

#### **Réponse aux Incidents (Incident Response)**

La réponse aux incidents est une discipline orientée actions immédiates visant à détecter, contenir et éliminer une menace active. Elle privilégie la rapidité et l'efficacité opérationnelle à court terme, sans nécessairement maintenir les standards de preuve légale.

**Caractéristiques clés :**
- Réactivité et pragmatisme
- Priorité au confinement de la menace
- Documentation secondaire (rapports d'impact)
- Récupération et continuité métier

**Contextes d'application :**
- Cybersécurité d'entreprise (SOC, équipes de sécurité)
- Incidents de sécurité internes
- Gestion de crises informatiques
- Triage rapide et escalade

#### **Tension opérationnelle et Hybridation**

Dans la réalité du terrain, ces deux disciplines doivent coexister. Une investigation commence souvent par une réponse tactique immédiate (isoler le système, arrêter l'attaque), puis doit évoluer vers une démarche légale si des poursuites sont envisagées ou si des obligations réglementaires s'appliquent.

> **Note du terrain** : Beaucoup d'incidents d'entreprise commencent sans intention légale puis découvrent une fraude ou un vol de données qui exige rétrospectivement une approche forensique. Il est prudent d'appliquer les standards forensiques dès le départ, même en cas de doute sur le caractère judiciaire de l'incident.

---

### Les deux piliers du DFIR

```
                   ┌───────────────────────────────────────┐
                   │                 DFIR                  │
                   └───────────────────┬───────────────────┘
                                       │
           ┌───────────────────────────┴───────────────────────────┐
           ▼                                                       ▼
┌──────────────────────────────────────┐               ┌──────────────────────────────────────┐
│       1. Digital Forensics           │               │       2. Incident Response           │
│       (Informatique légale)          │               │       (Réponse aux Incidents)        │
├──────────────────────────────────────┤               ├──────────────────────────────────────┤
│ Objectif : Comprendre et prouver.    │               │ Objectif : Contenir et éradiquer.    │
│                                      │               │                                      │
│ Consiste à collecter, préserver et   │               │ C'est la phase d'urgence. On identi- │
│ analyser les preuves numériques      │               │ fie l'attaque, on isole les machines │
│ (artefacts, logs, mémoire RAM) sans  │               │ compromises pour stopper l'hémorra-  │
│ les modifier, souvent en vue de      │               │ gie, et on restaure l'activité       │
│ poursuites judiciaires ou d'audits.  │               │ de l'entreprise de façon sécurisée.  │
└──────────────────────────────────────┘               └──────────────────────────────────────┘

```
---

### 1.2 Le Cycle de Vie d'un Incident selon le NIST et l'IETF

#### **Modèle NIST Cybersecurity Framework (SP 800-61)**

Le NIST propose un cycle d'incident en quatre phases, devenu le standard de facto en Amérique du Nord et largement adopté internationalement.

| Phase | Activités Clés | Acteurs | Durée Typique |
|-------|----------------|--------|--------------|
| **1. Préparation** | Outils, processus, formation, segmentation réseau | SOC, CISO, Ops | Continu |
| **2. Détection & Analyse** | Alertes, triage, qualification de l'incident, scope initial | SOC, Analystes | Minutes à heures |
| **3. Confinement, Éradication, Récupération** | Isolement du système, suppression du malware, rebuild | Ops, Forensics, Dev |Heures à jours |
| **4. Activités Post-Incident** | Debriefing, rapports, remédiation long-terme | Management, Compliance, Tech |Jours à semaines |

#### **Modèle RFC 2350 (IETF Incident Handling)**

L'IETF propose une approche plus granulaire, souvent utilisée par les CERT et les entités publiques.

- **Détection** : Identification d'un événement anormal
- **Triage** : Évaluation de l'impact et urgence
- **Analyse** : Compréhension du vecteur d'attaque
- **Contention** : Blocage de la propagation
- **Suppression** : Élimination de la cause racine
- **Récupération** : Restauration des services
- **Follow-up** : Apprentissage et correction

#### **Application Opérationnelle Hybride**

En pratique, l'équipe DFIR navigue entre ces deux modèles selon le contexte :

- Les phases de **préparation** et **détection** relèvent d'une approche proactive et continue (NIST).
- Les phases de **confinement et éradication** demandent une coordination entre IR et Forensics, où les standards légaux commencent à être appliqués.
- Le **post-incident** fusionne les rapports d'impact (IR) avec les conclusions légales (Forensics).

> **Alerte sécurité** : Ne pas confondre "fin de l'incident opérationnel" (menace contenue) avec "clôture légale" (investigation terminée). Les deux peuvent être décalées de plusieurs mois.

---

### 1.3 Le Profil des Attaquants Modernes

#### **Cybercriminalité Organisée**

- **Motivation** : Profit financier direct (ransomware, vol de données, fraude)
- **Caractéristiques** : Structure hiérarchisée, outils professionnels, ciblage basé sur ROI
- **Durée de présence** : Heures à jours (hit-and-run) ou mois (accès persistant pour monétisation progressive)
- **Indicateurs typiques** : Outils de pénétration éprouvés (Mimikatz, Cobalt Strike), communications chiffrées, exfiltration méthodique

**Exemple d'artefact à rechercher :**
- Présence de RDP bruteforcé, puis changement de mot de passe administrateur
- Téléchargement de scanners de réseau et outils d'énumération
- Accès aux bases de données critiques suivi d'une exfiltration massive

#### **Acteurs Parrainés par un État (APT)**

- **Motivation** : Cyberespionnage, sabotage, influence informationnelle
- **Caractéristiques** : Ressources illimitées, patients, sophistication technique extrême, logiques géopolitiques
- **Durée de présence** : Mois à années (persistance très longue)
- **Indicateurs typiques** : 0-day exploits, outils custom, camouflagein profond, infrastructure sophistiquée

**Exemple d'artefact à rechercher :**
- Traces d'accès très anciennes avec perturbation méthodique des logs
- Utilisation de vulnérabilités non divulguées (0-day)
- Présence de malwares custom et outils de reconnaissance peu connus

#### **Hacktivisme & Activisme Numérique**

- **Motivation** : Cause politique, idéologique ou protest
- **Caractéristiques** : Efficacité variable, outils publiquement disponibles, revendications publiques
- **Durée de présence** : Court terme, attaques éclairs
- **Indicateurs typiques** : Exploitation de vulnérabilités publiées, défacements web, outils de scan gratuits

**Exemple d'artefact à rechercher :**
- Injection SQL ou XSS sur services web
- Pages modifiées ou messages injectés
- Absence de mouvement latéral (pas de persistance)

#### **Menaces Internes (Insiders)**

- **Motivation** : Vengeance, appât du gain, idéologie
- **Caractéristiques** : Accès légitime initial, connaissance du réseau, difficiles à détecter
- **Durée de présence** : Variable, souvent longue
- **Indicateurs typiques** : Accès hors heures, activités impossibles (données accédées avant leur attribution), données sensibles exfiltrées sans alerte

> **Note du terrain** : Les insiders sont responsables de 34% des breaches selon le rapport Verizon 2024. Chercher les écarts entre les permissions et l'activité réelle.

---

### 1.4 Aspects Juridiques, Conformité et Déontologie

#### **Cadre Réglementaire Principal**

| Régulation | Champ d'Application | Obligations Clés |
|-----------|-------------------|------------------|
| **RGPD (EU 2016/679)** | Traitement de données personnelles | Notification de breach dans 72h, impact assessment, délégué DPO |
| **NIS2 (EU 2022/2555)** | Entités critiques (énergie, santé, finance) | Signalement d'incidents sérieux, audit annuel |
| **Loi Informatique et Libertés (France)** | Données personnelles (prolonge RGPD) | Respect des droits de l'individu, droit à l'oubli |
| **HIPAA (USA)** | Données de santé | Chiffrement des données, audit trail, notification |
| **PCI-DSS** | Données de cartes de crédit | Segmentation réseau, logs centralisés, scan régulier |

#### **Déontologie de l'Enquêteur DFIR**

**Impartialité & Objectivité** : Ne pas chercher à prouver une hypothèse préconçue, mais à établir les faits mesurables.

**Confidentialité** : Respecter les secrets professionnels et commerciaux du client. Non-divulgation d'informations sensibles sauf obligation légale.

**Intégrité de la Preuve** : Chaque modificationde système, chaque acquisition doit être documentée et justifiable.

**Compétence** : Ne pas dépasser ses compétences. Faire appel à des experts externes si nécessaire.

**Indépendance** : En cas de conflit d'intérêt, déclarer et se retirer.

> **Alerte sécurité** : En France, certaines investigations impliquent le respect du secret professionnel (avocat-client). Le DFIR doit être conscient que certains éléments ne peuvent pas être divulgués sans autorisation légale.
En sécurité informatique, le sigle **DFIR** signifie **Digital Forensics and Incident Response**.

 

* Pour bien **répondre** à un incident et boucher la faille, il faut impérativement comprendre comment l'attaquant est entré (analyse forensique).
* Pour mener une bonne **investigation**, il faut savoir réagir rapidement sur un système en production pour collecter les preuves avant qu'elles ne s'effacent (réponse aux incidents).
