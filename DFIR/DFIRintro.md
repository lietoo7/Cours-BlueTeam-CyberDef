En sécurité informatique, le sigle **DFIR** signifie **Digital Forensics and Incident Response**.

En français, on le traduit généralement par **Informatique légale et Réponse aux incidents** (ou *Analyse forensique et Réponse aux incidents*).

C’est une discipline de la cybersécurité qui combine deux expertises complémentaires pour faire face aux cyberattaques :

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

### Pourquoi regroupe-t-on ces deux termes ?

Auparavant, la réponse aux incidents (IR) et l'analyse forensique (DF) étaient souvent traitées séparément. Aujourd'hui, elles sont indissociables :

* Pour bien **répondre** à un incident et boucher la faille, il faut impérativement comprendre comment l'attaquant est entré (analyse forensique).
* Pour mener une bonne **investigation**, il faut savoir réagir rapidement sur un système en production pour collecter les preuves avant qu'elles ne s'effacent (réponse aux incidents).
