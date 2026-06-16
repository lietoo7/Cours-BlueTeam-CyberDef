## Chapitre 2 : Méthodologie et Chaîne de Captation

### 2.1 Le Principe de la Preuve Numérique et l'Ordre de Volatilité

#### **Qu'est-ce qu'une Preuve Numérique ?**

Une preuve numérique est toute information stockée ou transmise sous forme binaire qui peut établir un fait, une action ou une culpabilité.

**Caractéristiques distinctives :**
- **Fragile** : Modifiable sans trace apparente
- **Complexe** : Comprendre sa provenance (OS, application, format) est nécessaire
- **Abondante** : Un seul système peut contenir des millions d'artefacts
- **Admissibilité variable** : Dépend du contexte légal et de la chaîne de custodie

#### **L'Ordre de Volatilité : Hiérarchie de Collection**

L'ordre de volatilité est un concept fondamental de la forensics Windows et Linux. Il ordonne les sources de preuves par degré de volatilité (risque de perte).

**Ordre Décroissant (Du plus volatile au moins volatile) :**

1. **Registres CPU (caches L1/L2/L3)** - Microseconde
2. **Mémoire RAM (processus actifs, tables de pages, buffers)** - À l'extinction
3. **État du réseau (connexions actives, ARP cache, DNS cache)** - Secondes à minutes
4. **Fichiers système ouverts (file descriptors)** - À la fermeture
5. **Logs système en mémoire (syslog buffers, event logs)** - Selon configuration
6. **Disque dur (filesystems, slack space, unallocated space)** - Persistent
7. **Sauvegardes et archives** - Persistent long-terme
8. **Backups externes (bandes magnétiques, cloud)** - Persistent très long-terme

#### **Application Pratique en Investigation**

**Scénario : Incident détecté sur serveur critique (Windows Server 2019)**

Priorité de collection immédiate (avant arrêt) :
```
1. Dump mémoire (volatility, livekd, WinPmem)
2. État réseau (netstat, Get-NetTCPConnection, connections Powershell)
3. Processus actifs et handles ouverts (tasklist, Get-Process, handle.exe)
4. Logs système en mémoire (Get-EventLog, Powershell transcription)
5. Volumes montés et points de montage (mountvol, Get-Volume)
6. Puis : Acquisition disque complet (bit-stream image)
```

> **Note du terrain** : L'extinction non-planifiée du serveur détruit la RAM. Toujours prioriser le dump mémoire sur une acquisition disque dans les premières minutes si le système reste allumé et sain.

---

### 2.2 Garantir l'Intégrité : Empreintes Cryptographiques et Chaîne de Custodie

#### **Hashing Cryptographique : Concept et Application**

Le hash est une fonction mathématique qui transforme un bloc de données en une chaîne de caractères unique et irréversible.

**Propriétés essentielles :**

| Propriété | Définition | Implication |
|-----------|-----------|-------------|
| **Déterministe** | Même entrée = même hash toujours | Permet la vérification d'intégrité |
| **Effet avalanche** | Minuscule changement = hash totalement différent | Détecte toute modification |
| **Unidirectionnel** | Impossible de retrouver les données du hash | Preuve sans révéler le contenu |
| **Rapide** | Calcul instantané même sur gros volumes | Faisabilité opérationnelle |

#### **Algorithmes Approuvés & Dépréciation**

| Algorithme | Sortie | Statut | Utilisation |
|-----------|--------|--------|-------------|
| **MD5** | 128 bits | ⚠️ Déprécié (collisions pratiques) | Compatibilité legacy uniquement |
| **SHA-1** | 160 bits | ⚠️ Déprécié (collisions théoriques) | Compatibilité legacy uniquement |
| **SHA-256** | 256 bits | ✅ Standard NIST | Production, preuves légales |
| **SHA-512** | 512 bits | ✅ Standard NIST | Maximum de robustesse |
| **BLAKE2** | 256/512 bits | ✅ Cryptographie moderne | Alternative performante |

#### **Protocole de Hashage en Forensics**

**Étape 1 : Hash de Source**

Avant toute manipulation, hasher l'artefact original (disque physique, mémoire, etc.).

```bash
# Sur disque brut (Windows)
certutil -hashfile D:\evidence.dd SHA256

# Sur image disque (Linux)
sha256sum /media/evidence/forensic_image.dd
md5sum /media/evidence/forensic_image.dd
```

**Étape 2 : Hash d'Acquisition**

Hasher l'image acquise immédiatement après et comparer avec la source.

```bash
# KAPE (Acquisition Windows)
C:\kape\kape.exe -m SANS_TRIAGE --tdest C:\acquisition
# Génère automatiquement hash d'intégrité

# Volatility (Dump mémoire)
python3 -m volatility3 -f memory.dump windows.info
# Vérifier integrity flag
```

**Étape 3 : Hash de Preuve**

Au moment de présenter la preuve, recalculer le hash et le comparer avec le hash d'acquisition originel.

```bash
# Vérification lors de litige
certutil -hashfile "C:\Cases\Case_2024_001\evidence.dd" SHA256
# Doit correspondre au hash de 2024-01-15 dans le rapport
```

#### **Chaîne de Custodie (Chain of Custody)**

La chaîne de custodie est le registre documenté de qui a accédé à la preuve, quand, pourquoi et ce qui a été fait.

**Éléments obligatoires :**

```
[CHAIN OF CUSTODY TEMPLATE]

Numéro de dossier : CASE-2024-001
Article de preuve : Disque dur serveur (Seagate SkyHawk 2TB, S/N: ABC123)

Acquisition initiale :
  - Date/Heure : 2024-01-15 14:30 UTC
  - Lieu : Datacentre Paris-1, Salle serveurs
  - Acquéreur : Alice Martin (Forensicien, ANSSI)
  - Hash SHA256 : a1b2c3d4e5f6...
  - Méthode : DD over network, source live
  - Observations : Serveur toujours en fonctionnement, isolation réseau faite
  
Transfert analyse :
  - Date/Heure : 2024-01-15 18:00 UTC
  - De : Alice Martin vers Bob Chen (Analyste, Cabinet Juridique X)
  - Méthode : Clé USB chiffrée, transfert physique sécurisé
  - Hash vérifié : ✅ Correspondance conforme
  - Signature témoin : [Bob Chen]
  
Présentation tribunal :
  - Date : 2024-06-20
  - Présenté par : Alice Martin
  - Hash final vérifié : ✅ Correspondance conforme
  - Intégrité : Non compromise
```

#### **Erreurs Courantes & Risques Légaux**

| Erreur | Conséquence | Prévention |
|--------|-------------|-----------|
| Pas de hash originel | Impossible de prouver intégrité source | Hasher avant toute analyse |
| Modification non documentée du disque | Preuve irrecevable en cour | Traiter sur copie, jamais sur original |
| Chaîne de custodie incomplète | Contestation d'admissibilité | Documenter chaque transfert et accès |
| Hash calculé avec algorithme déprécié | Rejet par tribunal moderne | Utiliser minimum SHA256 |

> **Alerte sécurité** : En France, un défaut de chaîne de custodie ne rend pas automatiquement la preuve inexploitable, mais affaiblit considérablement son admissibilité. Un magistrat peut la rejeter ou la dévaluer fortement.

---

### 2.3 Le Poste de Travail de l'Analyste : Configuration d'une Station Forensique

#### **Caractéristiques d'une Station Forensique Idéale**

Une station forensique est un poste de travail sécurisé, isolé et configuré pour réduire au minimum les risques de contamination des preuves.

**Critères fondamentaux :**

| Aspect | Exigence | Justification |
|--------|---------|--------------|
| **Isolation réseau** | Air-gappé ou VLAN isolé | Éviter transmission accidentelle du malware |
| **Disque dur externe** | USB 3.1, write-blocked | Analyser preuves sans écrire sur disque hôte |
| **Système d'exploitation** | Linux ou Windows sécurisé | Réduire surface d'attaque |
| **Accès administrateur** | Compte local isolé | Exécution outils forensiques sans restrictions |
| **Hashage intégré** | Outils pré-installés (md5deep, hashdeep) | Vérification rapide de l'intégrité |
| **Stockage chiffré** | BitLocker, LUKS | Protéger les artefacts sensibles |

#### **Configuration Linux : SIFT Workstation (SANS)**

SIFT (SANS Investigative Forensic Toolkit) est une distribution Linux spécialisée basée sur Ubuntu, préconfigurée pour le DFIR.

**Installation basique :**

```bash
# Télécharger ISO SIFT depuis SANS (versions 3.x+)
wget https://sift-files.sans.org/sift-workstation-20240201.iso

# Créer machine virtuelle VMware/VirtualBox :
# - 4 CPU minimum, 8 GB RAM
# - 100 GB disque (investigations = beaucoup d'espace)
# - Réseau isolé (NAT ou VLAN dedicé)

# Post-installation
sudo sift update
sudo sift install --user analyst
```

**Outils pré-inclus dans SIFT :**

```
- Volatility 3 (mémoire)
- Sleuth Kit (filesystems)
- Foremost (carving)
- Autopsy (GUI forensics)
- Wireshark (réseau)
- Plaso (timeline)
- RegRipper (registre Windows)
- Yara (pattern matching)
```

#### **Configuration Windows : Poste Dédié Sécurisé**

Sur Windows (analyse de cas impliquant .NET, Powershell avancé), une configuration sécurisée est préférable à un système généraliste.

**Stack recommandé :**

```powershell
# Installation des prérequis

# 1. Python 3.11+
Invoke-WebRequest -Uri "https://www.python.org/downloads/" -OutFile python-installer.exe
.\python-installer.exe /quiet PrependPath=1

# 2. KAPE (Kroll Artifact Parser and Extractor)
# Télécharger depuis https://www.kapetriage.com/
# Installer en C:\kape\

# 3. Eric Zimmerman Tools
# Complet toolkit pour Windows forensics
$path = "C:\tools\EricZimmerman"
New-Item -ItemType Directory -Path $path -Force

# 4. Arsenal Image Mounter (pour monter images disque)
choco install arsenal-image-mounter

# 5. FTK Imager Lite (gratuit, acquisition)
choco install ftk-imager

# 6. Ghidra + IDA Free (reverse engineering)
choco install ghidra
```

**Environnement PowerShell sécurisé :**

```powershell
# Activer ExecutionPolicy restrictif
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Logging avancé (détecter implant accidentel sur station)
Update-Help
Get-ExecutionPolicy -List

# Audit des commandes
New-EventLog -LogName "Forensic-Workstation" -Source "PowerShell"
```

#### **Isolation Réseau & Virtualisation**

**Approche 1 : Air-gapped (Complètement isolé)**

Idéal pour les cas impliquant malware très sophistiqué.

```
[Analyseur DFIR]
      ↓
[Machine virtuelle SIFT, RAM vierge à chaque démarrage]
      ↓
[Disque externe write-blocked]
      ↓
[Aucune connexion réseau]
```

**Approche 2 : VLAN Isolé (Demi-air-gappé)**

Pour la plupart des cas, avec filtrage réseau strict.

```
[Station Forensique] → [Switch VLAN #99 "Forensics"]
                         ↓
                    [Firewall: sortie vers Internet bloquée]
                    [Sortie vers réseau prod bloquée]
                    [Sortie vers serveurs critiques bloquée]
```

**Configuration UFW (Linux) :**

```bash
# Bloquer tout trafic sortant par défaut
sudo ufw default deny outgoing
sudo ufw default deny incoming
sudo ufw default allow loopback

# Autoriser UNIQUEMENT les connexions de gestion
sudo ufw allow from 192.168.1.10 to any port 22  # SSH management

# Appliquer
sudo ufw enable
```

#### **Pratique Opérationnelle : Workflow d'Analyse Sécurisée**

**Jour 1 - Réception des preuves :**

```bash
# 1. Sur station forensique, connecter disque externe write-blocked
lsblk  # Identifier /dev/sdb (lecture seule)

# 2. Vérifier write-protect
cat /sys/block/sdb/ro  # Doit afficher "1"

# 3. Hasher la preuve
sha256sum /dev/sdb > evidence.sha256
md5sum /dev/sdb >> evidence.sha256

# 4. Monter en lecture seule
sudo mkdir -p /mnt/evidence
sudo mount -o ro,noexec /dev/sdb1 /mnt/evidence

# 5. Enregistrer hash et timestamp
date +"%Y-%m-%d %H:%M:%S" >> chain_of_custody.log
echo "Initial hash: $(cat evidence.sha256)" >> chain_of_custody.log
```

**Jours 2-N - Analyse :**

```bash
# Utiliser uniquement des copies (bit-stream images créées via DD)
sudo dd if=/dev/sdb of=/external_storage/evidence_copy.dd bs=4M
sha256sum /external_storage/evidence_copy.dd

# Analyser sur la copie, jamais l'original
volatility3 -f evidence_copy.dd windows.info
```

**Fin d'investigation - Archivage :**

```bash
# Créer archive sécurisée
tar czf case_2024_001.tar.gz /analysis/case_2024_001/
gpg --symmetric --cipher-algo AES256 case_2024_001.tar.gz

# Hash final
sha256sum case_2024_001.tar.gz.gpg > final_hash.txt

# Stocker : copie chiffrée + hash sur supports séparés
```

> **Note du terrain** : Une station forensique qui "vieillit" accumule des dépendances et des vulnérabilités. Réinitialiser l'OS une fois par an ou après analyse de malware très sophistiqué.
