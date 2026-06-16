## Chapitre 5 : Acquisition de la Preuve (Collecte)

### 5.1 Acquisition de la Mémoire Vive (RAM)

#### **Principes Fondamentaux**

La mémoire vive (RAM) contient l'état exécutif du système en temps réel : processus actifs, clés cryptographiques, tokens d'authentification, connexions réseau, buffers d'application.

**Volatilité :** La RAM s'efface complètement à l'extinction du serveur.

**Importance forensique :** Code injecté, malware fileless, passwords en mémoire, connexions C2 actives.

#### **Méthodes d'Acquisition**

| Méthode | Outil | Overhead | Détection | Qualité | Cas d'Usage |
|---------|-------|----------|-----------|---------|-----------|
| **Crash Dump** | Built-in (WinDbg) | Moyen | Faible | Bonne | Server Windows |
| **Dumper Hardware** | Carte FireWire/PCIe | Minimal | Très faible | Excellente | Lab forensique |
| **Kernel dump** | Volatility/KD.exe | Faible | Très faible | Très bonne | Production |
| **Hypervisor dump** | VMware/Hyper-V API | Minimal | Faible | Bonne | Infrastructure virtualisée |
| **Userspace dump** | WinPmem/LiME/avml | Moyen | Détectable | Bonne | Live incident response |

#### **Windows : WinPmem (Recommandé)**

WinPmem est un driver kernel qui accède directement à la RAM sans passer par l'API Windows (moins détectable).

**Installation & Utilisation :**

```powershell
# Télécharger WinPmem 3.3+
# Source : github.com/Velocidex/WinPmem

# Copier sur système à analyser (USB ou réseau)
C:\>winpmem_3.3_x64.exe

# Syntaxe basique
.\winpmem_3.3_x64.exe output_filename.raw

# Sortie simple
C:\>.\winpmem_3.3_x64.exe memory.dump
Dumping 16384 MB...
[████████████████████████████████] 100%
Successfully dumped 16384MB to memory.dump

# Dump avec hash
.\winpmem_3.3_x64.exe memory.dump --hash SHA256

# Résultat
SHA256: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a
```

**Considérations importants :**

```
⚠️  Taille fichier = RAM physique (8GB de RAM = 8GB fichier)
⚠️  Transfert réseau lent si > 32 GB
⚠️  Compression réduisez peu (RAM déjà chaotique)
⚠️  Vérifier espace disque libre disponible !
```

#### **Linux : AVML (Acquisition of Volatile Memory for Linux)**

```bash
# Télécharger AVML depuis Microsoft GitHub
wget https://github.com/microsoft/avml/releases/download/v0.10.1/avml

chmod +x avml

# Acquisition simple
sudo ./avml memory.dump

# Acquisition avec compression (optionnel)
sudo ./avml --output-format raw memory.dump

# Vérifier taille
ls -lh memory.dump
# -rw-r--r-- 1 root root 32G Jan 15 14:45 memory.dump
```

#### **Analyse Rapide de Dump RAM (Volatility 3)**

Immédiatement après acquisition, on peut requêter le dump pour artefacts critiques.

```bash
# Sur workstation forensique
python3 -m volatility3 -f memory.dump windows.info
# Retourne : OS, kernel base, KASLR offset, nombre processus

python3 -m volatility3 -f memory.dump windows.pslist
# Retourne : liste processus + parent + PID + statut

python3 -m volatility3 -f memory.dump windows.netscan
# Retourne : connexions TCP/UDP actives + adresses distantes (C2 !)

python3 -m volatility3 -f memory.dump windows.dumpfiles --pid 1234
# Extrait fichiers ouverts par processus PID 1234
```

> **Note du terrain** : Garder le dump RAM même après fin d'incident. Peut être requêté plus tard (1 mois après) si découverte de timing d'intrusion important (ex: "quand exactement l'attaquant était-il connecté ?").

---

### 5.2 Acquisition des Supports de Stockage : Clonage Binaire et Logique

#### **Distinction : Image Binaire vs Logique**

**Image Binaire (Bit-Stream / Forensic Image) :**

Copie exacte, bit par bit, de tous les secteurs du disque (y compris unallocated space, slack space, bad sectors).

Propriétés :
- Taille exacte = capacité disque
- Contient zones supprimées
- Requires write-blocke hardware
- Durée : longue (disque 2TB = 2-4h en acquisition réseau)

**Image Logique :**

Copie uniquement des fichiers/dossiers accessibles via le filesystem.

Propriétés :
- Taille < capacité disque
- Perd unallocated space
- Rapide à acquérir
- Suffisant pour certains cas (pas besoin slack space)

#### **Acquisition Binaire Windows : FTK Imager ou dd**

**Option 1 : FTK Imager (Gratuit, simple)**

```
[Interface FTK Imager]
File > Create Disk Image

Source : \\.\PhysicalDrive1 (disque physique)
ou
         C: (volume logique)

Destination : C:\evidence\disk_image.dd
Format : Raw (DD)
Verification : SHA-1 (automatique)

Parallèlement :
└─ Hash source = enregistré
└─ Hash image = enregistré à fin
└─ Comparaison = proof d'intégrité
```

**Option 2 : DD (Command-line, plus contrôle)**

```bash
# Sur Linux forensique workstation

# Identifier disque cible
sudo fdisk -l
# Disk /dev/sda: 2000GB
# Disk /dev/sdb: 500GB [EXTERNE - Disque à imager]

# Vérifier write-protect activé sur /dev/sdb
cat /sys/block/sdb/ro  # Doit afficher "1"

# Imager disque -> fichier
sudo dd if=/dev/sdb of=/external_storage/forensic_image.dd bs=4M
# bs=4M = block size 4MB (optimisation vitesse)

# Sortie
16384+0 records in
16384+0 records out
68719476736 bytes (68 GB) copied, 2400 s, 28.6 MB/s

# Vérifier taille = source
du -h forensic_image.dd
# 68G forensic_image.dd

# Hash image
sha256sum /external_storage/forensic_image.dd > image.sha256
```

#### **Acquisition Logique : KAPE avec ciblage**

KAPE peut aussi faire acquisition logique (plus rapide) pour cas où unallocated space non-critique.

```powershell
# Ciblage spécifique : Documents utilisateur, navigateur history, registre
.\kape.exe -m:\Users -m:\Windows\System32\config `
           --tdest C:\Evidence\Logical_Triage `
           --zip

# Résultat = dossier compressé, très petit, exfiltrable facilement
# Utilisé lors incident response urgent (exfiltrer vite les preuves)
```

#### **Validation & Chaîne de Custodie**

```
[ACQUISITION PROTOCOL - Bit-Stream Image]

Step 1 - Préparation (T-0)
├─ Enregistrer : numéro série disque, marque, modèle
├─ Brancher sur write-blocker (Tableau : USB3 + FC ou Firewire)
├─ Vérifier write-protect indicateur lumineux (rouge = protégé)
└─ Enregistrer timestamp exact de début

Step 2 - Acquisition (T+2h à T+4h selon taille)
├─ Lancer DD / FTK Imager
├─ Monitorer : pas d'erreurs d'I/O (bad sectors)
└─ Conserver log d'acquisition

Step 3 - Vérification d'Intégrité (T+4h à T+4:30h)
├─ Hash disque source : sha256sum /dev/sdb
│  Résultat : a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a
├─ Hash image acquise : sha256sum forensic_image.dd
│  Résultat : a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a
├─ Comparaison : ✅ MATCH
└─ Enregistrer "Intégrité confirmée 2024-01-15 16:30 UTC"

Step 4 - Chaîne de Custodie
├─ Signature (qui a acquis) : Alice Martin, ANSSI
├─ Témoins : Bob Chen (Cabinet juridique)
├─ Stockage : Coffre sécurisé, clé chiffré GPG
└─ Accès ultérieurs : Log + signatures ajoutées
```

> **Alerte légale** : Une seule discordance de hash entre source et image = preuve irrecevable en cour. Refaire l'acquisition entière si problème détecté.

---

### 5.3 Collecte Ciblée (Triage Collection) : KAPE et Frameworks d'Automatisation

#### **Utilité de la Collecte Ciblée**

En incident response, avoir une image disque complète prend 4-6h pour 2TB. Or, l'équipe a besoin de réponses en 30 minutes.

La **collecte ciblée** (targeted triage) acquiert les artefacts clés (registre, browser, prefetch, logs) en 2-5 minutes.

#### **KAPE : Targeted Artifact Acquition**

KAPE comprend des milliers d'artefacts par catégorie.

```
[KAPE Modes]

SANS_TRIAGE      : Toutes les preuves d'exécution + browser
                   Durée : 2-5 min

FULL             : Complet (registre, logs, MFT, prefetch, lnk, bagzip)
                   Durée : 10-20 min

CUSTOM           : Créer un profil spécifique pour votre org
                   Durée : variable
```

**Utilisation :**

```powershell
cd C:\kape

# Profil SANS Triage
.\kape.exe -m SANS_TRIAGE --tdest C:\Evidence\TRIAGE

# Résultat : Dossier avec structure préservée
C:\Evidence\TRIAGE\
├─ C_Drive\
│   ├─ Users\jdoe\
│   │   ├─ NTUSER.DAT
│   │   ├─ AppData\Local\Mozilla\Firefox\Profiles\...
│   │   └─ AppData\Roaming\Microsoft\Windows\Recent\...
│   ├─ Windows\System32\
│   │   ├─ config\SAM
│   │   ├─ config\SYSTEM
│   │   ├─ drivers\etc\HOSTS
│   │   └─ winevt\Logs\
│   └─ ProgramData\
├─ $Extend\
│   └─ $UsnJrnl  [USN Journal]
└─ KAPE_Integrity_[timestamp].sha256

# Profil complet
.\kape.exe -m FULL --tdest C:\Evidence\FULL

# Profil custom (créé avant l'exécution)
# Éditer le fichier LocalRecover.tkape pour inclure vos propres répertoires
.\kape.exe -m CUSTOM_INCIDENT --tdest C:\Evidence\CUSTOM
```

#### **UAC (Ultimate Artifact Collection)**

UAC est un alternative libre à KAPE, écrit en PowerShell.

```powershell
# Télécharger depuis github.com/Invoke-IR/PowerForensics
# ou github.com/kacos2000/...

# Exécution
.\UAC.ps1

# Interface interactive
SELECT ARTIFACTS TO COLLECT:
[1] Memory dump
[2] Registry hives
[3] Event logs
[4] Prefetch
[5] Browser artifacts
[6] All

Enter choice: 6

# Collecte démarre
```
