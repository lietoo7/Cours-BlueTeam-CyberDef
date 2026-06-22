
## Chapitre 9 : Analyse de la Mémoire RAM (Volatility 3 Avancé)

### 9.1 Concepts Fondamentaux de la Gestion Mémoire Sous Windows

#### **Architecture Mémoire Windows (Simplifiée)**

Windows utilise un schéma de mémoire virtuelle à deux niveaux :

```
Virtual Address Space (4 GB par processus, 64-bit = 16 EB)
     ↓
Page Tables (mappent VA → PA)
     ↓
Physical RAM (8 GB, 16 GB, etc.)
```

**Zones clés :**

| Zone | Adresse | Contenu | Volatilité |
|------|---------|---------|-----------|
| **Kernel Space** | 0xFFFF... | Code kernel, drivers, structures système | Critique |
| **User Space** | 0x0000... | Heap, stack, code application | Très critique |
| **Page File** | Disque | Mémoire "paginée" vers disque | Semi-persistant |
| **Registry** | Physique | Clés registre chargées en RAM | Semi-volatile |

#### **Processus & Virtual Address Spaces**

Chaque processus a son propre "virtual address space" de 4 GB (32-bit) ou 16 EB (64-bit).

```
Process Model (Windows):

Kernel.exe (PID 4)
  ├─ Virtual Address 0x0000:0000 → Physical RAM
  ├─ Page Table (PDPT)
  └─ CR3 = pointer to page tables

Explorer.exe (PID 1234)
  ├─ Virtual Address 0x0000:0000 → Physical RAM (différent que kernel)
  ├─ Page Table (PDPT)
  └─ CR3 = pointeur différent

[Même VA, adresses physiques différentes]
```

**Implication forensique :**

```
Analyser mémoire nécessite :
1. Récupérer CR3 de chaque processus (context switch)
2. Parser page tables (PDPT, PDT, PT, PTE)
3. Résoudre VA → PA pour chaque adresse
4. Reconstituer heap/stack par processus

Volatility automatise cela.
```

#### **Heap & Stack : Où le Malware Se Cache**

**Stack** : Accès rapide, stocke variables locales + return addresses

```
Function A calls B:
  Stack layout :
  ┌─────────────────┐
  │ Frame A         │ ← RSP (stack pointer) = top of stack
  │ Local vars A    │
  │ Return addr     │ ← Où revenir quand B finit
  │ Frame B         │
  │ Local vars B    │ ← Actuellement exécuté
  └─────────────────┘
  
Attack: Débordement stack (buffer overflow)
        Overwrite return address → Jump à code malveillant
```

**Heap** : Mémoire dynamique, lente mais grande

```
malloc() allocation :
  ┌──────────┐
  │ Chunk 1  │ ← Allocé
  │ metadata │
  ├──────────┤
  │ Chunk 2  │ ← Libre
  ├──────────┤
  │ Chunk 3  │ ← Allocé (souvent malware)
  └──────────┘

Attack: Heap spray (remplir heap avec shellcode)
        Heap corruption (overwrite chunk metadata)
```

---

### 9.2 Utilisation Avancée de Volatility 3

#### **Commandes Volatility Essentielles pour Forensics**

**1. Identification du Dump**

```bash
python3 -m volatility3 -f memory.dump windows.info
# Retourne :
# KUSER_SHARED_DATA: 0xffff0f80...
# KDLL Base: 0xfffff800...
# NT Build: 19041 (Windows 10 21H2)
# OS Profile auto-détecté
```

**2. Enumération Processus (Détection Caché)**

```bash
python3 -m volatility3 -f memory.dump windows.pslist
# Liste : processus "normaux" (linked list kernel)
# Manque : processus cachés (unlinked de la liste)

# Volatility compare multiple sources :
# - PsActiveProcessHead (liste kernel)
# - All processes in Virtual Address Space (enumerate pages)
# - CSRSS handles (processus doivent être enregistrés)

# Différence = hidden process
python3 -m volatility3 -f memory.dump windows.psscan
# Scan mémoire pour EPROCESS structures (cache-resistant)
# Retrouve processus hidden

# Différence entre pslist & psscan = processus injecté/caché
```

**3. Injection de Code & DLL Loading**

```bash
# Pour chaque processus, lister DLLs chargées
python3 -m volatility3 -f memory.dump windows.dlllist

# Résultat :
# PID: 1234 (explorer.exe)
#   0x00007ff0: C:\Windows\System32\kernel32.dll
#   0x00007ff8: C:\Windows\System32\ntdll.dll
#   0x00007ffc: C:\Windows\System32\mscoree.dll
#   0x00400000: C:\Users\jdoe\AppData\Local\Temp\injected.dll [SUSPECT]
#               ↑ DLL dans TEMP, chargée dynamiquement

# Code injection : Chercher RWX pages (lecture + écriture + exécution)
python3 -m volatility3 -f memory.dump windows.memmap --pid 1234 | grep RWX

# Résultat : Adresses avec RWX = potentiel shellcode
```

**4. Extraction Secrets (Passwords, Tokens, Keys)**

```bash
# Loot LSA (Local Security Authority) pour NT hashes
python3 -m volatility3 -f memory.dump windows.hashdump

# Résultat :
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
# Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# jdoe:1000:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
# ↑ Hashes NTLM (peuvent être crackés offline)

# Extraire credentials depuis LSASS memory
python3 -m volatility3 -f memory.dump windows.lsadump

# Résultat : Plaintext passwords (Kerberos tickets, SSO)
```

**5. Connexions Réseau Actives**

```bash
python3 -m volatility3 -f memory.dump windows.netscan

# Résultat :
# PID: 2344 (powershell.exe)
#   0x0a000064:55612 → 45.133.xxx.xxx:443 [ESTABLISHED]
#   ↑ PowerShell connectée à serveur C2 externe

# PID: 1024 (chrome.exe)
#   0xc0a80001:5000 → 8.8.8.8:53 [ESTABLISHED]
#   ↑ Chrome connecté à DNS Google (normal)
```

**6. Timeline Reconstruction (Processus Exécution)**

```bash
python3 -m volatility3 -f memory.dump windows.timelineshot
# Timeline de création/terminaison de tous les processus

# Résultat :
# 2024-01-15 13:45:22 Process Created: powershell.exe (PID 2344)
# 2024-01-15 13:45:25 DLL Loaded: C:\Temp\injected.dll
# 2024-01-15 13:45:30 Network Connection: 45.133.xxx.xxx:443
# 2024-01-15 14:35:22 Process Terminated: powershell.exe
```

#### **Cas d'Usage : Fileless Malware Detection**

Fileless malware vit **uniquement en mémoire**, pas sur disque.

```
[SCENARIO] Emotet.C fileless variant
          - Pas d'exécutable sur disque
          - Vit en mémoire PowerShell
          - Détection : uniquement via RAM dump

Detection steps:

1. Dump mémoire système
   ├─ ✅ Dump acquis rapidement

2. Enumerate processus
   └─ PowerShell.exe (PID 2344) chargé + executionPolicy modifiée

3. Analyzer PowerShell process
   python3 -m volatility3 -f memory.dump windows.dumpfiles --pid 2344
   └─ Extrait contenu mémoire processus

4. Chercher signatures PowerShell malveillant
   strings memory_2344 | grep -i "invoke\|obfuscation\|cmd"
   └─ Trouve contenu script PowerShell encodé

5. Decoder script (usually Base64 + obfuscation)
   Decode → Identifie Emotet C2 URLs
   
6. Timeline : Quand PowerShell a lancé le script ?
   ├─ 13:45:22 - Explorer.exe lance PowerShell hidden
   ├─ 13:45:24 - PowerShell télécharge script malveillant
   ├─ 13:45:25 - Script chauffé en mémoire (nunca sur disque)
   └─ Volatility retrouve tout en mémoire
```

---

### 9.3 Reverse Engineering de Malware via Mémoire

#### **Extraction de Malware du Dump**

Parfois, malware n'est pas sur disque (déjà supprimé). Volatility extrait desde mémoire.

```bash
# Trouver processus contenant code malveillant
python3 -m volatility3 -f memory.dump windows.pslist | grep -i "notepad\|svchost\|system"

# Pour processus suspect, dumper mémoire complète
python3 -m volatility3 -f memory.dump windows.dumpfiles --pid 1234 --output-dir ./dumps

# Analyser dump binaire avec Ghidra/IDA
# Chercher :
# - Strings suspectes (C2 domains, API calls)
# - Références mémoire anormales
# - Chunks de code injecté

# Exemple : Dumped data analysé dans Ghidra
strings dumps/pid.1234.img | grep -i "http\|cmd\|powershell"
# http://c2.attacker.ru/cmd?id=
# cmd.exe /c whoami
# powershell.exe -NoProfile -ExecutionPolicy Bypass
```

#### **Identification de Packer & Obfuscation**

```
Packed malware = Original code compressé + Decompressor stub
Detecter packer = Identifier entropie haute (données aléatoires)

Volatility plugin :
python3 -m volatility3 -f memory.dump windows.entropy --pid 1234

Résultat :
Memory page entropy scores:
0x400000: 2.1 [LOW - CODE section]
0x401000: 7.8 [HIGH - PACKED/COMPRESSED]
0x402000: 8.9 [VERY HIGH - ENCRYPTION KEY ?]

HIGH entropy = probability packer détecté
```
