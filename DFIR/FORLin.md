
## Chapitre 7 : Forensic Linux et macOS

### 7.1 Analyse du Système de Fichiers Linux (Ext4, APFS)

#### **Ext4 : Concepts Fondamentaux**

Ext4 est le système de fichiers standard sur Linux. Contrairement à NTFS, il conserve moins d'artefacts temporels mais offre une structure prédictible.

**Éléments clés :**

- **Inode** : Structure contenant métadonnées du fichier (permissions, timestamps, pointeurs de blocs)
- **Block** : Unité de données (4096 octets typiquement)
- **Unallocated space** : Blocs marqués comme "libres" mais contenant potentiellement d'anciennes données
- **Journal** : Log transactionnel qui enregistre changements avant d'être écrit sur disque

#### **Timestamps Ext4 & Volatilité**

Contrairement à Windows (4 timestamps), Ext4 a :

| Timestamp | Sigle | Signification | Volatilité |
|-----------|-------|--------------|-----------|
| **Modify time** | mtime | Dernière modification du fichier | ✓ Changé à chaque write |
| **Access time** | atime | Dernier accès (lecture) | ✓ Mais souvent désactivé pour perf |
| **Change time** | ctime | Dernier changement de métadonnée | ✓ Modifié avec atime/mtime |
| **Crtime** | Birth time | Création du fichier | ✗ Conservé en Ext4 (rarement en POSIX) |

**Exemple :**

```bash
# Lister timestamps complets
stat /home/user/malware.sh
# File: /home/user/malware.sh
# Size: 2048    Blocks: 8
# Access: (0755/-rwxr-xr-x)
# Uid: ( 1000/ jdoe)   Gid: ( 1000/  jdoe)
# Access: 2024-01-15 14:35:22.000000000 UTC
# Modify: 2024-01-15 13:45:10.000000000 UTC
# Change: 2024-01-15 13:45:10.000000000 UTC
# Birth : 2024-01-10 09:20:30.000000000 UTC
#
# ↑ Fichier créé 10 jan, modifié 15 jan à 13:45, accédé 14:35
```

#### **Carving & Unallocated Space**

```bash
# Utiliser Sleuth Kit pour finder fichiers supprimés dans unallocated
# Exemple : Récupérer image forensique

# Lister inodes supprimés
istat -d ext4 /dev/sdb1

# Carver des fichiers (par magic bytes)
foremost -i /dev/sdb1 -o /output/carved/

# Résultat
find /output/carved -name "*.txt" | head -5
# /output/carved/text/00001234.txt
# /output/carved/text/00001235.txt
# ... (potentiellement 1000s fichiers, signal/bruit)
```

---

### 7.2 Persistance sous Linux (Cron, Systemd, SSH Keys)

#### **Crontab : Tâches Planifiées**

**Localisation :**

```
/etc/crontab              [Tâches système]
/etc/cron.d/              [Tâches système (répertoire)]
/home/*/crontab           [Tâches utilisateur]
/var/spool/cron/crontabs/ [Copies de crontabs (si logiciel spécialisé)]
```

**Format :**

```crontab
# /etc/crontab
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root

# minute hour day_of_month month day_of_week user command
*/5 * * * * root /usr/sbin/logrotate -f /etc/logrotate.conf
0 2 * * * root /usr/bin/backup.sh

# Exemple malveillant :
0 * * * * root /tmp/.hidden/persistence.sh  [MALWARE - exécuté chaque heure]
@reboot root /etc/rc.local
```

**Extraction :**

```bash
# Lister crontabs
crontab -l -u jdoe
grep CRON /var/log/syslog | head -20

# Chercher crontabs suspects
find /etc/cron.d -type f -exec grep -l "tmp\|\.hidden" {} \;
```

#### **Systemd : Services & Timers**

Systemd a remplacé SysV init. Les services persistent via fichiers `.service`.

**Localisation :**

```
/etc/systemd/system/        [Services personnalisés]
/usr/lib/systemd/system/    [Services système]
/lib/systemd/system/        [Services (alternative)]
```

**Fichier de service malveillant :**

```ini
# /etc/systemd/system/cryptominer.service
[Unit]
Description=System Optimizer
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/xmrig -o pool.monero.net:3333 -u addr
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Activation du service :**

```bash
# Enregistrer le service
systemctl enable cryptominer.service

# Vérifier état
systemctl status cryptominer

# Lister tous les services démarrés au boot
systemctl list-unit-files | grep enabled

# Chercher services suspects
grep -r "tmp\|\.hidden\|crypto" /etc/systemd/system/
```

#### **SSH Keys & Backdoors**

**Localisation :**

```
~/.ssh/authorized_keys     [Clés publiques acceptées pour login]
~/.ssh/id_rsa              [Clé privée]
/root/.ssh/authorized_keys [Backdoor: attaquant ajoute sa clé pub]
```

**Attaque SSH courant : Ajout de clé backdoor**

```bash
# Attaquant génère sa propre paire de clés sur sa machine
ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa

# Attaquant obtient accès à serveur compromis (exploit, etc.)
# Puis ajoute sa clé publique
echo "ssh-rsa AAAA3NzaC1yc2EAAAADAQABAAABgQC..." >> ~/.ssh/authorized_keys

# Attaquant peut maintenant se connecter sans password
ssh -i ~/.ssh/id_rsa user@target.com
```

**Détection :**

```bash
# Lister authorized_keys
cat ~/.ssh/authorized_keys

# Vérifier timestamps de modifications
stat ~/.ssh/authorized_keys
# Modify: 2024-01-15 14:35:22 [SUSPECTE - quand système a été attaqué]

# Comparer avec backup/version control si disponible
diff ~/.ssh/authorized_keys ~/.ssh/authorized_keys.backup
# ssh-rsa AAAA3NzaC1... [NOUVELLE CLÉ MALVEILLANTE]
```

---

### 7.3 Analyse des Logs Système (Syslog, journalctl)

#### **Syslog : Logs système traditionnels**

**Localisation :**

```
/var/log/syslog           [Debian/Ubuntu]
/var/log/messages         [RedHat/CentOS]
/var/log/auth.log         [Authentification]
/var/log/secure           [RedHat authentification]
/var/log/kernel.log       [Kernel messages]
```

**Format :**

```
Jan 15 14:35:22 workstation sudo: jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/bin/bash
Jan 15 14:35:45 workstation kernel: Out of memory: Kill process firefox (2341) score 234 or sacrifice child
Jan 15 14:36:10 workstation sshd[5234]: Failed password for jdoe from 45.133.xxx.xxx port 54321 ssh2
```

**Extraction forensique :**

```bash
# Chercher bruteforce SSH
grep "Failed password" /var/log/auth.log | wc -l
# 5240 tentatives [BRUTE FORCE]

# Compter par adresse IP source
grep "Failed password" /var/log/auth.log | grep -oP "from \K[^\s]+" | sort | uniq -c
# 5200 45.133.xxx.xxx [MAJORITÉ - source bruteforce]
# 40 192.168.1.10     [Utilisateur normal faisant erreur]

# Extraction timeline
grep -i "sudo\|su\|ssh\|login" /var/log/auth.log | 
  awk '{print $1, $2, $3, $5, $6, $7}'
```

#### **Journalctl : Logs structurés (Systemd)**

Systemd journalctl est plus structuré et plus difficile à modifier que syslog.

```bash
# Afficher tous les logs
journalctl

# Logs depuis 1 jour
journalctl -n 50000 --since "1 day ago"

# Logs d'un service spécifique
journalctl -u ssh.service -n 1000

# Format complet (JSON, pour parsing)
journalctl -o json | jq '.'
# Output :
# {
#   "PRIORITY": "3",
#   "__REALTIME_TIMESTAMP": "1705335222000000",
#   "MESSAGE": "Failed password for jdoe from 45.133.xxx.xxx",
#   "_HOSTNAME": "workstation"
# }

# Chercher événements suspects
journalctl PRIORITY=3 | grep -i "fail\|error\|killed"

# Timeline JSON (pour analysis)
journalctl -o json --since "2024-01-15 13:00:00" \
  --until "2024-01-15 15:00:00" > timeline_compact.json
```

> **Note du terrain** : Les logs Systemd sont stockés dans `/var/log/journal/`. Attaquant sophistiqué peut essayer de supprimer ce répertoire (réduisant la volatilité des preuves). Vérifier timestamps d'accès du répertoire lui-même.
