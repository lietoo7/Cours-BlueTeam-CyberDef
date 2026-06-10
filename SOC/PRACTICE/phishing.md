# Fondamentaux de l'analyse du phishing
Apprenez à connaître tous les composants qui structurent un e-mail.
> Source : Tryhackme Phishing Analysis Fundamentals : https://tryhackme.com/room/phishingemails1tryoe

## 1. Introduction aux Menaces par Email

Le spam et le phishing (hameçonnage) demeurent les menaces d'ingénierie sociale les plus fréquentes pour les organisations modernes. Bien que le spam représente généralement un risque faible, le phishing est conçu pour tromper les utilisateurs afin de leur extorquer des informations sensibles ou de leur faire exécuter des logiciels malveillants (malwares).

> **L'enjeu cyber :** Un seul clic sur un lien malveillant ou l'ouverture d'une pièce jointe suspecte suffit à offrir un point d'ancrage initial à un attaquant dans le réseau, pouvant causer des dommages considérables à l'entreprise.
 
### Objectifs d'Apprentissage

* Comprendre les mécanismes fondamentaux de la distribution d'emails.
* Maîtriser l'analyse des en-têtes (headers) d'emails.
* Investiguer et décortiquer le corps (body) des messages suspectés.
* Identifier les différentes variantes de phishing.
* Évaluer la dangerosité d'un email pour neutraliser la menace.

## 2. Anatomie d'une Adresse Email

Toute investigation liée au phishing débute par l'élément le plus basique : **l'adresse email**. En comprendre la structure exacte est indispensable pour repérer les anomalies et les techniques d'usurpation utilisées par les attaquants.

*Historique : Popularisé dans les années 1970 sur le réseau ARPANET par Ray Tomlinson, le format de l'adresse email repose sur l'utilisation du symbole `@` pour séparer l'utilisateur du système de destination.*

Une adresse email se compose de trois éléments fondamentaux :

| Composant | Description | Exemple (`david@tryhackme.com`) |
| --- | --- | --- |
| **1. Le Nom d'utilisateur** *(Username)* | Identifie la boîte aux lettres spécifique du destinataire sur le serveur de messagerie. | `david` |
| **2. Le Symbole `@**` | Sert de séparateur et indique au système comment router l'email. | `@` |
| **3. Le Nom de Domaine** *(Domain name)* | Spécifie le serveur de messagerie (mail server) responsable de la réception du message. | `tryhackme.com` |

### L'Analogie Postale

Pour simplifier cette structure, on peut comparer une adresse email à une adresse postale classique :

* **Le nom de domaine** correspond à la rue ou à l'immeuble (la localisation générale).
* **Le nom d'utilisateur** correspond au nom de la personne ou au numéro de la boîte aux lettres (la cible précise au sein de cette localisation).

## 3. Les Protocoles de Messagerie

Pour acheminer un email de l'expéditeur au destinataire, plusieurs protocoles réseau collaborent en arrière-plan. Chacun possède un rôle strictement défini :

* **SMTP** *(Simple Mail Transfer Protocol)* : Dédié exclusivement à l'**envoi** d'emails.
* **POP3** *(Post Office Protocol version 3)* : Dédié au **téléchargement** d'emails sur un appareil unique.
* **IMAP** *(Internet Message Access Protocol)* : Dédié à la **synchronisation** d'emails entre plusieurs appareils.

Lors de la réception, le client de messagerie utilise soit POP3, soit IMAP selon sa configuration. Voici leurs différences fondamentales :

### Confrontation : POP3 vs IMAP

| Caractéristique | Protocole POP3 | Protocole IMAP |
| --- | --- | --- |
| **Stockage principal** | Téléchargé et stocké sur un **seul appareil**. | Conservé sur le **serveur distant**. |
| **Messages envoyés** | Visibles uniquement depuis l'appareil émetteur. | Synchronisés et visibles sur tous les appareils. |
| **Accès multi-appareil** | Impossible (limité au terminal de téléchargement). | Total (accès simultané depuis PC, smartphone, etc.). |
| **Persistance serveur** | Supprimé du serveur après téléchargement (par défaut). | Reste sur le serveur sauf suppression explicite. |

## 4. Le Voyage d'un Email (Workflow Réseau)

Plutôt que d'apprendre des définitions isolées, l'analyse défensive impose de comprendre le cheminement technique exact d'un message, de l'expéditeur au destinataire.

En se référant au schéma technique, voici les 6 étapes clés :

```
[ Expéditeur ] --- (1) SMTP ---> [ Serveur SMTP Externe ] --- (2) Requête DNS ---> [ Serveur DNS ]
                                           |                                             |
                                    (4) SMTP / Transfert                           (3) Résolution MX
                                           v                                             |
[ Destinataire ] <-- (6) POP3/IMAP -- [ Serveur Mail Cible ] <----------------------------+
       ^
       |
  (5) Connexion

```

### Description Étape par Étape

* **1. Envoi de l'email :** L'utilisateur expéditeur clique sur "Envoyer". Son client de messagerie transmet le message à son propre serveur de messagerie via le protocole **SMTP**.
* **2. Requête DNS :** Le serveur de messagerie de l'expéditeur interroge le serveur **DNS** pour identifier le serveur de messagerie légitime du domaine destinataire (recherche de l'enregistrement MX - *Mail Exchanger*).
* **3. Réponse du DNS :** Le DNS répond en fournissant l'adresse IP du serveur de messagerie de destination.
* **4. Livraison de l'email :** Le message est acheminé à travers Internet et délivré au serveur de messagerie du destinataire, toujours via **SMTP**.
* **5. Connexion du destinataire :** Le client de messagerie du destinataire se connecte à son serveur de messagerie pour vérifier l'arrivée de nouveaux messages.
* **6. Récupération du message :** L'email est soit téléchargé localement (**POP3**), soit synchronisé en temps réel (**IMAP**) sur le terminal de l'utilisateur final.

## 5. La Structure Globale d'un Email

Lorsqu'un email arrive dans une boîte de réception, il ne se limite pas au texte visible par l'utilisateur. Pour un analyste en sécurité, un email est systématiquement divisé en deux parties distinctes :

* **L'en-tête (Email Header) :** Il s'agit des métadonnées du message. Cette section invisible pour l'utilisateur standard retrace l'identité de l'émetteur, le parcours technique du message et l'historique des serveurs impliqués dans sa distribution.
* **Le corps du message (Email Body) :** Il contient le contenu textuel ou graphique réel délivré à l'utilisateur, généralement rédigé en texte brut (*Plain Text*) ou en code HTML (ce qui permet d'insérer des liens, des images et du style).

## 6. Les Composants Standards de l'En-tête

Avant de plonger dans les données brutes, il convient de maîtriser les champs d'en-tête de base, qui fournissent le contexte initial de l'échange :

* **From (De) :** L'adresse email affichée de l'expéditeur. *Attention : ce champ est facilement falsifiable par un attaquant (Spoofing).*
* **To (À) :** L'adresse email du destinataire principal.
* **Reply-To (Répondre à) :** L'adresse vers laquelle les réponses seront redirigées si le destinataire clique sur "Répondre". Ce champ est facultatif et souvent détourné par les attaquants pour recevoir les réponses sur une adresse différente de celle de l'expéditeur affiché.
* **Subject (Objet) :** Le titre de l'email, conçu pour inciter à l'ouverture (ou manipuler le comportement de la cible en cas de phishing).
* **Date :** L'horodatage précis (date, heure et fuseau horaire) indiquant le moment où l'email a été expédié par le serveur de messagerie d'origine.

## 7. Analyse de la Source Brute (*Message Source*)

Pour mener une investigation cyber efficace, l'affichage standard d'une boîte aux lettres est insuffisant. L'analyste doit impérativement inspecter le **code source brut** du message (*Raw Message Data*).

> **Pourquoi analyser la source brute ?** > L'affichage de la source révèle l'intégralité des en-têtes techniques cachés (comme les adresses IP d'origine, les sauts de serveurs, ou les signatures de sécurité) ainsi que le code HTML brut, permettant de détecter des liens masqués ou des scripts malveillants.

### Méthodologie : Accéder à la source (Exemple sous Thunderbird)

Pour extraire ces données techniques lors d'une analyse sur un fichier d'email (extension `.eml` ou `.msg`) :

1. Ouvrir le fichier d'email dans le client de messagerie (ex: *Thunderbird*).
2. Se rendre dans le menu **Affichage** (*View*).
3. Sélectionner **Code source du message** (*Message Source*).
4. *Raccourci universel :* `Ctrl + U`.

## 8. Le Corps de l'Email (*Email Body*) : Texte brut vs HTML

Le corps d'un email contient le message textuel destiné à la cible. Les serveurs de messagerie gèrent deux formats principaux pour l'affichage de ce contenu :

* **Le format Texte Brut (*Plain Text*) :** Contient uniquement des caractères alphanumériques sans aucune mise en forme (pas de gras, pas d'images, pas de liens masqués). C'est le format le plus sûr, car l'utilisateur voit exactement ce qui est écrit.
* **Le format HTML (*HTML Formatted*) :** Permet d'intégrer du style, des polices, des images et des hyperliens. C'est le format privilégié des attaquants, car il permet de dissimuler la destination réelle d'un lien derrière un texte légitime ou un bouton attrayant.

## 9. Analyse de la Source HTML et Détection des Pièges

La majorité des clients de messagerie modernes (comme *Thunderbird* ou *Outlook*) affichent par défaut la version interprétée (*Rendered HTML*). Pour des raisons de sécurité, ils bloquent souvent le téléchargement automatique des images distantes afin de protéger la vie privée de l'utilisateur et d'empêcher les attaquants de valider que la boîte mail est active.

L'examen du code source HTML brut (*Raw HTML*) permet à l'analyste de lever le voile sur plusieurs techniques de dissimulation :

```html
<a href="https://ant.anki-tech.com/ga/click/2-95262222...">Cliquez ici pour vérifier votre compte</a>

```

### Indicateurs à surveiller dans le code HTML :

1. **Divergence de liens :** Le texte du lien affiche une URL légitime (ex: `https://paypal.com`), mais l'attribut `href` pointe vers un domaine malveillant ou inconnu.
2. **Images distantes suspectes :** Balises `<img src="...">` pointant vers des serveurs externes éphémères, utilisées pour le suivi (*tracking*) ou l'exfiltration discrète de données.
3. **Faux formulaires :** Présence de balises `<form>` intégrées demandant directement des identifiants au sein de l'email.

## 10. Mécanismes et Reconstruction des Pièces Jointes

Les emails ne se limitent pas au texte ; ils transportent également des fichiers joints (documents, images, scripts). Contrairement aux systèmes de fichiers classiques, les pièces jointes dans un email ne sont pas stockées sous forme de fichiers séparés, mais sont **encodées en texte** directement au sein de la source brute du message.

Pour analyser une pièce jointe au niveau de la source, l'analyste doit identifier trois en-têtes MIME (*Multipurpose Internet Mail Extensions*) fondamentaux :

| En-tête de la pièce jointe | Rôle technique | Exemple concret |
| --- | --- | --- |
| **`Content-Type`** | Indique le type MIME et le format réel du fichier. | `application/pdf; name="Payment-updated.pdf"` |
| **`Content-Disposition`** | Spécifie que le fichier est une pièce jointe et définit son nom par défaut. | `attachment; filename="Payment-updated.pdf"` |
| **`Content-Transfer-Encoding`** | Indique la méthode d'encodage utilisée pour traduire le binaire en texte. | `base64` |

### Le Bloc de Données Base64

À la suite de ces en-têtes se trouve une longue chaîne de caractères alphanumériques apparemment aléatoires. Il s'agit du fichier binaire traduit en **Base64**.

> **Méthode d'investigation (Reconstruction) :** > Pour analyser un fichier suspect sans risquer d'infecter son poste de travail via le client mail, un analyste peut copier ce bloc de texte brut Base64 et utiliser un outil d'analyse (tel que **CyberChef** avec l'opération *From Base64*) afin de reconstruire le fichier d'origine dans un environnement sécurisé (Sandbox) pour en analyser la signature (MD5/SHA256).
Types of Phishing — traduction (conserver uniquement le côté théorique)

## 11. Types de phishing

Maintenant que nous comprenons comment les e-mails sont structurés et délivrés, il est important de reconnaître comment les attaquants abusent de ce système. Le courrier électronique reste l’un des vecteurs d’entrée les plus courants pour les cyberattaques, s’appuyant souvent sur l’ingénierie sociale pour tromper les utilisateurs et les inciter à agir.

Dans cette section, nous examinons les différents types d’e-mails malveillants et les techniques utilisées par les attaquants pour les faire paraître légitimes. En comprenant ces schémas, vous serez mieux à même d’identifier les messages suspects et d’éviter les pièges de phishing avant qu’ils ne compromettent vos systèmes. Les différents types d’e-mails malveillants peuvent être classés comme suit :

- Spam : E-mails non sollicités envoyés en masse à un grand nombre de destinataires. Une forme plus malveillante de spam est souvent appelée malspam.
- Phishing : E-mails se faisant passer pour une entité de confiance afin de tromper les destinataires et les pousser à divulguer des informations sensibles.
- Spear phishing : Forme ciblée de phishing visant une personne ou une organisation spécifique, utilisant souvent des informations personnalisées.
- Whaling : Type de spear phishing ciblant spécifiquement les cadres supérieurs (CEO, CFO) pour obtenir des données sensibles ou un accès financier.
- Smishing : Attaques de phishing menées via SMS ou messages texte, visant les utilisateurs sur appareils mobiles.
- Vishing : Attaques de phishing effectuées par appels vocaux, où les attaquants utilisent l’ingénierie sociale au téléphone.

### Anatomie d’un e-mail de phishing

Les attaquants utilisent souvent des techniques similaires quel que soit leur objectif (collecte d’identifiants, livraison de malware, accès non autorisé, etc.). Voici quelques caractéristiques communes des e-mails de phishing :

- Adresse d’expéditeur usurpée : l’adresse de l’expéditeur est falsifiée pour apparaître comme provenant d’une entité de confiance (ex. noreply@microsof.com).
- Objet ou message urgent : le message crée un sentiment d’urgence (« Votre compte sera verrouillé dans 24 heures »).
- Usurpation de marque : l’e-mail imite une organisation légitime (logos, couleurs similaires).
- Erreurs de grammaire et d’orthographe : le message peut contenir des fautes (bien que celles-ci soient moins fréquentes avec l’IA).
- Contenu générique : absence de personnalisation (« Cher client » au lieu de votre nom).
- Liens cachés ou raccourcis : les hyperliens dissimulent leur destination réelle (ex. bit.ly/secure-login).
- Pièces jointes malveillantes : pièces jointes déguisées en fichiers légitimes (ex. invoice.pdf.exe).

### Analyse sûre

Lors de l’analyse de liens et de pièces jointes, évitez de cliquer accidentellement. Les URL et adresses IP doivent être « défangées » pour les rendre non cliquables. La défangation consiste à remplacer certains caractères (comme @ ou .) par des caractères alternatifs :

- URL originale : http://www.suspiciousdomain.com
- URL défangée : hxxp[://]www[.]suspiciousdomain[.]com

 
---

# Les e-mails de phishing en action
Apprenez à repérer les différents indices d'une tentative de phishing en examinant de vrais e-mails malveillants.
> Source : Tryhackme Les e-mails de phishing en action : https://tryhackme.com/room/phishingemails2rytmuv

Après avoir appris à analyser les en-têtes et le corps des e-mails pour repérer les signaux d’alerte, nous passons à la pratique en examinant des exemples réels de phishing. Cette section met l’accent sur les tactiques employées par les attaquants pour reproduire des communications légitimes. L’analyse d’échantillons réels permet de discerner les nuances subtiles qui différencient une notification ordinaire d’une tentative sophistiquée de collecte d’identifiants. Attention : les exemples contiennent des informations issues de courriels réels ; ne pas interagir directement avec les adresses IP, domaines ou pièces jointes.

## Objectifs pratiques

- Identifier les tactiques d’ingénierie sociale courantes utilisées en phishing.
- Analyser les signaux d’alerte présents dans les e-mails de phishing.
- Détecter la manipulation de liens et la présence de pixels de suivi.
- Décomposer les techniques de collecte d’identifiants et de manipulation de pièces jointes.

Cancel Your Order — traduction (conserver uniquement le discours théorique/pratique)

## 1. Exemple : « Annulez votre commande »

### Objectif de l’analyse
Examiner un courriel se faisant passer pour un reçu de transaction (PayPal) afin de repérer : l’usurpation d’adresse, l’usage de services de raccourcissement d’URL pour masquer des liens malveillants, et l’imitation visuelle d’une marque.

Techniques de phishing observées
- Adresse expéditeur usurpée : imitation d’un service de confiance pour gagner en crédibilité.
- Raccourcissement d’URL : recours à des services de redirection pour dissimuler la destination réelle.
- HTML brandé : utilisation d’éléments visuels (logos, mise en page) imitant l’entreprise légitime.

Premières observations à relever
- Objet accrocheur créant un sentiment d’urgence (transaction fictive) pour provoquer une réaction rapide.
- Adresse "From" incohérente : le champ affiche service@paypal.com mais l’adresse réelle est gibberish@sultanbogor.com — signe d’usurpation.
- Destinataire inhabituel (domaine non standard) — indicateur supplémentaire de fraude.

Analyse du corps du message
- Présence d’un reçu indiquant l’achat de cartes cadeaux ; pas de pièces jointes.
- Élément interactif unique : bouton « Cancel the order » (Annuler la commande).

Analyse du bouton / liens
- Le bouton pointe vers une URL raccourcie, ce qui masque la destination finale.
- Règle pratique : ne jamais cliquer sur boutons ou liens sans vérifier la destination.
- Méthode sûre : examiner le code source de l’e-mail pour extraire l’URL raccourcie, puis utiliser un service d’analyse de redirections (par ex. WhereGoes) pour résoudre la destination sans y accéder directement.

## 2. Exemple : "Track Your Package"

Objectif de l’analyse
Examiner un faux avis d’expédition pour repérer l’usurpation d’adresse, la manipulation de liens et l’utilisation de pixels de suivi.

Techniques de phishing observées
- Adresse expéditeur usurpée : imitation d’un centre de distribution pour inspirer confiance.
- Pixel de suivi : inclusion d’images invisibles (1x1) qui notifient l’expéditeur quand l’e-mail est ouvert.
- Manipulation de lien : utilisation d’un numéro de suivi factice masquant une destination malveillante.

Premières observations à relever
- Objet accrocheur contenant un faux numéro de suivi pour créer un sentiment d’urgence et pousser l’utilisateur à cliquer.
- Champ From affiché (ex. « Distribution Center ») qui diffère de l’adresse réelle (ex. contact@beginpro.club) — indicateur d’usurpation.
- Le lien dans le corps correspond au numéro de suivi affiché, mais la destination réelle est inconnue tant qu’on n’a pas inspecté le code source.

Pourquoi les images sont bloquées automatiquement
- Les fournisseurs de messagerie bloquent souvent le chargement automatique des images pour empêcher les pixels de suivi de transmettre des informations (ouverture, adresse IP, user-agent) aux expéditeurs malveillants.

Analyse technique recommandée (procédure)
1. Ne pas autoriser le chargement automatique des images ni cliquer sur les liens.
2. Examiner l’en-tête complet pour comparer le nom d’affichage et l’adresse réelle de l’expéditeur.
3. Ouvrir le code source du message pour localiser :
   - les balises <img> suspectes (pixels de suivi) pointant vers des serveurs externes ;
   - les URL liées au numéro de suivi.
4. Défanger et extraire les URL puis résoudre les redirections via un outil d’analyse de liens (sans visiter la page).
5. Rechercher des incohérences : domaine d’envoi étranger, numéro de suivi non conforme au transporteur, ou liens menant vers domaines tiers.
6. Consigner les indicateurs (pixel détecté, usurpation, lien masqué) pour alerter ou bloquer la source.

Impact et usages des pixels de suivi
- Confirment qu’un destinataire a ouvert le message (valeur pour ciblage).
- Permettent de récolter métadonnées (heure d’ouverture, adresse IP, client mail).
- Souvent utilisés conjointement avec liens malveillants pour identifier cibles réactives et affiner campagnes.


---

# Outils d'analyse du phishing
Découvrez les outils essentiels qui aident un analyste à enquêter sur les e-mails suspectés d'hameçonnage.
> Source : Tryhackme : https://tryhackme.com/room/phishingemails3tryoe

---

# Prévention du phishing
Apprenez à vous défendre contre les e-mails de phishing.
> Source Tryhackme   : https://tryhackme.com/room/phishingemails4gkxh
