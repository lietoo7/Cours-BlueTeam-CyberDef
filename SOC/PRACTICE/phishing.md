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

## 1. Analyse d'en-têtes, de réputation d'adresses IP et d'URL.

### L'Automatisation de l'Analyse des En-têtes (*Mail Header Analysis*)

Bien que l'extraction manuelle des métadonnées directement depuis le code source brut d'un email soit une compétence fondamentale, ce processus peut s'avérer long et fastidieux lors d'investigations à grande échelle. Pour rationaliser et automatiser cette phase, les analystes en sécurité utilisent des outils d'analyse d'en-têtes. Ces solutions permettent d'extraire instantanément le chemin de routage, l'adresse IP d'origine de l'émetteur, ainsi que d'éventuelles erreurs de configuration de sécurité en y collant simplement l'en-tête brut.

Parmi les outils de référence gratuits, on retrouve :

* **Google Messageheader** *(intégré à la Google Admin Toolbox)* : Permet de cartographier rapidement le parcours de l'email de serveur en serveur et de mesurer les délais d'acheminement.
* **Message Header Analyzer** : Une solution alternative offrant des capacités d'analyse similaires pour décoder la structure technique des en-têtes de manière lisible.

### Analyse de Réputation : Adresses IP et Noms de Domaine

Une fois les indicateurs techniques (IoC) extraits des en-têtes (comme l'adresse IP du serveur émetteur), le défenseur doit évaluer la légitimité de l'infrastructure utilisée par l'expéditeur afin de déterminer si elle est liée à des activités cybercriminelles connues.

Plusieurs outils de Threat Intelligence (*Renseignement sur les menaces*) permettent de qualifier la dangerosité d'une adresse IP ou d'un domaine :

* **IPinfo :** Cet outil fournit la géolocalisation précise d'une adresse IP ainsi que le nom de l'organisation ou du fournisseur de services Internet (FAI / ASN) auquel elle appartient. Il aide à déceler les incohérences géographiques majeures par rapport à l'expéditeur légitime prétendu.
* **Cisco Talos IP & Domain Reputation Center :** Une plateforme de Threat Intelligence globale permettant de vérifier le score de réputation d'une IP, d'un domaine ou d'un réseau complet. Elle indique si l'indicateur soumis a déjà été classé comme malveillant ou s'il fait partie d'une liste noire active.

### Analyse de Réputation et Sandbox d'URL

L'investigation des hyperliens découverts dans le corps d'un email (ou cachés dans une pièce jointe) présente un risque de sécurité majeur : un analyste ne doit jamais cliquer directement sur un lien suspect depuis son poste de travail.

Pour contourner ce risque, on utilise des outils d'analyse d'URL à distance :

* **URLScan.io :** Cet outil agit comme une "Sandbox de navigation". Lorsqu'une URL lui est soumise, le service simule une session de navigation utilisateur réelle à partir d'un serveur distant sécurisé. Il enregistre l'intégralité des requêtes HTTP générées par la page, capture une capture d'écran du site rendu et analyse son comportement. Cela permet d'identifier la présence d'un portail de phishing ou d'un script malveillant sans jamais exposer l'infrastructure de l'entreprise.

*Règle d'or : Suivant les principes de la posture rigoureuse du consultant, cette suite théorique est désormais prête à être enrichie par des ateliers pratiques de manipulation de ces outils.*

## 2. Méthodologies d'extraction des URL et l'analyse de réputation des pièces jointes par hachage cryptographique.

### Analyse du Corps de l'Email et Extraction des URL

Le corps du message est l'espace où l'intention réelle de l'attaquant se matérialise. C'est là que sont positionnés les vecteurs d'infection ou de vol d'identifiants. L'extraction sécurisée des hyperliens est une étape clé de l'investigation pour identifier la destination finale d'une menace sans jamais s'y exposer.

Pour collecter les URL d'un email en toute sécurité, deux méthodes principales sont appliquées :

* **L'extraction manuelle ciblée :** Elle consiste à effectuer un clic droit sur le lien ou le bouton depuis le client de messagerie et à sélectionner l'option **Copier l'adresse du lien**. Cette manipulation permet de récupérer l'URL dans le presse-papiers afin de l'analyser textuellement ou de la soumettre à des outils de réputation, sans déclencher de session de navigation.
* **L'extraction automatisée globale :** Lorsque le message ou son code source HTML est particulièrement dense ou obscurci, l'analyste utilise des outils d'extraction d'URL (ou des scripts de parsing). En y collant le contenu brut de l'email, ces outils isolent et listent automatiquement l'intégralité des liens imbriqués, minimisant ainsi le risque d'omission. Le framework polyvalent **CyberChef** dispose également d'opérations dédiées à cette fonction de parsing.

### Gestion Sécurisée et Analyse des Pièces Jointes

Face à un email suspect contenant une pièce jointe, le téléchargement direct sur un poste de travail de production est une erreur critique. Le traitement d'un fichier potentiellement malveillant impose le respect d'un protocole strict.

> **Règle de manipulation :** > Tout téléchargement ou manipulation d'une pièce jointe suspecte doit s'effectuer exclusivement au sein d'un **environnement contrôlé et isolé**, tel qu'une machine virtuelle (VM) dédiée à l'analyse ou une Sandbox, afin de neutraliser tout risque d'exécution accidentelle sur le réseau de l'entreprise.

### Analyse par Empreinte Numérique (Hachage)

Une fois le fichier isolé en environnement sécurisé, la méthode la plus rapide et la plus sûre pour l'analyser consiste à calculer son **empreinte cryptographique** (ou *hash*). Le hachage génère un identifiant unique pour le fichier. Si le fichier est un malware connu, son empreinte aura déjà été répertoriée par la communauté de la cybersécurité.

### Génération d'un Hash sous Linux

Dans un terminal Linux, l'analyste utilise généralement la commande `sha256sum` pour générer l'empreinte SHA-256 du fichier :

```bash
user@tryhackme$ sha256sum shady_attachment.pdf
025ba9ce4a2118a9ca7b115c8869ff73bc16bad3732ba359cef1e60ad8f961f9  shady_attachment.pdf

```
### Qualification de la Menace via les Plateformes de Réputation

Une fois le hash obtenu, il n'est pas nécessaire de téléverser le fichier réel sur Internet. Il suffit de soumettre cette chaîne de caractères (le hash) aux plateformes de Threat Intelligence pour vérifier si le fichier a déjà été identifié comme malveillant.

### Les Outils de Référence :

* **Cisco Talos IP & Domain Reputation Center :** Permet de soumettre des empreintes de fichiers (hashes) pour obtenir leur classification immédiate (ex: labellisé comme *Phishing*, *Malicious*, ou *Spam*).
* **VirusTotal :** C'est l'un des agrégateurs les plus puissants du secteur. Il centralise les analyses de dizaines de moteurs antivirus et de fournisseurs de sécurité du marché. En y soumettant un hash, une URL, ou une adresse IP, l'analyste obtient instantanément un rapport de détection détaillé. Si le hash est inconnu, la plateforme permet également de téléverser le fichier pour une analyse dynamique en temps réel. 

## 3. L'Analyse Dynamique via les Bacs à Sable (*Malware Sandboxes*)

Lorsqu'une pièce jointe suspecte n'est pas répertoriée sur les plateformes de réputation globales (son hash SHA-256 est inconnu), l'analyste doit étudier son comportement réel. Heureusement, il n'est pas nécessaire de posséder des compétences avancées en ingénierie inverse (*Reverse Engineering*) pour comprendre les intentions d'un fichier malveillant.

Les défenseurs utilisent des **bacs à sable** (*Malware Sandboxes*), des environnements virtuels isolés et sécurisés conçus pour exécuter les fichiers suspects afin d'observer et de cartographier leurs actions en temps réel, sans aucun risque pour l'infrastructure de l'entreprise.

### Objectifs de l'analyse en Sandbox

L'exécution contrôlée d'un fichier permet de collecter de précieux Indicateurs de Compromission (IoC) :

* **Activité Réseau :** Identifier les adresses IP et les URL distantes que le fichier tente de contacter (serveurs de commande et de contrôle - *C2*).
* **Téléchargements de charges utiles :** Détecter si le fichier initial sert de compte-gouttes (*Dropper*) pour installer d'autres malwares.
* **Modifications Système :** Suivre la création de processus suspects, les modifications dans la base de registre ou les tentatives d'altération de fichiers système.

### Les Solutions de Sandbox de Référence

Le marché de la Git-Defensive propose plusieurs plateformes cloud reconnues permettant d'automatiser ces analyses :

### ANY.RUN (L'analyse interactive)

**ANY.RUN** se distingue par son approche **interactive en temps réel**. Contrairement aux systèmes automatisés classiques, il permet à l'analyste d'interagir directement avec le système d'exploitation virtuel (cliquer sur des fenêtres, valider des invites de commande, ouvrir des fichiers).

* *Avantage majeur :* Idéal pour déjouer les techniques d'évasion des malwares qui attendent une action humaine (un clic de l'utilisateur) pour déclencher leur charge utile.

### Hybrid Analysis

**Hybrid Analysis** est une solution gratuite combinant l'analyse statique (examen du code sans exécution) et l'analyse dynamique. Propulsée par la technologie Falcon Sandbox (CrowdStrike), elle fournit des rapports extrêmement détaillés sur l'évaluation des risques, les modifications de fichiers et le comportement réseau global de l'échantillon soumis.

### JOE Sandbox (L'analyse approfondie)

Développé par JOE Security, **JOE Sandbox** est un outil haut de gamme orienté vers l'analyse avancée et automatisée de fichiers et d'URL sur plusieurs systèmes d'exploitation (Windows, macOS, Linux, Android).

* *Avantage majeur :* Génère des rapports d'expertise complets incluant la classification précise des menaces selon la matrice MITRE ATT&CK et la détection approfondie des comportements d'évasion complexes.

## 3. Plateformes d'orchestration d'investigation 

### Centralisation et Orchestration de l'Analyse : L'écosystème PhishTool

L'analyse de phishing moderne nécessite l'usage combiné de multiples sources de données (données d'en-tête, réputation d'URL, hachage de fichiers, OSINT, Threat Intelligence). Pour éviter la dispersion des données et accélérer la prise de décision, les analystes SOC *(Security Operations Center)* et les chasseurs de menaces utilisent des plateformes de tri centralisées comme **PhishTool**.

Ces outils automatisent la majeure partie du travail forensique manuel en regroupant l'ensemble des artefacts au sein d'une interface d'analyse unique.

### Identification et Visualisation des Artefacts

Lorsqu'un fichier d'email suspect (`.eml` ou `.msg`) est téléversé dans la plateforme, le système extrait et segmente automatiquement les composants essentiels afin de fournir plusieurs niveaux de lecture simultanés :

* **La vue HTML interprétée (*Rendered HTML view*) :** Restitue l'affichage exact du message tel que la victime l'a perçu dans sa boîte de réception, permettant d'évaluer l'efficacité de l'ingénierie sociale (logos, charte graphique).
* **La vue HTML brute (*Raw HTML*) :** Isole le code source de mise en forme pour inspecter la structure des balises, les redirections dissimulées et les attributs de liens suspectés.
* **Le code source complet (*Message Source*) :** Donne un accès direct à l'intégralité des en-têtes techniques et des blocs de données Mime non interprétés.

### Analyse Approfondie et Intégration de Threat Intelligence

La plateforme organise l'investigation à travers différents onglets techniques dédiés à des vérifications spécifiques :

* **Résultats d'Authentification (*Authentication results*) :** Permet de contrôler instantanément la validité des protocoles de sécurité de l'email (validation SPF, DKIM, DMARC) afin de détecter les tentatives d'usurpation de domaine.
* **Chemins de Transmission (*Transmission paths*) :** Cartographie le routage de l'email à travers les différents serveurs de relais (sauts de serveurs) pour identifier le point d'injection initial.
* **Inspection des Liens et Fichiers :** Analyse de manière isolée les URL imbriquées et les pièces jointes présentes.

### L'Intégration Pivot (Exemple : VirusTotal)

L'un des atouts majeurs de ces plateformes d'orchestration réside dans leur capacité à interroger des API tierces. L'intégration native avec des services comme **VirusTotal** permet à l'analyste de consulter les scores de détection et la réputation d'un composant (IP, domaine, hash de fichier) directement depuis l'interface de tri, sans rupture de flux de travail (*workflow*).

### Résolution de l'Incident et Clôture du Cas (*Case Closure*)

La phase finale de la méthodologie d'analyse de phishing suit un processus rigoureux d'archivage et de remédiation, calqué sur les exigences réelles d'un environnement SOC :

1. **Qualification de la menace :** Une fois les preuves techniques accumulées, l'analyste qualifie formellement la nature du message (ex: marquage comme *Malicieux*, *Spam*, ou *Bénin*).
2. **Signalement des artefacts (Flagging) :** Les indicateurs de compromission validés durant l'exercice (adresses de l'expéditeur, adresses IP d'origine, URL frauduleuses) sont marqués et indexés.
3. **Documentation forensique :** Rédaction de notes d'investigation claires détaillant le comportement de la menace, les actions menées, et les éventuels postes de travail ayant interagi avec le message.
4. **Clôture (Resolve) :** Le dossier est clôturé. Les IoC ainsi documentés alimentent les listes de blocage de l'organisation (moteurs de filtrage, pare-feux, EDR) afin de neutraliser définitivement la campagne d'attaque.

---

# Prévention du phishing
Apprenez à vous défendre contre les e-mails de phishing.
> Source Tryhackme   : https://tryhackme.com/room/phishingemails4gkxh
