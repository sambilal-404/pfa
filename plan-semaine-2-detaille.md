# Plan Detaille - Sprint 2 (2 semaines) : Rattrapage apres 2 semaines d'absence

**Projet :** Detection Automatisee d'Anomalies dans les APIs REST
**Membre :** Bilal SAMMER (Detection Engine)
**Equipe :** Bilal, Mouad, Hamza, Ayoub
**Encadrant :** Pr Y.REGAD (y.regad@ump.ac.ma)
**Date projet :** Demarre le 12/03/2026
**Frequence sprint :** 2 semaines (compte rendu "sprint review" chaque 2 semaines)
**Situation actuelle :** 2 semaines sans activite. Sprint 1 (Cadrage) probablement incomplet. Sprint 2 doit demarrer immediatement.

---

## Etat des lieux : ce qui aurait du etre fait

### Sprint 1 (12/03 - 25/03) — Cadrage & CdC (2 semaines)

| Tache | Responsable | Statut probable | Urgence |
|-------|-------------|-----------------|---------|
| Etablir le Cahier des Charges | Bilal | Non fait | CRITIQUE |
| Charte de Projet | Mouad | Non fait | HAUTE |
| Contrats & conventions | Hamza | Non fait | MOYENNE |
| Matrice SWOT | Ayoub | Non fait | MOYENNE |
| Matrice RACI | Bilal | Non fait | HAUTE |
| Mise en place outils communication | Mouad | Non fait | HAUTE |

### Sprint 2 (26/03 - 08/04) — Recherche & Debut Conception (2 semaines)

Les actions prevues pour le Sprint 2 etaient :
1. **Bilal** : Implementation Python des 50 regles de detection + Rate Limiting
2. **Mouad** : Documentation OWASP API Top 10 + 100 premiers payloads SQLi
3. **Hamza** : Collecte dataset + script extraction features
4. **Ayoub** : Setup FastAPI + schema PostgreSQL + Dockerfile

---

## Plan de rattrapage Sprint 2 — Jour par jour (14 jours)

> Objectif : Rattraper le retard du Sprint 1 ET livrer le Sprint 2 complet.
> Frequence : Sprint de 2 semaines. Sprint review a fournir le 08/04.
> Temps de travail estime : 3-4 heures par jour minimum.

---

### JOUR 1 : Urgences administratives + Remise en contexte

**Duree totale : 4h**

#### Bloc 1 — Communication equipe (30 min)

- [ ] Envoyer un message au groupe WhatsApp/Discord pour faire le point
- [ ] Demander a chaque membre ou il en est sur ses taches Sprint 1
- [ ] Fixer une reunion rapide (meme 15 min en vocal) pour se synchroniser
- [ ] Verifier si le professeur a envoye des messages ou des deadlines

**Ressources :**
- Groupe WhatsApp/Discord de l'equipe
- Email du professeur : y.regad@ump.ac.ma

#### Bloc 2 — Finaliser le Cahier des Charges (2h)

Le CdC est le livrable le plus critique. Il doit contenir :

1. **Page de garde** : Titre du PFA, noms des membres, encadrant, date
2. **Contexte et problematique** (deja redige dans `compte-rendu-01.md`) :
   > "Les APIs REST sont devenues la surface d'attaque numero 1. Les WAFs traditionnels generent ~70% de faux positifs. Notre systeme combine fuzzing + detection 3 couches + ML pour reduire les FP a ~10%."
3. **Objectifs du projet** :
   - Concevoir un moteur de fuzzing automatise (Mouad)
   - Construire un Detection Engine hybride a 3 couches (Bilal)
   - Entrainer un classificateur ML (Hamza)
   - Integrer le tout dans une plateforme web (Ayoub)
4. **Perimetre fonctionnel** : Les 5 Epics du Product Backlog
5. **Stack technique** : Python, FastAPI, React, PostgreSQL, Docker, XGBoost
6. **Planning previsionnel** : Les 5 phases (11 sprints de 2 semaines, ~5 mois)
7. **Livrables attendus** : Plateforme, dataset, modele ML, rapport comparatif, 50 regles, 500+ payloads

**Ressources :**
- Fichier `compte-rendu-01.md` (contient deja le contexte, SWOT, backlog, RACI)
- Fichier `notes-essentielles.md` (contient l'architecture, les roles, le planning)
- Google Docs pour la redaction collaborative
- Template CdC : chercher "template cahier des charges projet informatique" sur Google

#### Bloc 3 — Finaliser la matrice RACI (30 min)

La matrice RACI est deja redigee dans `compte-rendu-01.md` (lignes 228-244). Il faut :
- [ ] La copier dans l'onglet "La matrice RACI" du fichier `Suivi de Projet (PFA).xlsx`
- [ ] Verifier que chaque tache a un seul A (Approbateur)
- [ ] S'assurer que la Tache 9 (Integration) a bien tout le monde en R

**Ressources :**
- Fichier `Suivi de Projet (PFA).xlsx` (fourni par le professeur)
- Fichier `compte-rendu-01.md` (section Matrice RACI)

#### Bloc 4 — Remplir le fichier Excel de suivi (1h)

Le professeur exige que 6 onglets soient remplis dans `Suivi de Projet (PFA).xlsx` :

| Onglet | Contenu a remplir | Source |
|--------|-------------------|--------|
| 1. Tableau de Bord | Date MaJ, nb personnes (4), budget (15 150 MAD), phase actuelle (CdC), avancement (~5%) | `compte-rendu-01.md` lignes 177-187 |
| 2. Product Backlog | Les 15 taches (GP1-GP6 + Tache 1-9) avec etat, priorite, dates, responsable | `compte-rendu-01.md` lignes 85-106 |
| 3. Kanban | Dispatcher les taches dans A faire / En cours / Termine pour chaque membre | `compte-rendu-01.md` lignes 196-203 |
| 4. Matrice RACI | Copier la matrice R/A/C/I | `compte-rendu-01.md` lignes 228-244 |
| 5. SWOT | Forces, Faiblesses, Opportunites, Menaces | `compte-rendu-01.md` lignes 26-54 |
| 6. Table des Documents | Liste des 13 livrables avec liens Google Drive | `compte-rendu-01.md` lignes 253-266 |

**Ressources :**
- Fichier Excel `Suivi de Projet (PFA).xlsx`
- Microsoft Excel ou Google Sheets
- Toutes les donnees sont dans `compte-rendu-01.md`

---

### JOUR 2 : Apprentissage fondamental — WAF + OWASP

**Duree totale : 3h30**

#### Bloc 1 — Comprendre les WAFs (45 min)

- [ ] Lire l'article Cloudflare sur les WAFs
- [ ] Comprendre Whitelist vs Blacklist
- [ ] Retenir le probleme des faux positifs

**Ressources :**
| Ressource | URL | Temps |
|-----------|-----|-------|
| Cloudflare - What is a WAF? | https://www.cloudflare.com/learning/ddos/glossary/web-application-firewall-waf/ | 30 min |
| Wikipedia - Web Application Firewall | https://en.wikipedia.org/wiki/Web_application_firewall | 15 min |

**Notes a retenir :**
> Un WAF filtre le traffic HTTP entre client et serveur. Deux approches : whitelist (autoriser le connu) vs blacklist (bloquer le malveillant). Probleme : taux eleve de faux positifs (~70%). Notre projet reduit ca grace au ML.

#### Bloc 2 — OWASP Top 10 Web + API (1h30)

- [ ] Lire le OWASP Top 10 Web (focus sur A01, A03, A05)
- [ ] Lire le OWASP API Security Top 10 (focus sur BOLA, Rate Limiting, Injection)

**Ressources :**
| Ressource | URL | Temps |
|-----------|-----|-------|
| OWASP Top 10 (2021) | https://owasp.org/www-project-top-ten/ | 45 min |
| OWASP API Security Top 10 (2023) | https://owasp.org/API-Security/editions/2023/en/0x11-t10/ | 45 min |
| Video explicative OWASP Top 10 | Chercher "OWASP Top 10 explained" sur YouTube (NetworkChuck ou Computerphile) | Optionnel |

**Les 3 attaques fondamentales a maitriser :**

| Attaque | Definition | Exemple |
|---------|-----------|---------|
| **Injection (A03)** | Envoyer du code malveillant au lieu de donnees | `' OR '1'='1` dans un champ login |
| **BOLA (API #1)** | Acceder aux donnees d'un autre utilisateur | `GET /api/users/42` alors que tu es user 7 |
| **Rate Limiting absent (API #4)** | Pas de limite de requetes = brute force possible | 10 000 tentatives de mot de passe en 1 minute |

#### Bloc 3 — Restitution active (15 min)

- [ ] Fermer tous les onglets
- [ ] Ecrire de memoire sur papier : "Mon role dans le PFA en 3 phrases"
- [ ] Verifier avec le fichier `bilal-plan-semaine.md`

**Ce que tu dois pouvoir dire :**
> "Je construis le Detection Engine qui analyse le traffic API en temps reel. J'utilise 3 couches : regex pour les attaques connues, rate limiting pour le volume, et anomaly detection pour les attaques inconnues. Mon moteur genere des alertes que le ML de Hamza filtre pour reduire les faux positifs."

---

### JOUR 3 : Pratique intensive — Regex et Pattern Matching

**Duree totale : 3h30**

#### Bloc 1 — Bases des Regex (30 min)

Les symboles critiques a connaitre :

| Symbole | Signification | Exemple |
|---------|--------------|---------|
| `.` | N'importe quel caractere | `a.c` matche "abc", "a1c" |
| `*` | 0 ou plus repetitions | `ab*c` matche "ac", "abc", "abbc" |
| `+` | 1 ou plus repetitions | `ab+c` matche "abc", "abbc" mais PAS "ac" |
| `[]` | Classe de caracteres | `[a-z]` matche une lettre minuscule |
| `\|` | OU logique | `cat\|dog` matche "cat" ou "dog" |
| `\b` | Limite de mot | `\bSELECT\b` matche "SELECT" mais pas "SELECTED" |
| `\s` | Espace/whitespace | `\s+` matche un ou plusieurs espaces |
| `\d` | Chiffre | `\d{3}` matche "123", "456" |
| `\w` | Lettre/chiffre/underscore | `\w+` matche un mot |
| `(?i)` | Case insensitive | `(?i)select` matche "SELECT", "Select" |

**Ressources :**
| Ressource | URL | Temps |
|-----------|-----|-------|
| Regex101 (bac a sable interactif) | https://regex101.com | Toute la session |
| RegexOne (tutoriel interactif) | https://regexone.com | 20 min |
| Regex Cheat Sheet | https://quickref.me/regex | Reference |

#### Bloc 2 — Lab pratique : ecrire des regex de detection (2h)

Ouvrir https://regex101.com et coller ces 6 requetes dans la zone de test :

```
GET /api/users?id=1
GET /api/users?id=1' OR '1'='1
GET /api/users?id=1 UNION SELECT * FROM passwords--
POST /login avec body: {"user": "<script>alert(1)</script>"}
GET /files?path=../../../etc/passwd
GET /api/users?id=1; DROP TABLE users--
```

**Exercice 1 — SQL Injection** (objectif : detecter les lignes 2, 3, 6)
```regex
(\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER)\b)|('(\s)*(OR|AND)(\s)*')|(--)|(;)
```

**Exercice 2 — XSS** (objectif : detecter la ligne 4)
```regex
(<script[^>]*>)|(javascript:)|(on\w+\s*=)
```

**Exercice 3 — Path Traversal** (objectif : detecter la ligne 5)
```regex
(\.\./|\.\.\\)
```

**Exercice 4 — Command Injection**
```regex
(;|\||\$\(|`).*(\b(ls|cat|rm|wget|curl|bash|sh|nc)\b)
```

- [ ] Tester chaque regex sur regex101.com
- [ ] Verifier que la requete 1 (legitime) n'est PAS detectee
- [ ] Comprendre pourquoi chaque partie de la regex fonctionne
- [ ] Essayer de modifier les regex et observer les effets

**Ressources complementaires :**
| Ressource | URL | Usage |
|-----------|-----|-------|
| OWASP Regex Validation Cheatsheet | https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html | Patterns avances |
| PayloadsAllTheThings (GitHub) | https://github.com/swisskyrepo/PayloadsAllTheThings | Exemples de payloads reels |
| HackTricks SQLi | https://book.hacktricks.wiki/en/pentesting-web/sql-injection/index.html | Comprendre SQLi en profondeur |

#### Bloc 3 — Synthese Pattern Matching (30 min)

- [ ] Ecrire de memoire les 4 regex (SQLi, XSS, Path Traversal, Command Injection)
- [ ] Formuler a voix haute :

> "Le Pattern Matching utilise des expressions regulieres pour chercher des signatures d'attaques connues dans les requetes HTTP. Par exemple, la presence de 'UNION SELECT' dans un parametre indique une tentative de SQL Injection. C'est rapide et efficace pour les attaques connues, mais ne detecte pas les attaques nouvelles ou obfusquees."

---

### JOUR 4 : Rate Limiting + Anomaly Detection

**Duree totale : 3h30**

#### Bloc 1 — Rate Limiting (1h)

**3 algorithmes a connaitre :**

| Algorithme | Comment ca marche | Avantage | Inconvenient |
|------------|-------------------|----------|--------------|
| **Fixed Window** | Compteur qui se reset a chaque minute fixe | Simple | Attaquant peut envoyer 200 req en 2 secondes aux frontieres |
| **Sliding Window** | Fenetre qui glisse en temps reel | Precis, pas de pics | Plus complexe a implementer |
| **Token Bucket** | Seau de jetons, 1 jeton = 1 requete, jetons se remplissent progressivement | Gere les bursts | Un peu plus complexe |

**Exemple concret Fixed Window vs Sliding Window :**

```
FIXED WINDOW (probleme) :
  Fenetre 1 : 12:00:00 - 12:00:59 -> Limite 100 req
  12:00:55 -> 99 requetes envoyees -> OK
  12:01:00 -> Compteur reset a 0
  12:01:01 -> 100 requetes envoyees -> OK
  = 199 requetes en 6 secondes! Limite contournee.

SLIDING WINDOW (solution) :
  A tout moment, on regarde les 60 dernieres secondes
  12:01:01 -> On compte de 12:00:01 a 12:01:01
  -> 99 + 100 = 199 -> BLOQUE (depasse 100)
```

**Ressources :**
| Ressource | URL | Temps |
|-----------|-----|-------|
| Rate Limiting Algorithms (blog) | Chercher "rate limiting algorithms explained blog" sur Google | 30 min |
| Cloudflare - What is Rate Limiting? | https://www.cloudflare.com/learning/bots/what-is-rate-limiting/ | 15 min |
| Video : Rate Limiting System Design | Chercher "rate limiting system design" sur YouTube (ByteByteGo) | 15 min |
| Redis Rate Limiting (optionnel) | https://redis.io/glossary/rate-limiting/ | Optionnel |

#### Bloc 2 — Anomaly Detection / Detection d'anomalies (1h30)

**Principe fondamental :**
1. Definir un "comportement normal" (baseline) a partir de donnees historiques
2. Calculer la moyenne et l'ecart-type de chaque metrique
3. Si une requete depasse `moyenne + 3 * ecart-type` -> anomalie (regle des 3 sigma)

**Calcul a maitriser :**

```
Exemple : Longueur d'URL
  Donnees normales : [35, 42, 50, 38, 55, 40, 48, 45, 52, 43]
  Moyenne = 44.8 caracteres
  Ecart-type = 6.3 caracteres
  Seuil (3-sigma) = 44.8 + 3 * 6.3 = 63.7 caracteres

  Requete avec URL de 200 caracteres -> 200 > 63.7 -> ANOMALIE DETECTEE
```

**Metriques a surveiller :**

| Metrique | Valeur normale | Valeur suspecte | Pourquoi |
|----------|---------------|-----------------|----------|
| Longueur URL | 30-80 car | > 200 car | Payload long = injection probable |
| Nombre de parametres | 1-5 | > 15 | Trop de params = scanning |
| Taille du body | 100-1000 bytes | > 10000 bytes | Body enorme = payload cache |
| Entropie | 3-4 bits | > 6 bits | Entropie elevee = donnees encodees/obfusquees |
| Caracteres speciaux | 0-5 | > 20 | Beaucoup de speciaux = payload suspect |

**Entropie — explication simple :**
- Mesure du "desordre" ou "hasard" dans une chaine de caracteres
- `"hello world"` -> entropie ~3.2 (lettres repetees, mots normaux)
- `"x7$kQ9!mZ@2"` -> entropie ~3.9 (caracteres aleatoires)
- Un payload encode (Base64, URL-encode) a une entropie elevee
- Seuil recommande : > 5.0 bits -> suspect

**Ressources :**
| Ressource | URL | Temps |
|-----------|-----|-------|
| 3-Sigma Rule (Wikipedia) | https://en.wikipedia.org/wiki/68%E2%80%9395%E2%80%9399.7_rule | 15 min |
| Shannon Entropy explained | Chercher "shannon entropy explained simply" sur Google | 20 min |
| Anomaly Detection intro | Chercher "anomaly detection for beginners" sur YouTube | 30 min |
| Scikit-learn Anomaly Detection | https://scikit-learn.org/stable/modules/outlier_detection.html | Reference |

#### Bloc 3 — Dessiner le flux (30 min)

- [ ] Prendre un papier et dessiner le flux d'une requete HTTP :

```
Requete HTTP entrante
        |
        v
  [Couche 1: Pattern Matching]
  La requete contient "UNION SELECT"?
        |            |
       OUI          NON
        |            |
   BLOQUER      [Couche 2: Rate Limiting]
                Meme IP > 100 req/min?
                     |            |
                    OUI          NON
                     |            |
                BLOQUER      [Couche 3: Anomaly Detection]
                             URL > seuil 3-sigma?
                             Entropie > 5.0?
                                  |            |
                                 OUI          NON
                                  |            |
                             SUSPECT      AUTORISER
                                  |
                                  v
                         [ML Classifier (Hamza)]
                         Vraie attaque ou faux positif?
```

---

### JOUR 5 : Documentation des 50 regles de detection

**Duree totale : 4h**

C'est le livrable principal de Bilal : un fichier structure avec 50 regles documentees.

#### Bloc 1 — Regles de Signature / Pattern Matching (20 regles) — 1h30

| # | Pattern (Regex) | Attaque detectee | Severite | Exemple de payload |
|---|----------------|------------------|----------|-------------------|
| 1 | `\bUNION\s+SELECT\b` | SQL Injection | HIGH | `1 UNION SELECT * FROM users` |
| 2 | `'\s*(OR\|AND)\s*'` | SQL Injection (Auth Bypass) | HIGH | `' OR '1'='1` |
| 3 | `;\s*DROP\s+TABLE\b` | SQL Injection (Destructif) | CRITICAL | `; DROP TABLE users--` |
| 4 | `'\s*;\s*--` | SQL Injection (Comment) | HIGH | `admin';--` |
| 5 | `\bINSERT\s+INTO\b` | SQL Injection (Insert) | HIGH | `INSERT INTO admin VALUES(...)` |
| 6 | `\bUPDATE\s+\w+\s+SET\b` | SQL Injection (Update) | HIGH | `UPDATE users SET role='admin'` |
| 7 | `\bDELETE\s+FROM\b` | SQL Injection (Delete) | CRITICAL | `DELETE FROM users WHERE 1=1` |
| 8 | `\bALTER\s+TABLE\b` | SQL Injection (Alter) | CRITICAL | `ALTER TABLE users ADD col` |
| 9 | `\bEXEC(\s\|UTE)?\b` | SQL Injection (Exec) | CRITICAL | `EXEC xp_cmdshell('dir')` |
| 10 | `\bSLEEP\s*\(\d+\)` | SQL Injection (Time-based blind) | HIGH | `SLEEP(5)` |
| 11 | `<script[^>]*>` | XSS (Script tag) | HIGH | `<script>alert(1)</script>` |
| 12 | `javascript\s*:` | XSS (Protocol) | MEDIUM | `javascript:alert(1)` |
| 13 | `on\w+\s*=` | XSS (Event handler) | HIGH | `onerror=alert(1)` |
| 14 | `<img\s+[^>]*src\s*=\s*x\s+onerror` | XSS (Img tag) | HIGH | `<img src=x onerror=alert(1)>` |
| 15 | `<iframe[^>]*>` | XSS (Iframe) | HIGH | `<iframe src="evil.com">` |
| 16 | `\.\./` ou `\.\.\\` | Path Traversal | HIGH | `../../../etc/passwd` |
| 17 | `\.\.\%2[fF]` | Path Traversal (URL-encoded) | HIGH | `..%2f..%2fetc/passwd` |
| 18 | `;\s*\b(cat\|ls\|rm\|wget\|curl)\b` | Command Injection (semicolon) | CRITICAL | `; cat /etc/passwd` |
| 19 | `\|\s*\b(bash\|sh\|nc\|ncat)\b` | Command Injection (pipe) | CRITICAL | `\| bash -i` |
| 20 | `` `[^`]*` `` | Command Injection (backtick) | HIGH | `` `whoami` `` |

#### Bloc 2 — Regles Comportementales (15 regles) — 1h

| # | Condition | Attaque detectee | Severite | Seuil |
|---|-----------|------------------|----------|-------|
| 21 | > 100 req/min meme IP | Brute Force | HIGH | 100 req/min |
| 22 | > 10 echecs login consecutifs meme IP | Account Takeover | HIGH | 10 echecs |
| 23 | > 50 endpoints differents/min meme IP | Scanning/Enumeration | MEDIUM | 50 endpoints/min |
| 24 | Acces /admin ou /debug sans auth | Unauthorized Access | CRITICAL | 0 tolerance |
| 25 | > 5 requetes sur /login en < 10 sec | Credential Stuffing | HIGH | 5 req/10s |
| 26 | Requetes a heures anormales (2h-5h) hors pattern habituel | Anomalie temporelle | LOW | Hors baseline |
| 27 | > 1000 req/min meme IP | DDoS applicatif | CRITICAL | 1000 req/min |
| 28 | Changement de User-Agent > 5 fois/min meme IP | Bot evasion | MEDIUM | 5 UA/min |
| 29 | > 20 requetes 404 consecutives | Directory Bruteforce | MEDIUM | 20 x 404 |
| 30 | Requetes avec methodes inhabituelles (TRACE, OPTIONS en masse) | Method probing | LOW | > 10/min |
| 31 | > 10 tentatives acces a des IDs sequentiels (1, 2, 3...) | BOLA / IDOR | HIGH | 10 IDs sequentiels |
| 32 | Upload de fichier > 10MB | Oversized payload | MEDIUM | 10 MB |
| 33 | Requetes sans header User-Agent | Bot probable | LOW | Absence UA |
| 34 | Meme requete exacte repetee > 50 fois | Replay Attack | MEDIUM | 50 repetitions |
| 35 | > 3 IP differentes avec meme session cookie | Session Hijacking | CRITICAL | 3 IPs/session |

#### Bloc 3 — Regles Statistiques (15 regles) — 1h

| # | Metrique mesuree | Condition d'alerte | Severite | Methode |
|---|-----------------|-------------------|----------|---------|
| 36 | Longueur URL | > baseline + 3*sigma | MEDIUM | 3-sigma |
| 37 | Nombre de parametres GET | > baseline + 3*sigma | MEDIUM | 3-sigma |
| 38 | Taille du body POST | > baseline + 3*sigma | LOW | 3-sigma |
| 39 | Entropie du payload | > 5.0 bits | MEDIUM | Shannon entropy |
| 40 | Nombre caracteres speciaux dans URL | > 20 | MEDIUM | Seuil fixe |
| 41 | Ratio chiffres/lettres dans parametres | > 0.8 | LOW | Seuil fixe |
| 42 | Nombre de headers HTTP | > baseline + 3*sigma | LOW | 3-sigma |
| 43 | Taille totale des headers | > baseline + 3*sigma | LOW | 3-sigma |
| 44 | Longueur valeur d'un seul parametre | > 500 car | MEDIUM | Seuil fixe |
| 45 | Profondeur du JSON body | > 10 niveaux | MEDIUM | Seuil fixe |
| 46 | Nombre de cles dans JSON body | > baseline + 3*sigma | LOW | 3-sigma |
| 47 | Variance du temps entre requetes (meme IP) | < 0.01 sec (trop regulier = bot) | MEDIUM | Variance |
| 48 | Frequence de caracteres non-ASCII | > 30% du total | HIGH | Ratio |
| 49 | Longueur du cookie | > baseline + 3*sigma | LOW | 3-sigma |
| 50 | Score composite (somme ponderee regles 36-49) | > seuil composite | HIGH | Score |

#### Bloc 4 — Mise en forme (30 min)

- [ ] Creer un fichier `detection_rules.json` ou `detection_rules.py` propre
- [ ] Chaque regle doit avoir : `id`, `type`, `pattern/condition`, `severity`, `description`, `example`
- [ ] Sauvegarder sur le Google Drive dans le dossier "Dossier PFA"

**Ressources pour les regles :**
| Ressource | URL | Usage |
|-----------|-----|-------|
| ModSecurity Core Rule Set | https://github.com/coreruleset/coreruleset | Regles WAF open-source de reference |
| OWASP CRS Regex | https://github.com/coreruleset/coreruleset/tree/main/rules | Regex de detection professionelles |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings | Payloads pour tester les regles |
| SecLists | https://github.com/danielmiessler/SecLists | Listes de fuzzing et payloads |

---

### JOUR 6 : Comparaison avec Cloudflare WAF + Preparation presentation

**Duree totale : 3h30**

#### Bloc 1 — Comprendre Cloudflare WAF (1h)

**Comment Cloudflare fonctionne :**
- Cloudflare est un **reverse proxy** : le trafic passe par Cloudflare AVANT d'atteindre ton serveur
- Il utilise des **regles generiques** (OWASP CRS + regles proprietaires)
- Grande base de regles mise a jour en temps reel
- Protection DDoS integree

**Ses faiblesses (notre proposition de valeur) :**
- **Faux positifs eleves (~40-70%)** : regles generiques pas adaptees a chaque API
- **Pas de contexte metier** : Cloudflare ne sait pas ce qui est "normal" pour TON API
- **Regles statiques** : ne s'adapte pas au comportement specifique des utilisateurs
- **Cout** : solution payante pour les fonctionnalites avancees

**Notre avantage :**
- Le Detection Engine (Bilal) genere des alertes
- Le ML Classifier (Hamza) apprend le contexte specifique de l'API
- Resultat : faux positifs de 40% -> 10%

**Ressources :**
| Ressource | URL | Temps |
|-----------|-----|-------|
| Cloudflare WAF documentation | https://developers.cloudflare.com/waf/ | 30 min |
| Cloudflare vs ModSecurity | Chercher "cloudflare waf vs modsecurity comparison" | 15 min |
| WAF Bypass Techniques (pour comprendre les limites) | Chercher "waf bypass techniques owasp" | 15 min |

#### Bloc 2 — Preparer la methodologie de comparaison (1h)

**Protocole de test prevu :**

```
Etape 1 : Preparer 100 requetes test
  - 50 requetes LEGITIMES (trafic normal d'une API REST)
    - GET /api/users/1 (lecture profil)
    - POST /api/login {"email": "user@mail.com", "password": "pass123"}
    - GET /api/products?category=electronics&page=2
    - ...
  - 50 requetes MALVEILLANTES (payloads de Mouad)
    - GET /api/users?id=1' OR '1'='1
    - POST /login {"user": "<script>alert(1)</script>"}
    - GET /files?path=../../../etc/passwd
    - ...

Etape 2 : Tester avec notre systeme
  -> Compter les True Positives (attaques detectees)
  -> Compter les False Positives (legit bloquees)

Etape 3 : Tester avec les regles Cloudflare/ModSecurity
  -> Memes metriques

Etape 4 : Calculer et comparer
```

**Metriques de comparaison :**

| Metrique | Formule | Objectif |
|----------|---------|----------|
| **Detection Rate (Recall)** | Attaques detectees / Total attaques | > 90% |
| **Precision** | Vraies alertes / Total alertes | > 85% |
| **False Positive Rate** | Legit bloquees / Total legit | < 10% |
| **F1-Score** | 2 * (Precision * Recall) / (Precision + Recall) | > 87% |

**Resultats attendus :**

| Metrique | Notre systeme | Cloudflare WAF |
|----------|---------------|----------------|
| Detection Rate | ~90% | ~96% |
| Faux Positifs | ~10% | ~40% |
| Precision | ~90% | ~70.6% |
| F1-Score | ~90% | ~81.4% |

> Avec le ML de Hamza : FP reduit a ~5%, detection a ~95%

#### Bloc 3 — Preparer les 2 slides (1h30)

**Slide 1 : Detection Engine — Architecture 3 couches**
- Schema en entonnoir (3 filtres)
- Couche 1 : Pattern Matching (Regex) -> attaques connues
- Couche 2 : Rate Limiting (Sliding Window) -> attaques volumetriques
- Couche 3 : Anomaly Detection (3-sigma, entropie) -> attaques zero-day

**Slide 2 : Comparaison avec Cloudflare WAF**
- Tableau comparatif (detection rate, FP, precision)
- Conclusion : notre systeme + ML = meilleur rapport detection/FP

**Ressources pour les slides :**
| Ressource | URL | Usage |
|-----------|-----|-------|
| Google Slides | https://slides.google.com | Creation des slides |
| Canva (templates) | https://www.canva.com | Templates de presentation |
| draw.io | https://app.diagrams.net | Schemas et diagrammes |
| Excalidraw | https://excalidraw.com | Schemas style tableau blanc |

---

### JOUR 7 : Setup projet Python + Implementation regles de signature

**Duree totale : 4h**

#### Bloc 1 — Setup de l'environnement Python (30 min)

```bash
# Creer le projet
mkdir -p pfa-detection-engine
cd pfa-detection-engine

# Creer un environnement virtuel
python3 -m venv venv
source venv/bin/activate

# Installer les dependances necessaires
pip install fastapi uvicorn pydantic

# Structure de fichiers
mkdir -p src/rules src/engine tests
touch src/__init__.py
touch src/rules/__init__.py
touch src/rules/signature_rules.py
touch src/rules/behavior_rules.py
touch src/rules/statistical_rules.py
touch src/engine/__init__.py
touch src/engine/detection_engine.py
touch src/engine/rate_limiter.py
touch src/engine/anomaly_detector.py
```

**Ressources :**
| Ressource | URL | Usage |
|-----------|-----|-------|
| Python 3.10+ | https://www.python.org/downloads/ | Runtime |
| FastAPI docs | https://fastapi.tiangolo.com/ | Framework API |
| VS Code | https://code.visualstudio.com/ | Editeur |
| Git | https://git-scm.com/ | Version control |

#### Bloc 2 — Implementation des 20 regles de signature (2h30)

Commencer par le fichier `signature_rules.py` :

```python
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class DetectionRule:
    id: int
    name: str
    pattern: str
    severity: Severity
    description: str
    attack_type: str

    def matches(self, text: str) -> bool:
        return bool(re.search(self.pattern, text, re.IGNORECASE))

# Les 20 regles de signature
SIGNATURE_RULES = [
    DetectionRule(1, "SQLi - UNION SELECT", r"\bUNION\s+SELECT\b",
                  Severity.HIGH, "Detects UNION-based SQL injection", "SQL Injection"),
    DetectionRule(2, "SQLi - Auth Bypass", r"'\s*(OR|AND)\s*'",
                  Severity.HIGH, "Detects OR/AND-based auth bypass", "SQL Injection"),
    DetectionRule(3, "SQLi - DROP TABLE", r";\s*DROP\s+TABLE\b",
                  Severity.CRITICAL, "Detects DROP TABLE attempts", "SQL Injection"),
    # ... continuer avec les regles 4 a 20
]
```

- [ ] Implementer les 20 regles de signature
- [ ] Ecrire 2-3 tests unitaires simples
- [ ] Verifier que les requetes legitimes ne sont pas detectees

**Ressources :**
| Ressource | URL | Usage |
|-----------|-----|-------|
| Python `re` module docs | https://docs.python.org/3/library/re.html | Reference regex Python |
| Python dataclasses | https://docs.python.org/3/library/dataclasses.html | Structure de donnees |
| pytest | https://docs.pytest.org/ | Tests unitaires |

#### Bloc 3 — Init repo Git + push (1h)

- [ ] `git init` dans le dossier du projet
- [ ] Creer un `.gitignore` (venv/, __pycache__/, .env)
- [ ] Premier commit : "feat: project structure + 20 signature detection rules"
- [ ] Creer le repo sur GitHub et push
- [ ] Partager le lien du repo avec l'equipe

**Ressources :**
| Ressource | URL | Usage |
|-----------|-----|-------|
| GitHub New Repo | https://github.com/new | Creer le repo |
| gitignore Python template | https://github.com/github/gitignore/blob/main/Python.gitignore | Template .gitignore |

---

## SEMAINE 2 (Jours 8-14) : Implementation complete + Integration

> La premiere semaine a couvert le rattrapage administratif + l'apprentissage theorique + les premieres regles.
> Cette deuxieme semaine est 100% implementation et preparation du livrable Sprint 2.

---

### JOUR 8 : Implementation du Rate Limiter (Sliding Window)

**Duree totale : 4h**

#### Bloc 1 — Implementer le Rate Limiter en Python (2h30)

Fichier `src/engine/rate_limiter.py` :

```python
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

@dataclass
class RateLimitConfig:
    max_requests: int = 100       # Max requetes autorisees
    window_seconds: int = 60      # Fenetre de temps en secondes
    block_duration: int = 300     # Duree du blocage en secondes (5 min)

class SlidingWindowRateLimiter:
    """
    Implementation de l'algorithme Sliding Window pour le rate limiting.
    Compte les requetes par IP dans une fenetre glissante.
    """
    def __init__(self, config: RateLimitConfig = None):
        self.config = config or RateLimitConfig()
        # Dict[ip_address] -> List[timestamps]
        self.requests: Dict[str, List[float]] = defaultdict(list)
        # Dict[ip_address] -> blocked_until_timestamp
        self.blocked: Dict[str, float] = {}

    def is_allowed(self, ip_address: str) -> Tuple[bool, dict]:
        now = time.time()

        # Verifier si l'IP est bloquee
        if ip_address in self.blocked:
            if now < self.blocked[ip_address]:
                return False, {
                    "reason": "IP temporarily blocked",
                    "blocked_until": self.blocked[ip_address],
                    "remaining_seconds": int(self.blocked[ip_address] - now)
                }
            else:
                del self.blocked[ip_address]

        # Nettoyer les anciennes requetes (hors fenetre)
        window_start = now - self.config.window_seconds
        self.requests[ip_address] = [
            ts for ts in self.requests[ip_address] if ts > window_start
        ]

        # Compter les requetes dans la fenetre
        request_count = len(self.requests[ip_address])

        if request_count >= self.config.max_requests:
            # Bloquer l'IP
            self.blocked[ip_address] = now + self.config.block_duration
            return False, {
                "reason": "Rate limit exceeded",
                "request_count": request_count,
                "limit": self.config.max_requests,
                "window": self.config.window_seconds
            }

        # Enregistrer la requete
        self.requests[ip_address].append(now)
        return True, {
            "request_count": request_count + 1,
            "remaining": self.config.max_requests - request_count - 1
        }
```

- [ ] Implementer la classe `SlidingWindowRateLimiter` complete
- [ ] Ajouter des configs specifiques par endpoint (ex: /login = 10 req/min, /api = 100 req/min)
- [ ] Tester manuellement avec un script qui simule des requetes rapides

#### Bloc 2 — Tests du Rate Limiter (1h)

Fichier `tests/test_rate_limiter.py` :

```python
import time
from src.engine.rate_limiter import SlidingWindowRateLimiter, RateLimitConfig

def test_allows_normal_traffic():
    limiter = SlidingWindowRateLimiter(RateLimitConfig(max_requests=5, window_seconds=60))
    for i in range(5):
        allowed, info = limiter.is_allowed("192.168.1.1")
        assert allowed is True

def test_blocks_excessive_traffic():
    limiter = SlidingWindowRateLimiter(RateLimitConfig(max_requests=3, window_seconds=60))
    for i in range(3):
        limiter.is_allowed("192.168.1.1")
    allowed, info = limiter.is_allowed("192.168.1.1")
    assert allowed is False
    assert info["reason"] == "Rate limit exceeded"

def test_different_ips_independent():
    limiter = SlidingWindowRateLimiter(RateLimitConfig(max_requests=2, window_seconds=60))
    limiter.is_allowed("1.1.1.1")
    limiter.is_allowed("1.1.1.1")
    allowed, _ = limiter.is_allowed("2.2.2.2")
    assert allowed is True  # Different IP, should be allowed
```

- [ ] Ecrire au moins 5 tests unitaires
- [ ] Executer avec `pytest tests/test_rate_limiter.py -v`

**Ressources :**
| Ressource | URL | Usage |
|-----------|-----|-------|
| pytest docs | https://docs.pytest.org/ | Framework de test |
| Python `time` module | https://docs.python.org/3/library/time.html | Gestion du temps |
| Python `collections.defaultdict` | https://docs.python.org/3/library/collections.html#collections.defaultdict | Compteurs par IP |

#### Bloc 3 — Commit + point equipe (30 min)

- [ ] `git add . && git commit -m "feat: sliding window rate limiter with tests"`
- [ ] Envoyer un message a l'equipe pour le point mi-sprint

---

### JOUR 9 : Implementation du Anomaly Detector

**Duree totale : 4h**

#### Bloc 1 — Module de calcul statistique (1h30)

Fichier `src/engine/anomaly_detector.py` :

```python
import math
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional

@dataclass
class BaselineStats:
    """Statistiques baseline pour une metrique donnee."""
    mean: float = 0.0
    std_dev: float = 0.0
    count: int = 0
    min_val: float = float('inf')
    max_val: float = float('-inf')

class AnomalyDetector:
    """
    Detection d'anomalies basee sur la regle des 3-sigma.
    Compare chaque requete au baseline du comportement normal.
    """
    def __init__(self, sigma_threshold: float = 3.0):
        self.sigma_threshold = sigma_threshold
        self.baselines: Dict[str, BaselineStats] = {}
        self.training_data: Dict[str, List[float]] = defaultdict(list)

    def train(self, metric_name: str, values: List[float]):
        """Calcule le baseline a partir de donnees normales."""
        if not values:
            return
        n = len(values)
        mean = sum(values) / n
        variance = sum((x - mean) ** 2 for x in values) / n
        std_dev = math.sqrt(variance)

        self.baselines[metric_name] = BaselineStats(
            mean=mean,
            std_dev=std_dev,
            count=n,
            min_val=min(values),
            max_val=max(values)
        )

    def is_anomaly(self, metric_name: str, value: float) -> tuple[bool, dict]:
        """Verifie si une valeur depasse le seuil 3-sigma."""
        if metric_name not in self.baselines:
            return False, {"reason": "No baseline for this metric"}

        baseline = self.baselines[metric_name]
        threshold = baseline.mean + self.sigma_threshold * baseline.std_dev
        is_anomalous = value > threshold

        return is_anomalous, {
            "metric": metric_name,
            "value": value,
            "mean": round(baseline.mean, 2),
            "std_dev": round(baseline.std_dev, 2),
            "threshold": round(threshold, 2),
            "deviation": round((value - baseline.mean) / baseline.std_dev, 2)
                         if baseline.std_dev > 0 else 0
        }

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calcule l'entropie de Shannon d'une chaine de caracteres."""
        if not text:
            return 0.0
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        length = len(text)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )
        return round(entropy, 4)

    @staticmethod
    def count_special_chars(text: str) -> int:
        """Compte le nombre de caracteres speciaux."""
        special = set("!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\")
        return sum(1 for c in text if c in special)
```

- [ ] Implementer la classe `AnomalyDetector` avec les methodes `train`, `is_anomaly`
- [ ] Implementer `calculate_entropy` et `count_special_chars`
- [ ] Creer une methode `analyze_request` qui verifie toutes les metriques d'un coup

#### Bloc 2 — Fonctions d'extraction de features (1h30)

Fichier `src/engine/feature_extractor.py` :

```python
from urllib.parse import urlparse, parse_qs
import json

def extract_features(method: str, url: str, headers: dict, body: str = "") -> dict:
    """Extrait toutes les metriques d'une requete HTTP pour l'anomaly detection."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    features = {
        "url_length": len(url),
        "path_length": len(parsed.path),
        "num_params": len(params),
        "total_param_value_length": sum(len(v) for vals in params.values() for v in vals),
        "body_length": len(body),
        "num_headers": len(headers),
        "special_chars_url": AnomalyDetector.count_special_chars(url),
        "special_chars_body": AnomalyDetector.count_special_chars(body),
        "entropy_url": AnomalyDetector.calculate_entropy(url),
        "entropy_body": AnomalyDetector.calculate_entropy(body),
        "has_user_agent": "User-Agent" in headers,
        "path_depth": parsed.path.count("/"),
    }

    # Body JSON depth
    if body:
        try:
            json_body = json.loads(body)
            features["json_depth"] = _json_depth(json_body)
            features["json_keys"] = _count_keys(json_body)
        except json.JSONDecodeError:
            features["json_depth"] = 0
            features["json_keys"] = 0

    return features

def _json_depth(obj, current=0):
    if isinstance(obj, dict):
        return max((_json_depth(v, current + 1) for v in obj.values()), default=current)
    elif isinstance(obj, list):
        return max((_json_depth(v, current + 1) for v in obj), default=current)
    return current

def _count_keys(obj):
    if isinstance(obj, dict):
        return len(obj) + sum(_count_keys(v) for v in obj.values())
    elif isinstance(obj, list):
        return sum(_count_keys(v) for v in obj)
    return 0
```

- [ ] Implementer l'extracteur de features
- [ ] Tester avec des exemples de requetes normales et malveillantes
- [ ] Verifier que l'entropie est plus elevee pour les payloads encodes

#### Bloc 3 — Tests du Anomaly Detector (1h)

```python
def test_entropy_normal_vs_malicious():
    detector = AnomalyDetector()
    normal = detector.calculate_entropy("hello world")
    malicious = detector.calculate_entropy("x7$kQ9!mZ@2pL#fW")
    assert malicious > normal

def test_3sigma_detection():
    detector = AnomalyDetector()
    # Train avec des URL de 30 a 80 caracteres
    normal_lengths = [35, 42, 50, 38, 55, 40, 48, 45, 52, 43]
    detector.train("url_length", normal_lengths)
    # URL de 200 caracteres = anomalie
    is_anomaly, info = detector.is_anomaly("url_length", 200)
    assert is_anomaly is True
```

- [ ] Ecrire au moins 5 tests
- [ ] `git commit -m "feat: anomaly detector with 3-sigma and entropy"`

**Ressources :**
| Ressource | URL | Usage |
|-----------|-----|-------|
| Python `math` module | https://docs.python.org/3/library/math.html | Calculs mathematiques |
| Shannon Entropy (Wikipedia) | https://en.wikipedia.org/wiki/Entropy_(information_theory) | Comprendre l'entropie |
| Python `urllib.parse` | https://docs.python.org/3/library/urllib.parse.html | Parser les URLs |

---

### JOUR 10 : Assemblage du Detection Engine complet

**Duree totale : 4h**

#### Bloc 1 — Classe principale DetectionEngine (2h)

Fichier `src/engine/detection_engine.py` :

```python
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional
from src.rules.signature_rules import SIGNATURE_RULES
from src.engine.rate_limiter import SlidingWindowRateLimiter
from src.engine.anomaly_detector import AnomalyDetector
from src.engine.feature_extractor import extract_features

class ThreatLevel(Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class DetectionResult:
    is_threat: bool
    threat_level: ThreatLevel
    matched_rules: List[dict]
    rate_limit_status: dict
    anomaly_scores: dict
    recommendation: str  # "ALLOW", "FLAG", "BLOCK"

class DetectionEngine:
    """
    Moteur de detection principal — 3 couches de defense.
    Couche 1: Pattern Matching (Signatures)
    Couche 2: Rate Limiting (Sliding Window)
    Couche 3: Anomaly Detection (3-sigma + entropie)
    """

    def __init__(self):
        self.signature_rules = SIGNATURE_RULES
        self.rate_limiter = SlidingWindowRateLimiter()
        self.anomaly_detector = AnomalyDetector()

    def analyze(self, method: str, url: str, headers: dict,
                body: str = "", ip_address: str = "0.0.0.0") -> DetectionResult:
        """Analyse une requete HTTP a travers les 3 couches."""
        matched_rules = []
        full_text = f"{method} {url} {body}"

        # COUCHE 1: Pattern Matching
        for rule in self.signature_rules:
            if rule.matches(full_text):
                matched_rules.append({
                    "rule_id": rule.id,
                    "name": rule.name,
                    "severity": rule.severity.value,
                    "attack_type": rule.attack_type
                })

        # COUCHE 2: Rate Limiting
        rate_allowed, rate_info = self.rate_limiter.is_allowed(ip_address)

        # COUCHE 3: Anomaly Detection
        features = extract_features(method, url, headers, body)
        anomaly_results = {}
        for metric, value in features.items():
            if isinstance(value, (int, float)):
                is_anomaly, info = self.anomaly_detector.is_anomaly(metric, value)
                if is_anomaly:
                    anomaly_results[metric] = info

        # DECISION FINALE
        threat_level, recommendation = self._decide(
            matched_rules, rate_allowed, anomaly_results
        )

        return DetectionResult(
            is_threat=(threat_level != ThreatLevel.SAFE),
            threat_level=threat_level,
            matched_rules=matched_rules,
            rate_limit_status=rate_info,
            anomaly_scores=anomaly_results,
            recommendation=recommendation
        )

    def _decide(self, matched_rules, rate_allowed, anomaly_results):
        # Regles CRITICAL -> BLOCK immediat
        if any(r["severity"] == "CRITICAL" for r in matched_rules):
            return ThreatLevel.CRITICAL, "BLOCK"
        # Rate limit depasse -> BLOCK
        if not rate_allowed:
            return ThreatLevel.HIGH, "BLOCK"
        # Regles HIGH -> BLOCK
        if any(r["severity"] == "HIGH" for r in matched_rules):
            return ThreatLevel.HIGH, "BLOCK"
        # Anomalies multiples -> FLAG (envoyer au ML)
        if len(anomaly_results) >= 2:
            return ThreatLevel.MEDIUM, "FLAG"
        # Regles MEDIUM ou 1 anomalie -> FLAG
        if matched_rules or anomaly_results:
            return ThreatLevel.LOW, "FLAG"
        # Rien detecte -> ALLOW
        return ThreatLevel.SAFE, "ALLOW"
```

- [ ] Implementer la classe `DetectionEngine` complete
- [ ] Implementer la logique de decision `_decide`
- [ ] S'assurer que les 3 couches fonctionnent ensemble

#### Bloc 2 — Tests d'integration (1h30)

```python
def test_sqli_detected():
    engine = DetectionEngine()
    result = engine.analyze("GET", "/api/users?id=1' OR '1'='1", {}, "", "1.1.1.1")
    assert result.is_threat is True
    assert result.recommendation == "BLOCK"

def test_legitimate_request():
    engine = DetectionEngine()
    result = engine.analyze("GET", "/api/users/1", {"User-Agent": "Chrome"}, "", "1.1.1.1")
    assert result.is_threat is False
    assert result.recommendation == "ALLOW"

def test_brute_force_detected():
    engine = DetectionEngine()
    config = RateLimitConfig(max_requests=5, window_seconds=60)
    engine.rate_limiter = SlidingWindowRateLimiter(config)
    for i in range(5):
        engine.analyze("POST", "/login", {}, '{"user":"a"}', "1.1.1.1")
    result = engine.analyze("POST", "/login", {}, '{"user":"a"}', "1.1.1.1")
    assert result.recommendation == "BLOCK"
```

- [ ] Ecrire au moins 8 tests d'integration couvrant les 3 couches
- [ ] Tester les cas limites (requete vide, IP inconnue, etc.)

#### Bloc 3 — Commit + documentation (30 min)

- [ ] `git commit -m "feat: complete detection engine with 3 layers"`
- [ ] Ecrire un README.md minimal pour le repo

**Ressources :**
| Ressource | URL | Usage |
|-----------|-----|-------|
| Python Design Patterns | https://refactoring.guru/design-patterns/python | Architecture propre |
| Clean Code Python | https://github.com/zedr/clean-code-python | Bonnes pratiques |

---

### JOUR 11 : Endpoint FastAPI + Coordination avec Ayoub

**Duree totale : 3h30**

#### Bloc 1 — Creer l'endpoint POST /detect (1h30)

Fichier `src/api/main.py` :

```python
from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import Optional, Dict
from src.engine.detection_engine import DetectionEngine

app = FastAPI(title="PFA Detection Engine API", version="0.1.0")
engine = DetectionEngine()

class DetectionRequest(BaseModel):
    method: str                        # GET, POST, PUT, DELETE
    url: str                           # /api/users?id=1
    headers: Dict[str, str] = {}       # {"User-Agent": "Chrome"}
    body: str = ""                     # Request body
    ip_address: str = "0.0.0.0"       # Source IP

class DetectionResponse(BaseModel):
    is_threat: bool
    threat_level: str
    recommendation: str               # ALLOW, FLAG, BLOCK
    matched_rules: list
    rate_limit_status: dict
    anomaly_scores: dict

@app.post("/detect", response_model=DetectionResponse)
async def detect_threat(req: DetectionRequest):
    result = engine.analyze(
        method=req.method,
        url=req.url,
        headers=req.headers,
        body=req.body,
        ip_address=req.ip_address
    )
    return DetectionResponse(
        is_threat=result.is_threat,
        threat_level=result.threat_level.value,
        recommendation=result.recommendation,
        matched_rules=result.matched_rules,
        rate_limit_status=result.rate_limit_status,
        anomaly_scores=result.anomaly_scores
    )

@app.get("/health")
async def health():
    return {"status": "ok", "rules_loaded": len(engine.signature_rules)}
```

- [ ] Creer l'endpoint `POST /detect`
- [ ] Creer l'endpoint `GET /health`
- [ ] Tester avec `uvicorn src.api.main:app --reload`
- [ ] Verifier le Swagger auto-genere sur `http://localhost:8000/docs`

#### Bloc 2 — Tester avec curl ou Postman (1h)

```bash
# Test requete legitime
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","url":"/api/users/1","headers":{"User-Agent":"Chrome"},"ip_address":"1.1.1.1"}'

# Test SQL Injection
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","url":"/api/users?id=1'\'' OR '\''1'\''='\''1","headers":{},"ip_address":"2.2.2.2"}'

# Test XSS
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{"method":"POST","url":"/login","headers":{},"body":"{\"user\":\"<script>alert(1)</script>\"}","ip_address":"3.3.3.3"}'
```

- [ ] Tester au moins 5 requetes (2 legit + 3 malveillantes)
- [ ] Verifier que les reponses JSON sont correctes
- [ ] Prendre des screenshots des resultats pour la presentation

#### Bloc 3 — Coordination avec Ayoub (1h)

- [ ] Se synchroniser avec Ayoub sur le format de l'API
- [ ] Definir le contrat d'interface : quels champs dans la requete, quels champs dans la reponse
- [ ] Discuter de l'integration : Ayoub va appeler `POST /detect` depuis son backend principal
- [ ] Partager la doc Swagger (`/docs`) avec Ayoub

**Ressources :**
| Ressource | URL | Usage |
|-----------|-----|-------|
| FastAPI docs | https://fastapi.tiangolo.com/ | Endpoints |
| Pydantic models | https://docs.pydantic.dev/ | Validation des donnees |
| Swagger UI | http://localhost:8000/docs | Doc interactive auto-generee |
| Postman | https://www.postman.com/downloads/ | Tester les APIs |
| curl documentation | https://curl.se/docs/ | Tests en ligne de commande |

---

### JOUR 12 : Implementation des regles comportementales + Tests

**Duree totale : 3h30**

#### Bloc 1 — Implementer les 15 regles comportementales (2h)

Fichier `src/rules/behavior_rules.py` :

```python
from collections import defaultdict
from dataclasses import dataclass
import time
from typing import Dict, List, Set

@dataclass
class BehaviorAlert:
    rule_id: int
    name: str
    severity: str
    details: dict

class BehaviorAnalyzer:
    """Analyse le comportement par IP sur le temps."""

    def __init__(self):
        self.login_failures: Dict[str, List[float]] = defaultdict(list)
        self.endpoints_accessed: Dict[str, Set[str]] = defaultdict(set)
        self.user_agents: Dict[str, Set[str]] = defaultdict(set)
        self.status_404_count: Dict[str, int] = defaultdict(int)
        self.request_hashes: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.session_ips: Dict[str, Set[str]] = defaultdict(set)

    def analyze(self, ip: str, method: str, url: str, headers: dict,
                status_code: int = 200, session_id: str = None) -> List[BehaviorAlert]:
        alerts = []
        now = time.time()

        # Regle 23: Scanning (trop d'endpoints differents)
        self.endpoints_accessed[ip].add(url.split("?")[0])
        if len(self.endpoints_accessed[ip]) > 50:
            alerts.append(BehaviorAlert(23, "Scanning/Enumeration", "MEDIUM",
                          {"distinct_endpoints": len(self.endpoints_accessed[ip])}))

        # Regle 24: Acces admin sans auth
        if "/admin" in url or "/debug" in url:
            if "Authorization" not in headers:
                alerts.append(BehaviorAlert(24, "Unauthorized Admin Access", "CRITICAL",
                              {"url": url}))

        # Regle 28: User-Agent rotation
        ua = headers.get("User-Agent", "")
        if ua:
            self.user_agents[ip].add(ua)
        if len(self.user_agents[ip]) > 5:
            alerts.append(BehaviorAlert(28, "Bot Evasion (UA rotation)", "MEDIUM",
                          {"distinct_user_agents": len(self.user_agents[ip])}))

        # Regle 29: Directory bruteforce (404s)
        if status_code == 404:
            self.status_404_count[ip] += 1
        if self.status_404_count[ip] > 20:
            alerts.append(BehaviorAlert(29, "Directory Bruteforce", "MEDIUM",
                          {"404_count": self.status_404_count[ip]}))

        # Regle 33: Requetes sans User-Agent
        if not ua:
            alerts.append(BehaviorAlert(33, "No User-Agent (Bot)", "LOW",
                          {"ip": ip}))

        # Regle 35: Session hijacking (meme session, IPs differentes)
        if session_id:
            self.session_ips[session_id].add(ip)
            if len(self.session_ips[session_id]) > 3:
                alerts.append(BehaviorAlert(35, "Session Hijacking", "CRITICAL",
                              {"session": session_id,
                               "ips": list(self.session_ips[session_id])}))

        # ... implementer les regles 22, 25, 26, 27, 30, 31, 32, 34
        return alerts
```

- [ ] Implementer les 15 regles comportementales
- [ ] Integrer `BehaviorAnalyzer` dans `DetectionEngine`

#### Bloc 2 — Tests comportementaux (1h)

- [ ] Tester le scanning (51 endpoints differents)
- [ ] Tester l'acces admin sans auth
- [ ] Tester la rotation de User-Agent
- [ ] Tester le directory bruteforce (21 erreurs 404)

#### Bloc 3 — Commit (30 min)

- [ ] `git commit -m "feat: 15 behavior rules + behavior analyzer"`
- [ ] Push sur GitHub

**Ressources :**
| Ressource | URL | Usage |
|-----------|-----|-------|
| Python `collections` | https://docs.python.org/3/library/collections.html | defaultdict, Counter |
| OWASP Testing Guide | https://owasp.org/www-project-web-security-testing-guide/ | Comprendre les attaques comportementales |

---

### JOUR 13 : Tests complets sur 100 requetes + Comparaison Cloudflare

**Duree totale : 4h**

#### Bloc 1 — Creer le dataset de test (1h30)

Fichier `tests/test_dataset.py` :

```python
# 50 requetes LEGITIMES
LEGITIMATE_REQUESTS = [
    {"method": "GET",  "url": "/api/users/1", "body": ""},
    {"method": "GET",  "url": "/api/products?category=electronics&page=2", "body": ""},
    {"method": "POST", "url": "/api/login", "body": '{"email":"user@mail.com","password":"pass123"}'},
    {"method": "PUT",  "url": "/api/users/1/profile", "body": '{"name":"John","age":25}'},
    {"method": "GET",  "url": "/api/orders?status=pending&limit=10", "body": ""},
    # ... 45 de plus
]

# 50 requetes MALVEILLANTES
MALICIOUS_REQUESTS = [
    {"method": "GET",  "url": "/api/users?id=1' OR '1'='1", "body": "", "attack": "SQLi"},
    {"method": "GET",  "url": "/api/users?id=1 UNION SELECT * FROM passwords--", "body": "", "attack": "SQLi"},
    {"method": "POST", "url": "/login", "body": '{"user":"<script>alert(1)</script>"}', "attack": "XSS"},
    {"method": "GET",  "url": "/files?path=../../../etc/passwd", "body": "", "attack": "Path Traversal"},
    {"method": "GET",  "url": "/api?cmd=;cat /etc/passwd", "body": "", "attack": "Command Injection"},
    # ... 45 de plus
]
```

- [ ] Ecrire 50 requetes legitimes realistes
- [ ] Ecrire 50 requetes malveillantes couvrant SQLi, XSS, Path Traversal, Command Injection, BOLA
- [ ] Coordonner avec Mouad pour utiliser ses payloads

#### Bloc 2 — Executer les tests et calculer les metriques (1h30)

```python
def run_benchmark():
    engine = DetectionEngine()
    tp, fp, tn, fn = 0, 0, 0, 0

    for req in LEGITIMATE_REQUESTS:
        result = engine.analyze(req["method"], req["url"], {}, req["body"], "1.1.1.1")
        if result.is_threat:
            fp += 1  # Faux positif: legit classee comme menace
        else:
            tn += 1  # Vrai negatif: legit classee comme safe

    for req in MALICIOUS_REQUESTS:
        result = engine.analyze(req["method"], req["url"], {}, req["body"], "2.2.2.2")
        if result.is_threat:
            tp += 1  # Vrai positif: attaque detectee
        else:
            fn += 1  # Faux negatif: attaque non detectee

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    print(f"True Positives:  {tp}/50")
    print(f"False Positives: {fp}/50")
    print(f"Precision:       {precision:.1%}")
    print(f"Recall:          {recall:.1%}")
    print(f"F1-Score:        {f1:.1%}")
    print(f"FP Rate:         {fpr:.1%}")
```

- [ ] Executer le benchmark
- [ ] Noter les resultats
- [ ] Comparer avec les chiffres attendus de Cloudflare

#### Bloc 3 — Rediger le rapport comparatif (1h)

Creer un fichier `comparison_report.md` :

```
## Resultats de la comparaison

### Notre systeme (Detection Engine seul, sans ML)
| Metrique          | Valeur   |
|-------------------|----------|
| Detection Rate    | XX/50    |
| Faux Positifs     | XX/50    |
| Precision         | XX%      |
| Recall            | XX%      |
| F1-Score          | XX%      |

### Cloudflare WAF (valeurs de reference)
| Metrique          | Valeur   |
|-------------------|----------|
| Detection Rate    | ~48/50   |
| Faux Positifs     | ~20/50   |
| Precision         | ~70.6%   |
| Recall            | ~96%     |
| F1-Score          | ~81.4%   |

### Conclusion
Notre systeme maintient un taux de detection comparable tout en
reduisant significativement les faux positifs. Avec le ML de Hamza,
les FP devraient passer sous les 5%.
```

- [ ] Remplir avec les vrais chiffres
- [ ] Ajouter au Google Drive dans "Dossier PFA"

**Ressources :**
| Ressource | URL | Usage |
|-----------|-----|-------|
| Confusion Matrix explained | https://en.wikipedia.org/wiki/Confusion_matrix | Comprendre TP/FP/TN/FN |
| Scikit-learn metrics | https://scikit-learn.org/stable/modules/model_evaluation.html | Reference pour Precision/Recall/F1 |
| ModSecurity CRS benchmarks | Chercher "modsecurity crs false positive rate" | Chiffres de reference |

---

### JOUR 14 : Finalisation Sprint + Preparation Sprint Review

**Duree totale : 4h**

#### Bloc 1 — Nettoyage du code et documentation (1h)

- [ ] Revoir tout le code et ajouter des docstrings
- [ ] S'assurer que tous les tests passent : `pytest tests/ -v`
- [ ] Mettre a jour le `README.md` du repo avec :
  - Description du projet
  - Comment installer et lancer
  - Comment lancer les tests
  - Architecture (3 couches)
- [ ] `git commit -m "docs: README + docstrings"`
- [ ] Push final sur GitHub

#### Bloc 2 — Mise a jour du fichier Excel de suivi (1h)

Mettre a jour `Suivi de Projet (PFA).xlsx` pour la Sprint Review :

| Onglet | Mise a jour |
|--------|-------------|
| Tableau de Bord | Avancement: ~15-20%, Phase: Recherche & Conception |
| Product Backlog | Tache 2 (Detection Engine): 40% termine. Tache_GP1 (CdC): 100% |
| Kanban | Deplacer les taches terminees dans "Termine" |
| Sprint Planning | Remplir Sprint 2 backlog + retrospective |

**Sprint 2 Retrospective (a remplir) :**
- **Ce qui a bien marche** : Rattrapage rapide, 50 regles documentees, code fonctionnel
- **Ce qui peut etre ameliore** : Meilleure communication, ne plus laisser 2 semaines sans travailler
- **Actions** : Points de synchro bi-hebdomadaires, deadlines intermediaires

#### Bloc 3 — Preparer et repeter la presentation Sprint Review (1h30)

La Sprint Review est le moment de presenter au professeur ce qui a ete fait pendant le sprint.

**Structure de la presentation (5 min max) :**

1. **[0:00 - 0:30] Rappel du contexte** :
   > "Notre PFA porte sur la detection automatisee d'anomalies dans les APIs REST. Mon role est de construire le Detection Engine."

2. **[0:30 - 1:30] Ce qui a ete fait ce sprint** :
   > "J'ai concu et implemente un moteur de detection a 3 couches : Pattern Matching avec 20 regles regex, Rate Limiting avec l'algorithme Sliding Window, et Anomaly Detection avec la regle des 3-sigma et l'entropie de Shannon. Au total, 50 regles de detection sont documentees."

3. **[1:30 - 2:30] Demo en live** :
   > Montrer le Swagger (`/docs`), envoyer une requete legitime puis une requete malveillante, montrer la difference dans la reponse.

4. **[2:30 - 3:30] Resultats du benchmark** :
   > "Sur 100 requetes test, notre moteur detecte X% des attaques avec seulement Y% de faux positifs, contre ~40% pour Cloudflare."

5. **[3:30 - 4:00] Plan Sprint 3** :
   > "Pour le prochain sprint, je vais affiner les regles, integrer avec le module ML de Hamza, et commencer les tests sur une vraie API."

**Questions pieges a preparer :**

**Q1 : "Pourquoi Sliding Window plutot que Fixed Window ?"**
> "Fixed Window remet le compteur a zero de facon rigide. Un attaquant peut envoyer 100 requetes a 12:00:59 et 100 autres a 12:01:01, contournant la limite. Sliding Window glisse en temps reel et empeche ce contournement."

**Q2 : "Qu'est-ce que l'entropie dans votre contexte ?"**
> "C'est la mesure du desordre dans une chaine de caracteres. Un payload encode ou obfusque a une entropie plus elevee qu'un parametre normal. Si on depasse 5.0 bits, on signale une anomalie."

**Q3 : "Pourquoi du Regex si on utilise du ML ?"**
> "Performance et cout. Le Regex bloque instantanement les attaques evidentes comme `<script>`. Le ML est reserve pour les cas ambigus. Ca reduit la charge sur le modele et accelere le temps de reponse."

**Q4 : "Comment vous gerez les faux positifs ?"**
> "Notre moteur a 3 niveaux de decision : BLOCK pour les menaces evidentes, FLAG pour les cas suspects qui sont envoyes au ML de Hamza pour confirmation, et ALLOW pour le trafic normal. Le ML filtre les faux positifs car il apprend le contexte specifique de l'API."

- [ ] Repeter la presentation 3-4 fois a voix haute avec chronometre
- [ ] Preparer la demo live (lancer le serveur FastAPI avant la presentation)
- [ ] Avoir les screenshots du benchmark prets en backup

#### Bloc 4 — Communication finale (30 min)

- [ ] Envoyer le compte rendu Sprint 2 au professeur
- [ ] Partager le lien du repo GitHub avec l'equipe
- [ ] Planifier le Sprint 3 avec l'equipe

---

## Planning revise du projet (Sprints de 2 semaines)

> Avec des sprints de 2 semaines au lieu d'1 semaine, le planning passe de 22 sprints a 11 sprints.

| Phase | Sprints | Periode | Description |
|-------|---------|---------|-------------|
| Phase 1 — Cadrage & CdC | Sprint 1 | 12/03 au 25/03 | Cahier des Charges, SWOT, RACI, Charte, outils |
| Phase 2 — Recherche & Conception | Sprint 2-3 | 26/03 au 22/04 | OWASP, architecture, dataset, setup backend |
| Phase 3 — Developpement | Sprint 4-7 | 23/04 au 17/06 | Implementation des 4 modules en parallele |
| Phase 4 — Integration & Tests | Sprint 8-9 | 18/06 au 15/07 | Integration Docker, tests end-to-end, comparaison |
| Phase 5 — Finalisation | Sprint 10-11 | 16/07 au 12/08 | Dashboard, rapport, optimisation ML, soutenance |

**Duree totale : ~5 mois (11 sprints de 2 semaines)**
**Sprint review : tous les 2 semaines**

---

## Resume des livrables du Sprint 2 (14 jours)

### Semaine 1 (Jours 1-7) : Rattrapage + Theorie + Premieres regles

| # | Livrable | Format | Priorite | Jour |
|---|----------|--------|----------|------|
| 1 | Cahier des Charges finalise | Google Docs / PDF | CRITIQUE | Jour 1 |
| 2 | Fichier Excel de suivi rempli (6 onglets) | Excel | CRITIQUE | Jour 1 |
| 3 | Matrice RACI dans Excel | Excel | HAUTE | Jour 1 |
| 4 | Notes personnelles WAF + OWASP | Papier / Markdown | MOYENNE | Jour 2 |
| 5 | Exercices Regex completes sur regex101 | Screenshots | HAUTE | Jour 3 |
| 6 | Document 50 regles de detection | JSON / Markdown | HAUTE | Jour 5 |
| 7 | Methodologie de comparaison Cloudflare | Markdown | MOYENNE | Jour 6 |
| 8 | 2 slides pour la presentation | Google Slides | HAUTE | Jour 6 |
| 9 | Code Python : 20 regles signature | Python | HAUTE | Jour 7 |
| 10 | Repo Git initialise et push | GitHub | HAUTE | Jour 7 |

### Semaine 2 (Jours 8-14) : Implementation + Tests + Sprint Review

| # | Livrable | Format | Priorite | Jour |
|---|----------|--------|----------|------|
| 11 | Rate Limiter (Sliding Window) + tests | Python | HAUTE | Jour 8 |
| 12 | Anomaly Detector (3-sigma + entropie) + tests | Python | HAUTE | Jour 9 |
| 13 | Detection Engine complet (3 couches) | Python | CRITIQUE | Jour 10 |
| 14 | Endpoint FastAPI `POST /detect` fonctionnel | Python/FastAPI | HAUTE | Jour 11 |
| 15 | 15 regles comportementales implementees | Python | HAUTE | Jour 12 |
| 16 | Benchmark 100 requetes + rapport comparatif | Markdown | HAUTE | Jour 13 |
| 17 | Excel de suivi mis a jour (Sprint Review) | Excel | CRITIQUE | Jour 14 |
| 18 | Presentation Sprint Review preparee | Oral + slides | CRITIQUE | Jour 14 |

---

## Toutes les ressources en un seul endroit

### Lecture obligatoire

| # | Ressource | URL | Temps estime |
|---|-----------|-----|-------------|
| 1 | Cloudflare - What is a WAF? | https://www.cloudflare.com/learning/ddos/glossary/web-application-firewall-waf/ | 30 min |
| 2 | OWASP Top 10 (2021) | https://owasp.org/www-project-top-ten/ | 45 min |
| 3 | OWASP API Security Top 10 (2023) | https://owasp.org/API-Security/editions/2023/en/0x11-t10/ | 45 min |
| 4 | Cloudflare - What is Rate Limiting? | https://www.cloudflare.com/learning/bots/what-is-rate-limiting/ | 15 min |
| 5 | 3-Sigma Rule (Wikipedia) | https://en.wikipedia.org/wiki/68%E2%80%9395%E2%80%9399.7_rule | 15 min |

### Pratique obligatoire

| # | Ressource | URL | Temps estime |
|---|-----------|-----|-------------|
| 6 | Regex101 (bac a sable) | https://regex101.com | 2h |
| 7 | RegexOne (tutoriel) | https://regexone.com | 20 min |

### Reference technique

| # | Ressource | URL | Usage |
|---|-----------|-----|-------|
| 8 | ModSecurity Core Rule Set | https://github.com/coreruleset/coreruleset | Regles WAF de reference |
| 9 | PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings | Payloads reels |
| 10 | SecLists | https://github.com/danielmiessler/SecLists | Listes de fuzzing |
| 11 | Regex Cheat Sheet | https://quickref.me/regex | Reference rapide |
| 12 | Python `re` module | https://docs.python.org/3/library/re.html | Regex en Python |
| 13 | FastAPI documentation | https://fastapi.tiangolo.com/ | Framework API |
| 14 | Pydantic documentation | https://docs.pydantic.dev/ | Validation des donnees |
| 15 | OWASP Input Validation Cheatsheet | https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html | Validation patterns |
| 16 | Cloudflare WAF docs | https://developers.cloudflare.com/waf/ | Comprendre Cloudflare |
| 17 | HackTricks SQLi | https://book.hacktricks.wiki/en/pentesting-web/sql-injection/index.html | SQLi en profondeur |
| 18 | Python dataclasses | https://docs.python.org/3/library/dataclasses.html | Structure de donnees |
| 19 | pytest documentation | https://docs.pytest.org/ | Tests unitaires |
| 20 | Confusion Matrix (Wikipedia) | https://en.wikipedia.org/wiki/Confusion_matrix | Comprendre TP/FP/TN/FN |

### Outils de developpement

| # | Outil | URL | Usage |
|---|-------|-----|-------|
| 21 | Python 3.10+ | https://www.python.org/downloads/ | Runtime |
| 22 | VS Code | https://code.visualstudio.com/ | Editeur de code |
| 23 | Git | https://git-scm.com/ | Version control |
| 24 | Postman | https://www.postman.com/downloads/ | Tester les APIs |
| 25 | GitHub | https://github.com/new | Heberger le repo |

### Outils de creation (presentations, schemas)

| # | Outil | URL | Usage |
|---|-------|-----|-------|
| 26 | Google Slides | https://slides.google.com | Presentation |
| 27 | draw.io | https://app.diagrams.net | Schemas architecture |
| 28 | Excalidraw | https://excalidraw.com | Schemas rapides |
| 29 | Canva | https://www.canva.com | Templates visuels |

### Videos recommandees (optionnel mais utile)

| # | Sujet | Ou chercher | Temps |
|---|-------|-------------|-------|
| 30 | OWASP Top 10 explique | YouTube : "OWASP Top 10 explained" (NetworkChuck) | 20 min |
| 31 | Rate Limiting System Design | YouTube : "rate limiting system design" (ByteByteGo) | 15 min |
| 32 | Anomaly Detection intro | YouTube : "anomaly detection for beginners" | 30 min |
| 33 | WAF explained | YouTube : "web application firewall explained" | 15 min |
| 34 | FastAPI crash course | YouTube : "FastAPI tutorial" (TechWithTim ou Traversy Media) | 30 min |
| 35 | Python testing with pytest | YouTube : "pytest tutorial" | 20 min |

---

## Message a envoyer au professeur (Sprint Review)

> Bonjour Professeur REGAD,
>
> Veuillez trouver ci-dessous le compte rendu du Sprint 2 de notre PFA "Detection Automatisee d'Anomalies dans les APIs REST".
>
> **Ce qui a ete realise durant ce sprint (2 semaines) :**
>
> 1. Finalisation du cadrage : Cahier des Charges, SWOT, RACI, Charte de Projet
> 2. Fichier Excel de suivi rempli (6 onglets)
> 3. Etude des WAFs et de l'OWASP Top 10 (Web + API)
> 4. Documentation de 50 regles de detection (20 signatures, 15 comportementales, 15 statistiques)
> 5. Implementation Python du Detection Engine a 3 couches :
>    - Pattern Matching (20 regles regex)
>    - Rate Limiting (algorithme Sliding Window)
>    - Anomaly Detection (3-sigma + entropie de Shannon)
> 6. Endpoint FastAPI `POST /detect` fonctionnel avec documentation Swagger
> 7. Benchmark sur 100 requetes test + rapport comparatif avec Cloudflare WAF
>
> **Prochaines etapes (Sprint 3) :**
> - Affiner les regles et reduire les faux positifs
> - Integrer le Detection Engine avec le module ML de Hamza
> - Commencer les tests sur une API cible reelle
>
> Le lien du repo GitHub : *(a completer)*
>
> Cordialement,
> Bilal SAMMER

---

## Message a envoyer a l'equipe

> Salut l'equipe,
>
> Desole pour les 2 semaines de silence. On a du retard a rattraper. Voici ce que chacun doit faire sur ce sprint (2 semaines) :
>
> **Mouad** : Finalise la doc OWASP API Top 10 + commence les 100 premiers payloads SQLi. J'ai besoin de tes payloads pour tester mon Detection Engine.
>
> **Hamza** : Identifie les sources de dataset (CSIC 2010) + prepare le script d'extraction features. Mon engine va generer des alertes que ton ML va filtrer — on doit se mettre d'accord sur le format des features.
>
> **Ayoub** : Init le projet FastAPI + premiers endpoints + schema PostgreSQL + Dockerfile. Mon endpoint `POST /detect` est pret, on doit discuter de l'integration.
>
> **Moi (Bilal)** : 50 regles de detection + implementation complete du Detection Engine Python + benchmark + rapport comparatif Cloudflare.
>
> On se fait un point vocal ce soir/demain pour se synchroniser ? Sprint review dans 2 semaines.

---

*Fichier genere le 24/03/2026. Sprint 2 : 26/03 - 08/04. Sprint review : 08/04.*
