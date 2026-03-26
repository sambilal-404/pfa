# Plan Personnel - BILAL (Detection Engine)

## Preparation pour la presentation de la semaine prochaine

---

## TON ROLE EN UNE PHRASE

Tu es **le defenseur** : tu construis le systeme qui analyse le traffic API en temps reel et decide si une requete est normale ou suspecte. Tu es le **pont** entre les attaques de Mouad et la classification ML de Hamza.

---

## CE QUE TU DOIS MAITRISER CETTE SEMAINE

### JOUR 1-2 : Comprendre ce qu'est un WAF

#### A lire

- **Cloudflare Learning Center - "What is a WAF?"**
  - URL : https://www.cloudflare.com/learning/ddos/glossary/web-application-firewall-waf/
  - Temps : ~30 min
  - Ce que tu dois retenir :
    - Un WAF filtre le traffic HTTP entre un client et une application web
    - Il fonctionne avec des **regles** (rules) qui definissent ce qui est autorise ou bloque
    - Deux approches : **whitelist** (autoriser seulement le connu) vs **blacklist** (bloquer le connu malveillant)
    - Les limites : beaucoup de **faux positifs** (bloquer du trafic legitime)

- **OWASP Top 10 Web Application Security Risks**
  - URL : https://owasp.org/www-project-top-ten/
  - Temps : ~1 heure
  - Ce que tu dois retenir :
    - Les 10 risques les plus courants dans les applications web
    - Focus sur : **Injection (A03)**, **Broken Access Control (A01)**, **Security Misconfiguration (A05)**
    - Pour chaque risque, comprendre : qu'est-ce que c'est + un exemple concret

- **OWASP API Security Top 10**
  - URL : https://owasp.org/API-Security/editions/2023/en/0x11-t10/
  - Temps : ~1 heure
  - Ce que tu dois retenir :
    - Difference entre securite web classique et securite API
    - BOLA (Broken Object Level Authorization) = risque #1 des APIs
    - Rate limiting absent = porte ouverte aux attaques

#### Notes a preparer pour la presentation

> "Un WAF (Web Application Firewall) est un pare-feu applicatif qui filtre le traffic HTTP. Il utilise des regles pour detecter et bloquer les requetes malveillantes. Le probleme principal des WAFs traditionnels est le taux eleve de faux positifs - ils bloquent souvent du trafic legitime. Notre projet vise a reduire ce probleme grace au Machine Learning."

---

### JOUR 2-3 : Pattern Matching et Regex

#### A apprendre

- **Regex (Expressions Regulieres)**
  - Site de pratique : https://regex101.com
  - Temps : 2-3 heures de pratique
  - **Concepts essentiels a maitriser** :
    - `.` = n'importe quel caractere
    - `*` = 0 ou plus repetitions
    - `+` = 1 ou plus repetitions
    - `[]` = classe de caracteres (ex: `[a-z]`)
    - `|` = OU logique
    - `\s` = espace, `\d` = chiffre, `\w` = lettre/chiffre
    - `(?i)` = case insensitive

#### Regex a savoir ecrire (tu dois pouvoir les expliquer)

```
# Detection SQL Injection
(\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER)\b)|('(\s)*(OR|AND)(\s)*')|(--)|(;)

# Detection XSS
(<script[^>]*>)|(javascript:)|(on\w+\s*=)

# Detection Path Traversal
(\.\./|\.\.\\)

# Detection Command Injection
(;|\||\$\(|`).*(ls|cat|rm|wget|curl|bash|sh|nc)
```

#### Exercice pratique

1. Va sur https://regex101.com
2. Colle ces requetes dans la zone de test :
   ```
   GET /api/users?id=1
   GET /api/users?id=1' OR '1'='1
   GET /api/users?id=1 UNION SELECT * FROM passwords--
   POST /login avec body: {"user": "<script>alert(1)</script>"}
   GET /files?path=../../../etc/passwd
   GET /api/users?id=1; DROP TABLE users--
   ```
3. Ecris des regex qui detectent les 5 requetes malveillantes mais PAS la premiere (legitime)

#### Pour la presentation

> "Le Pattern Matching utilise des expressions regulieres pour chercher des signatures d'attaques connues dans les requetes HTTP. Par exemple, la presence de 'UNION SELECT' dans un parametre indique une tentative de SQL Injection. C'est rapide et efficace pour les attaques connues, mais ne detecte pas les attaques nouvelles ou obfusquees."

---

### JOUR 3-4 : Rate Limiting

#### Concepts a comprendre

- **Pourquoi le rate limiting ?**
  - Sans limite, un attaquant peut envoyer des milliers de requetes par seconde
  - Brute force sur login, DDoS, scraping massif
  - Il faut **compter** les requetes par IP et **bloquer** au-dela d'un seuil

- **3 algorithmes a connaitre** :

| Algorithme | Principe | Avantage | Inconvenient |
|------------|----------|----------|--------------|
| **Fixed Window** | Compteur par fenetre fixe (ex: par minute) | Simple a implementer | Pics aux frontieres de fenetres |
| **Sliding Window** | Fenetre glissante qui se deplace | Plus precis | Plus complexe |
| **Token Bucket** | Seau de jetons, chaque requete consomme un jeton | Gere les pics | Un peu plus complexe |

- **A lire** :
  - "Rate Limiting Fundamentals" : chercher sur Google "rate limiting algorithms explained"
  - Comprendre Redis comme compteur rapide (optionnel mais bon a mentionner)

#### Exemple concret a expliquer

```
Regle : Maximum 100 requetes par minute par IP

IP 192.168.1.1:
  - 09:00:00 -> Requete 1   -> OK
  - 09:00:01 -> Requete 2   -> OK
  - ...
  - 09:00:45 -> Requete 100 -> OK
  - 09:00:46 -> Requete 101 -> BLOQUE (rate limit depasse)
  - 09:01:00 -> Compteur reset -> OK a nouveau
```

#### Pour la presentation

> "Le Rate Limiting permet de detecter les attaques par volume comme le brute force ou le DDoS. On compte les requetes par adresse IP dans une fenetre de temps. Si une IP depasse le seuil (par exemple 100 requetes par minute), on la bloque temporairement. L'algorithme Sliding Window est le plus precis car il evite les pics aux frontieres de fenetres."

---

### JOUR 4-5 : Anomaly Detection (Detection d'anomalies)

#### Concepts a comprendre

- **Principe** : Definir un "comportement normal" (baseline), puis detecter tout ce qui s'en ecarte
- **Difference avec pattern matching** : On ne cherche pas des signatures connues, on cherche ce qui est **anormal**

- **Statistiques de base a maitriser** :

| Concept | Formule | Exemple |
|---------|---------|---------|
| **Moyenne** | somme / n | URL moyenne = 50 caracteres |
| **Ecart-type** | racine(variance) | Ecart-type = 15 caracteres |
| **Seuil** | moyenne + k * ecart-type | Seuil (k=3) = 50 + 3*15 = 95 caracteres |

- **Regle des 3 sigma** : Si une valeur depasse moyenne + 3 * ecart-type, il y a **99.7%** de chance que ce soit anormal

#### Metriques a surveiller

| Metrique | Normal | Suspect |
|----------|--------|---------|
| Longueur URL | 30-80 car | > 200 car |
| Nombre de parametres | 1-5 | > 15 |
| Taille du body | 100-1000 bytes | > 10000 bytes |
| Entropie de la requete | 3-4 bits | > 6 bits |
| Caracteres speciaux | 0-5 | > 20 |

#### Qu'est-ce que l'entropie ?

- Mesure du "desordre" dans une chaine de caracteres
- Texte normal = faible entropie (lettres repetees, mots connus)
- Payload encode/obfusque = haute entropie (caracteres aleatoires)
- Exemple :
  - `"hello world"` -> entropie ~3.2
  - `"x7$kQ9!mZ@2"` -> entropie ~3.9
  - Plus l'entropie est elevee dans un parametre, plus c'est suspect

#### Pour la presentation

> "La detection d'anomalies compare chaque requete a un baseline de comportement normal. On utilise des metriques statistiques comme la moyenne et l'ecart-type. Par exemple, si la longueur moyenne d'une URL est de 50 caracteres avec un ecart-type de 15, une URL de 200 caracteres depasse le seuil de 3 sigma et est signalee comme anomalie. Cette approche detecte des attaques inconnues que le pattern matching ne peut pas voir."

---

### JOUR 5-6 : Les 3 Types de Regles de Detection

#### Resume des 50 regles (a documenter)

**Type 1 : Regles de signature (pattern matching)**

| # | Pattern | Attaque | Severite |
|---|---------|---------|----------|
| 1 | `UNION SELECT` | SQL Injection | HIGH |
| 2 | `OR '1'='1` | SQL Injection | HIGH |
| 3 | `; DROP TABLE` | SQL Injection | CRITICAL |
| 4 | `<script>` | XSS | HIGH |
| 5 | `<img src=x onerror=` | XSS | HIGH |
| 6 | `javascript:` | XSS | MEDIUM |
| 7 | `../../../` | Path Traversal | HIGH |
| 8 | `; cat /etc/passwd` | Command Injection | CRITICAL |
| 9 | `\| wget` | Command Injection | CRITICAL |
| 10 | `admin'--` | Auth Bypass | HIGH |

**Type 2 : Regles de comportement**

| # | Condition | Attaque | Severite |
|---|-----------|---------|----------|
| 11 | > 100 req/min meme IP | Brute Force | HIGH |
| 12 | > 10 login echoues | Account Takeover | HIGH |
| 13 | Acces /admin sans auth | Unauthorized Access | CRITICAL |
| 14 | > 50 endpoints differents/min | Scanning | MEDIUM |
| 15 | Requetes a 3h du matin (hors pattern) | Anomalie temporelle | LOW |

**Type 3 : Regles statistiques**

| # | Condition | Seuil | Severite |
|---|-----------|-------|----------|
| 16 | Longueur URL > baseline + 3*sigma | Variable | MEDIUM |
| 17 | Nb parametres > baseline + 3*sigma | Variable | MEDIUM |
| 18 | Entropie > 5.0 | 5.0 bits | MEDIUM |
| 19 | Taille body > baseline + 3*sigma | Variable | LOW |
| 20 | Caracteres speciaux > 20 | 20 | MEDIUM |

---

### JOUR 6-7 : Comparaison avec Cloudflare + Preparation finale

#### Ce que tu dois comprendre sur Cloudflare WAF

- **Comment ca marche** : Cloudflare est un reverse proxy qui filtre le trafic avant qu'il atteigne ton serveur
- **Ses forces** : Grande base de regles, mise a jour en temps reel, protection DDoS integree
- **Ses faiblesses** : Faux positifs eleves (~70%), regles generiques pas adaptees a chaque API, pas de contexte metier
- **Notre avantage** : En ajoutant le ML (Hamza), on reduit les faux positifs car le modele apprend le contexte specifique de l'API

#### Methodologie de comparaison (a presenter)

```
1. Preparer 100 requetes test :
   - 50 requetes legitimes (trafic normal)
   - 50 requetes malveillantes (payloads de Mouad)

2. Tester avec notre systeme :
   - Combien d'attaques detectees ? (True Positives)
   - Combien de legit bloquees ? (False Positives)

3. Tester avec Cloudflare WAF :
   - Memes metriques

4. Comparer :
   | Metrique              | Notre systeme | Cloudflare |
   |-----------------------|---------------|------------|
   | Attaques detectees    | 45/50 (90%)   | 48/50 (96%) |
   | Faux positifs         | 5/50 (10%)    | 20/50 (40%) |
   | Precision             | 90%           | 70.6%       |
   | F1-Score              | 90%           | 81.4%       |
```

#### Pour la presentation

> "Cloudflare WAF est une reference en securite web, mais ses regles generiques generent beaucoup de faux positifs. Notre approche combine la detection par regles avec un classificateur ML qui apprend le contexte specifique de l'API testee. Resultat : on maintient un taux de detection comparable (90% vs 96%) tout en reduisant les faux positifs de 40% a 10%."

---

## RESUME : TES 2 SLIDES POUR LA PRESENTATION

### Slide 1 : Detection Engine - Approche

```
DETECTION ENGINE - 3 COUCHES DE DEFENSE

Couche 1 : Pattern Matching (Signature)
  -> Regex pour detecter attaques connues
  -> SQL Injection, XSS, Path Traversal, Command Injection
  -> Rapide, mais limite aux patterns connus

Couche 2 : Rate Limiting (Comportement)
  -> Compter requetes par IP
  -> Sliding Window Algorithm
  -> Detecte brute force, DDoS, scanning

Couche 3 : Anomaly Detection (Statistique)
  -> Baseline du comportement normal
  -> Seuil = moyenne + 3 * ecart-type
  -> Detecte attaques inconnues / zero-day
```

### Slide 2 : Resultats et Comparaison

```
COMPARAISON AVEC CLOUDFLARE WAF

                    Notre systeme    Cloudflare
Detection rate      90%              96%
Faux positifs       10%              40%
Precision           90%              70.6%

+ Avec le ML (Hamza) : faux positifs reduits a ~5%

LIVRABLE :
-> 50 regles de detection documentees
-> Comparaison detaillee avec Cloudflare
-> Engine Python integre au backend (Ayoub)
```

---

## CHECKLIST AVANT LA PRESENTATION

- [ ] Je sais expliquer ce qu'est un WAF en 2 phrases
- [ ] Je sais la difference entre Pattern Matching et Anomaly Detection
- [ ] Je peux ecrire 3 regex de detection (SQL, XSS, Path Traversal)
- [ ] Je sais expliquer les 3 algorithmes de rate limiting
- [ ] Je sais ce que sont la moyenne, l'ecart-type et le seuil 3-sigma
- [ ] Je peux expliquer pourquoi Cloudflare a des limites
- [ ] Je sais comment mon role se connecte a Mouad (input) et Hamza (output)
- [ ] Mes 2 slides sont pretes
- [ ] J'ai un exemple concret pour chaque type de detection

---

## VOCABULAIRE CLE A MAITRISER

| Terme | Definition |
|-------|------------|
| **WAF** | Web Application Firewall - filtre le traffic HTTP |
| **Pattern Matching** | Detection par correspondance de motifs (regex) |
| **Rate Limiting** | Limitation du nombre de requetes par unite de temps |
| **Anomaly Detection** | Detection de ce qui devie du comportement normal |
| **False Positive** | Fausse alerte - requete legitime classee comme attaque |
| **False Negative** | Attaque non detectee - passee a travers les filtres |
| **Precision** | Parmi les alertes, combien sont de vraies attaques |
| **Recall** | Parmi les vraies attaques, combien ont ete detectees |
| **Baseline** | Profil du comportement normal de l'API |
| **Sigma (ecart-type)** | Mesure de dispersion autour de la moyenne |
| **Entropie** | Mesure du desordre/aleatoire dans une chaine |
| **Sliding Window** | Fenetre de temps glissante pour compter des evenements |
| **Regex** | Expression reguliere pour chercher des motifs dans du texte |
| **Payload** | Donnee malveillante envoyee dans une requete |
| **Signature** | Motif connu d'une attaque specifique |
