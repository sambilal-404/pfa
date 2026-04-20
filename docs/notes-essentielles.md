# PFA - Detection Automatisee d'Anomalies dans les APIs REST

## Notes Essentielles du Projet

---

## 1. Problematique

- Les APIs REST sont devenues la **surface d'attaque #1** dans les applications modernes
- Le fuzzing manuel est **trop lent** et ne couvre pas assez de cas
- Les WAFs traditionnels (ex: Cloudflare) generent **trop de faux positifs (~70%)**
- Il manque une solution qui combine **fuzzing automatique + detection temps reel + ML**

## 2. Solution Proposee

Un systeme complet en 4 modules complementaires :

```
   [Mouad: Fuzzing Engine]
            |
            v
   [Bilal: Detection Engine]  <-->  [Hamza: ML Classifier]
            |
            v
   [Ayoub: Backend + Dashboard]
```

**Objectif cle** : Reduire les faux positifs de **70% a ~10%** grace au ML.

---

## 3. Les 4 Roles

### MOUAD - Fuzzing Engine (Le Hacker)

**Mission** : Generer automatiquement des attaques contre les APIs pour les tester.

| Etape | Periode | Livrable |
|-------|---------|----------|
| Comprendre OWASP API Top 10 | Mois 1-2 | Document avec explication + exemple par vulnerabilite |
| Creer les payloads | Mois 3-4 | Base de donnees de 500+ payloads (SQL Injection, XSS, Path Traversal...) |
| Automatiser le fuzzing | Mois 5-6 | Outil de fuzzing fonctionnel + rapport vulnerabilites |

**OWASP API Top 10 a couvrir** :
1. BOLA - Acces aux objets d'autres utilisateurs
2. Broken Auth - Bypass de l'authentification
3. Excessive Data - API retourne trop d'infos
4. Rate Limiting - Pas de limite de requetes
5. BFLA - Acces aux fonctions admin
6. Mass Assignment - Modifier des champs interdits
7. Misconfiguration - Erreurs de config
8. Injection - SQL/Command injection
9. Old Versions - Anciennes versions encore actives
10. Logging - Pas de logs des attaques

**Exemples de payloads** :
- SQL Injection (100) : `' OR '1'='1`, `' UNION SELECT NULL--`, `'; DROP TABLE users--`
- XSS (50) : `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`
- Path Traversal (30) : `../../../etc/passwd`, `....//....//etc/passwd`

---

### BILAL - Detection Engine (Le Defenseur)

**Mission** : Regarder le traffic API et detecter quand quelque chose est suspect.

| Etape | Periode | Livrable |
|-------|---------|----------|
| Comprendre la detection | Mois 1-2 | Maitrise pattern matching, rate limiting, anomaly detection |
| Construire les regles | Mois 3-4 | Fichier avec 50 regles documentees (pattern + severite + description) |
| Comparer avec Cloudflare | Mois 5-6 | Tableau comparatif + graphiques + conclusion |

**3 Piliers de la detection** :

1. **Pattern Matching** - Regex pour detecter signatures d'attaques connues
2. **Rate Limiting** - Compter requetes par IP, bloquer si > seuil (ex: >100 req/min)
3. **Anomaly Detection** - Comparer requete actuelle vs baseline normal (statistiques)

**3 Types de regles** :

| Type | Exemple | Severite |
|------|---------|----------|
| Signature | Requete contient `UNION SELECT` -> SQL Injection | HIGH |
| Comportement | Meme IP > 100 req/min -> Brute Force | MEDIUM |
| Statistique | Longueur URL > moyenne + 3*ecart-type -> Anomalie | LOW-HIGH |

**Comparaison Cloudflare** (objectif) :
- 100 requetes test (50 legit + 50 attaques)
- Comparer detection rate, precision, faux positifs
- Conclusion : "Notre systeme + ML reduit faux positifs de 75%"

---

### HAMZA - ML Classifier (Le Data Scientist)

**Mission** : Entrainer un modele qui distingue vraies attaques vs faux positifs.

| Etape | Periode | Livrable |
|-------|---------|----------|
| Collecter et labelliser donnees | Mois 1-2 | CSV avec 10k requetes (5k legit + 5k malveillantes) |
| Feature Engineering | Mois 3-4 | Script Python extraction features + analyse importance |
| Entrainer le modele | Mois 5-6 | Modele .pkl + rapport evaluation + API prediction |

**Features a extraire (20-30)** :

| Categorie | Features |
|-----------|----------|
| Longueurs | Longueur URL, longueur body, nombre parametres |
| Caracteres | Nb caracteres speciaux, ratio chiffres/lettres, entropie |
| Patterns | Mots-cles SQL? Balises HTML? Caracteres encodes? |

**Objectifs du modele** :
- Accuracy > 90%
- Precision > 85%
- Recall > 90%
- False Positive Rate < 10%

**Modeles recommandes** : XGBoost ou Random Forest

**Sources de donnees** : HTTP DATASET CSIC 2010, traffic normal API publique, attaques de Mouad

---

### AYOUB - Data & Integration (L'Architecte)

**Mission** : Assembler le tout : backend, database, frontend, integration.

| Etape | Periode | Livrable |
|-------|---------|----------|
| Backend API (FastAPI) | Mois 1-3 | Endpoints fonctionnels + doc Swagger |
| Database et stockage | Mois 2-4 | Schema PostgreSQL + scripts migration |
| Frontend dashboard | Mois 4-6 | Dashboard React responsive |

**Endpoints API** :
```
POST /fuzz       -> Lance fuzzing (Mouad)
GET  /results    -> Recupere resultats
POST /detect     -> Detecte anomalie (Bilal)
POST /classify   -> Classifie avec ML (Hamza)
GET  /dashboard  -> Stats pour frontend
```

**Tables DB** : `requests`, `detections`, `classifications`, `reports`

**Pages Frontend** :
1. Configuration (entrer URL API cible)
2. Lancement (bouton "Start Fuzzing")
3. Resultats (liste vulnerabilites)
4. Statistiques (graphiques)

---

## 4. Stack Technique

| Categorie | Technologie |
|-----------|-------------|
| Backend | Python, FastAPI |
| Frontend | React |
| ML | XGBoost / Random Forest, scikit-learn |
| Database | PostgreSQL |
| Infra | Docker |
| WAF reference | Cloudflare, ModSecurity |

---

## 5. Planning Global

| Periode | Objectif |
|---------|----------|
| Mois 1-2 | Recherche + Collecte donnees |
| Mois 3-4 | Developpement des modules |
| Mois 5-6 | Integration + Tests + Comparaison |

---

## 6. Livrables Finaux

- Plateforme web fonctionnelle (fuzzing + detection + ML + dashboard)
- Dataset annote (10 000 requetes)
- Modele ML (>90% accuracy)
- Rapport comparatif vs Cloudflare
- Base de donnees de 500+ payloads
- 50 regles de detection documentees

---

## 7. Innovation du Projet

- **Combinaison unique** : Fuzzing + Detection + ML dans un seul systeme
- **Reduction significative des faux positifs** : de 70% a ~10%
- **Open-source** : contribution a la communaute securite
- **Competences marche** : API security est un domaine tres demande

---

## 8. Cles du Succes

1. **Communication** : Se parler souvent entre membres
2. **Integration** : Tester ensemble regulierement
3. **Documentation** : Tout documenter au fur et a mesure
4. **Demos** : Faire des demos mensuelles au professeur

---

## 9. Structure de la Presentation (10-15 slides)

| Slide | Contenu | Duree |
|-------|---------|-------|
| 1 | Titre + Noms + Encadrant | - |
| 2 | Problematique (APIs = attaque #1, WAFs = faux positifs) | 1 min |
| 3 | Solution proposee (Fuzzing + Detection + ML) | 1 min |
| 4 | Architecture generale (diagramme 4 modules) | 1 min |
| 5 | Mouad - Fuzzing Engine | 2 min |
| 6 | Bilal - Detection Engine | 2 min |
| 7 | Hamza - ML Classifier | 2 min |
| 8 | Ayoub - Integration & Backend | 2 min |
| 9 | Technologies utilisees | 1 min |
| 10 | Planning / Timeline | 1 min |
| 11 | Livrables attendus | 1 min |
| 12 | Innovation | 1 min |
| 13 | Questions | - |
