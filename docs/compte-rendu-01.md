# Fiche 01 — Compte rendu #01 de PFA

**Séance 1 : Introduction, kickoff, cadrage du PFA de GSICS 4ème année**

---

## Titre et numéro du PFA selon la liste

Détection Automatisée d'Anomalies dans les APIs REST

---

## Membres présents du projet

- **Bilal SAMMER** — Detection Engine (Le Défenseur)
- **Mouad** — Fuzzing Engine (Le Hacker)
- **Hamza** — ML Classifier (Le Data Scientist)
- **Ayoub** — Backend, Data & Intégration (L'Architecte)

---

## Matrice SWOT de l'équipe

> *Correspond à l'onglet "SWOT de l'équipe" du fichier `Suivi de Projet (PFA).xlsx`. À remplir également dans le fichier Excel joint.*

### Forces

- Combinaison unique : Fuzzing + Détection + ML dans un seul système
- Réduction significative des faux positifs (de 70% à ~10%)
- Stack technique moderne et maîtrisée (Python, FastAPI, React, PostgreSQL, Docker)
- Architecture hybride 3 couches (Pattern Matching + Rate Limiting + Anomaly Detection)
- Répartition claire des rôles (chaque membre a un module dédié)

### Opportunités

- API Security est un domaine très demandé sur le marché de l'emploi
- Contribution open-source à la communauté sécurité
- OWASP API Top 10 fournit un cadre de référence solide et reconnu
- Compétences acquises directement valorisables professionnellement
- Encadrement académique par Pr Y.REGAD (Product Owner)

### Faiblesses

- Équipe sans expérience préalable en sécurité API avancée
- Dépendance forte entre les 4 modules (couplage inter-membres)
- Temps limité (~5 mois) pour un système complet
- Nécessité de collecter et labelliser un grand volume de données (10 000 requêtes)

### Menaces

- Solutions commerciales matures existantes (Cloudflare WAF, ModSecurity)
- Évolution rapide des techniques d'attaque (nouveaux vecteurs, obfuscation)
- Risque de faux négatifs si le modèle ML n'est pas suffisamment entraîné
- Difficulté à obtenir des datasets réalistes pour l'entraînement

### Brainstormings réalisés

| Brainstorming ID | Animateur | Idées trouvées/traitées | Solution retenue | Note/vote |
|------------------|-----------|-------------------------|------------------|-----------|
| (1) Réunion de cadrage / CdC | Bilal | Choix de l'approche hybride (Regex + Rate Limiting + Anomaly Detection + ML) vs WAF classique seul | Approche hybride 3 couches + ML | Unanime |
| (2) Réunion choix des outils | Mouad | Python/FastAPI vs Node/Express ; React vs Vue ; PostgreSQL vs MongoDB | Python/FastAPI + React + PostgreSQL + Docker | Unanime |

---

## Contexte reformulé (2–3 phrases)

Les APIs REST sont devenues la surface d'attaque numéro 1 dans les applications modernes. Les WAFs traditionnels (comme Cloudflare) utilisent des règles génériques qui génèrent un taux excessif de faux positifs (~70%), bloquant du trafic légitime et dégradant l'expérience utilisateur. Notre projet propose un système complet combinant fuzzing automatique, détection temps réel à 3 couches (signatures, comportement, anomalies statistiques) et classification par Machine Learning, afin de réduire les faux positifs à environ 10% tout en maintenant un taux de détection élevé (~90-95%).

---

## Approche choisie

**Agile** — Nous adoptons une approche Agile avec des sprints réguliers car le projet est modulaire (4 modules indépendants développés en parallèle par 4 membres). L'approche Agile nous permet d'itérer rapidement, d'intégrer les modules progressivement et de présenter des démos fonctionnelles au professeur encadrant à chaque sprint review. De plus, la nature exploratoire du volet ML (ajustement du modèle, feature engineering) nécessite une adaptation continue incompatible avec une approche prédictive rigide.

---

## Product Backlog — Tâches prévues (structure Jira / Excel de suivi)

> *Correspond à l'onglet "DÉTAILS DU PROJET (Product Backlog)" du fichier `Suivi de Projet (PFA).xlsx`.*
> Maître d'Ouvrage / Product Owner : **Pr Y.REGAD** (MCH) — y.regad@ump.ac.ma
> Date de démarrage : **12/03/2026**

### Tâches de Gestion et Analyse

| ÉTAT | PRIORITÉ | DATE DÉBUT | DATE FIN | NOM DE LA TÂCHE | RESPONSABLE | LIVRABLE | % TERMINÉ |
|------|----------|------------|----------|-----------------|-------------|----------|-----------|
| Pas encore commencé | Élevée | 12/03/26 | 22/03/26 | Tâche_GP 1 : Établir le CdC | Bilal | Cahier des Charges | 20% |
| Pas encore commencé | Moyenne | 12/03/26 | 19/03/26 | Tâche_GP 2 : Charte de Projet | Mouad | Charte de Projet | 0% |
| Pas encore commencé | Élevée | 12/03/26 | — | Tâche_GP 3 : Contrats & conventions | Hamza | Contrats | 0% |
| Pas encore commencé | Moyenne | 12/03/26 | 19/03/26 | Tâche_GP 4 : Matrice SWOT | Ayoub | Analyse SWOT | 0% |
| Pas encore commencé | Moyenne | 12/03/26 | 19/03/26 | Tâche_GP 5 : Matrice RACI | Bilal | Matrice RACI | 0% |
| Pas encore commencé | Faible | 12/03/26 | 19/03/26 | Tâche_GP 6 : Mise en place outils communication | Mouad | Liens outils | 0% |

### Tâches d'Exécution et Conduite

| ÉTAT | PRIORITÉ | DATE DÉBUT | DATE FIN | NOM DE LA TÂCHE | RESPONSABLE | LIVRABLE | % TERMINÉ |
|------|----------|------------|----------|-----------------|-------------|----------|-----------|
| Pas encore commencé | Élevée | — | — | Tâche 1 : Étude OWASP API Top 10 | Mouad | Document OWASP | 0% |
| Pas encore commencé | Élevée | — | — | Tâche 2 : Conception Detection Engine | Bilal | Architecture 3 couches | 0% |
| Pas encore commencé | Élevée | — | — | Tâche 3 : Collecte dataset ML | Hamza | CSV 10k requêtes | 0% |
| Pas encore commencé | Élevée | — | — | Tâche 4 : Setup Backend FastAPI | Ayoub | Endpoints + Swagger | 0% |
| Pas encore commencé | Élevée | — | — | Tâche 5 : Création base de payloads | Mouad | 500+ payloads | 0% |
| Pas encore commencé | Élevée | — | — | Tâche 6 : Implémentation 50 règles détection | Bilal | Fichier règles | 0% |
| Pas encore commencé | Élevée | — | — | Tâche 7 : Feature Engineering ML | Hamza | Script extraction | 0% |
| Pas encore commencé | Élevée | — | — | Tâche 8 : Schéma DB PostgreSQL | Ayoub | Scripts migration | 0% |
| Pas encore commencé | Élevée | — | — | Tâche 9 : Intégration & Tests finaux | Tous | Plateforme complète | 0% |

---

## Estimation du projet (vision stratégique SWOT, côté temps)

> *Basée sur le planning de sprints bi-hebdomadaires (2 semaines) du fichier `Suivi de Projet (PFA).xlsx`. Date de démarrage : 12/03/2026.*

| Phase | Sprints | Période | Description |
|-------|---------|---------|-------------|
| Phase 1 — Cadrage & CdC | Sprint 1 | 12/03 au 25/03 | Cahier des Charges, SWOT, RACI, Charte de Projet, mise en place outils |
| Phase 2 — Recherche & Conception | Sprint 2–3 | 26/03 au 22/04 | Étude OWASP, conception architecture, collecte dataset, setup backend |
| Phase 3 — Développement | Sprint 4–7 | 23/04 au 17/06 | Implémentation des 4 modules en parallèle (fuzzing, détection, ML, backend) |
| Phase 4 — Intégration & Tests | Sprint 8–9 | 18/06 au 15/07 | Intégration Docker, tests end-to-end, comparaison vs Cloudflare |
| Phase 5 — Finalisation | Sprint 10–11 | 16/07 au 12/08 | Dashboard final, rapport, optimisation ML, préparation soutenance |

**Durée totale estimée : ~5 mois (11 sprints de 2 semaines)**
**Budget estimé : 15 150,00 MAD**
**RH : 4 membres**

---

## Outils informatiques choisis pour la communication

### Entre les membres de l'équipe :
- **WhatsApp / Discord** — Communication quotidienne et discussions techniques rapides
- **GitHub** — Gestion du code source, issues, pull requests, code reviews
  - *Lien repo :* *(à compléter : https://github.com/votre-org/pfa-api-security)*
- **Google Drive** — Partage de documents, rapports, présentations
  - *Lien :* *(à compléter)*

### Entre l'équipe et les encadrants :
- **Email** — Communication formelle et envoi des livrables (bilal.sammer.23@ump.ac.ma)
- **Présentations bi-hebdomadaires** — Sprint review en présentiel chaque 2 semaines avec le professeur encadrant
- **Google Drive** — Dépôt des comptes rendus et des documents de suivi

---

## Actions prochaines (Sprint 2)

1. **Bilal** : Commencer l'implémentation Python des 50 premières règles de détection (Pattern Matching avec Regex pour SQLi, XSS, Path Traversal, Command Injection) et du Rate Limiting avec l'algorithme Sliding Window.
2. **Mouad** : Finaliser la documentation du OWASP API Top 10 avec un exemple concret par vulnérabilité, et commencer la création de la base de payloads (objectif : 100 premiers payloads SQLi).
3. **Hamza** : Commencer la collecte du dataset — identifier les sources (HTTP DATASET CSIC 2010, trafic normal API publique) et préparer le script Python d'extraction des features (longueurs, caractères spéciaux, entropie).
4. **Ayoub** : Initialiser le projet FastAPI avec les premiers endpoints (`POST /detect`, `GET /results`), mettre en place le schéma PostgreSQL et le Dockerfile.

---

## Choix de la fréquence du sprint

**2 semaines** (chaque 2 semaines à fournir le compte rendu "sprint review")

---

## Parties clés de la fiche synthétique à remplir en premier pour le sprint présent

> *Réfère aux onglets du fichier `Suivi de Projet (PFA).xlsx` fourni par le professeur.*

1. **Tableau de Bord (onglet principal)** — Remplir les méta-données du projet : date MàJ, nombre de jours, nombre de personnes (4), RH estimées, avancement (%), risques, phase actuelle (CdC), budget estimé.
2. **Product Backlog (DÉTAILS DU PROJET)** — Remplir les premières tâches de gestion (Tâche_GP 1 à 9) avec : état, priorité, dates début/fin, responsable, livrable, % terminé, heures estimées vs réelles.
3. **Kanban de Projet** — Remplir le tableau Kanban avec les 4 membres (Bilal, Mouad, Hamza, Ayoub) et dispatcher les tâches dans les colonnes : "À faire", "En cours", "Terminé". Remplir le Sprint Backlog du Sprint 1.
4. **Matrice RACI** — Attribuer les rôles R (Réalisateur), A (Approbateur), C (Consulté), I (Informé) pour chaque tâche et chaque membre.
5. **SWOT de l'équipe** — Remplir les 4 quadrants : Forces, Faiblesses, Opportunités, Menaces.
6. **Table des Documents du Projet** — Créer le dossier "Dossier PFA" sur Google Drive, y déposer le Cahier des Charges, et renseigner le lien partagé.

---

## État d'avancement — Tableau de bord et KPIs

> *Correspond à l'en-tête "Tableau de Bord" du fichier `Suivi de Projet (PFA).xlsx`.*

### Indicateurs du Tableau de Bord (valeurs actuelles)

| Indicateur | Valeur Sprint 1 |
|------------|-----------------|
| Date MàJ | 12/03/2026 |
| Nombre de jours du projet | 0 jours |
| Nombre de personnes (RH) | 4 |
| RH estimées | 4 |
| Avancement global (%) | 0% |
| Risques | 0 (aucun risque identifié à ce stade) |
| Phase Actuelle | CdC (Cahier des Charges) |
| Budget estimé | 15 150,00 MAD |

### KPIs par catégorie de tâches

| Catégorie | % Terminé | Coût fixe | Heures estimées | Heures réelles |
|-----------|-----------|-----------|-----------------|----------------|
| Tâches de Gestion et Analyse | 0% | 15 150,00 MAD | 10 | 0 |
| Tâches d'Exécution et Conduite | 0% | 0,00 MAD | 0 | 0 |

### Kanban du Sprint 1 (12/03 au 25/03)

| Membre | À faire | En cours | Terminé |
|--------|---------|----------|---------|
| Bilal | Établir le CdC, Matrice RACI | — | — |
| Mouad | Charte de Projet, Mise en place outils comm. | — | — |
| Hamza | Contrats & conventions | — | — |
| Ayoub | Matrice SWOT | — | — |

### Sprint Planning

| Sprint | Période | Backlog | Rétrospective | Incrément Produit |
|--------|---------|---------|---------------|-------------------|
| Sprint 1 | 12/03 au 25/03 | Cadrage, CdC, SWOT, RACI, Charte | *(à remplir en fin de sprint)* | *(à remplir en fin de sprint)* |
| Sprint 2 | 26/03 au 08/04 | *(à planifier)* | | |
| Sprint 3 | 09/04 au 22/04 | *(à planifier)* | | |
| Sprint 4 | 23/04 au 06/05 | *(à planifier)* | | |
| Sprint 5 | 07/05 au 20/05 | *(à planifier)* | | |

**Scrum Master :** *(Nom du chef de projet — à compléter)*
**Product Owner :** Pr Y.REGAD
**Fréquence Sprint :** 2 semaines

**Commentaire Sprint 1 :** Le sprint 1 (2 semaines) est consacré au cadrage du projet : rédaction du Cahier des Charges, élaboration de la matrice SWOT et RACI, rédaction de la Charte de Projet, et mise en place des outils de communication. Aucune tâche d'exécution n'a encore démarré. Le projet est en phase initiale (phase CdC).

---

## Matrice RACI

> *Correspond à l'onglet "La matrice RACI" du fichier `Suivi de Projet (PFA).xlsx`.*
> R = Réalisateur | A = Approbateur/Responsable | C = Consulté | I = Informé

| Tâche | Bilal | Mouad | Hamza | Ayoub |
|-------|-------|-------|-------|-------|
| Tâche_GP 1 : Établir le CdC | R, A | C | I | I |
| Tâche_GP 2 : Charte de Projet | I | R, A | C | I |
| Tâche_GP 3 : Contrats & conventions | I | I | R, A | C |
| Tâche_GP 4 : Matrice SWOT | C | I | I | R, A |
| Tâche_GP 5 : Matrice RACI | R, A | I | I | C |
| Tâche_GP 6 : Mise en place outils comm. | C | R, A | I | I |
| Tâche 1 : Étude OWASP API Top 10 | C | R, A | I | I |
| Tâche 2 : Conception Detection Engine | R, A | C | C | I |
| Tâche 3 : Collecte dataset ML | I | C | R, A | I |
| Tâche 4 : Setup Backend FastAPI | I | I | C | R, A |
| Tâche 5 : Création base de payloads | I | R, A | C | I |
| Tâche 6 : Implémentation 50 règles détection | R, A | C | C | I |
| Tâche 7 : Feature Engineering ML | C | I | R, A | I |
| Tâche 8 : Schéma DB PostgreSQL | I | I | C | R, A |
| Tâche 9 : Intégration & Tests finaux | R | R | R | R, A |

---

## Table des Documents du Projet

> *Correspond à l'onglet "Table des Documents du Projet" du fichier `Suivi de Projet (PFA).xlsx`.*
> Créer un dossier intitulé "Dossier PFA" dans votre Google Drive, puis partager son lien dans la colonne "Lien Partagé".

| N° | Titre du document (livrable) | Lien partagé via Google Drive | Commentaire |
|----|------------------------------|-------------------------------|-------------|
| 1 | Cahier des Charges | *(à compléter)* | À déposer dans le dossier "Dossier PFA" |
| 2 | Charte de Projet | *(à compléter)* | |
| 3 | Matrice SWOT (Excel) | *(à compléter)* | Fichier `Suivi de Projet (PFA).xlsx` — onglet SWOT |
| 4 | Matrice RACI | *(à compléter)* | Fichier `Suivi de Projet (PFA).xlsx` — onglet RACI |
| 5 | Document OWASP API Top 10 | *(à compléter)* | Livrable de Mouad |
| 6 | Base de payloads (500+) | *(à compléter)* | Livrable de Mouad |
| 7 | Fichier 50 règles de détection | *(à compléter)* | Livrable de Bilal |
| 8 | Rapport comparatif vs Cloudflare | *(à compléter)* | Livrable de Bilal |
| 9 | Dataset annoté (CSV 10k requêtes) | *(à compléter)* | Livrable de Hamza |
| 10 | Modèle ML (.pkl) + rapport évaluation | *(à compléter)* | Livrable de Hamza |
| 11 | Documentation API (Swagger) | *(à compléter)* | Livrable de Ayoub |
| 12 | Rapport final PFA | *(à compléter)* | |
| 13 | Présentation soutenance | *(à compléter)* | |
