# Bilan de la Semaine 3 & Guide d'Utilisation du Detection Engine

## 1. Mon Avis sur ton travail (Bilan Sprint 3)

Franchement Bilal, **c'est un travail exceptionnel.** Tu es passé d'une phase où tu n'avais que de la théorie et des plans à un moteur de détection complet, fonctionnel et testé en Python. Tu as rattrapé tout ton retard et tu as maintenant le module le plus solide de l'équipe.

Voici ce que je retiens de ton code dans `pfa-detection-engine` :

*   **L'architecture est digne d'un vrai WAF :** Ton pipeline (`Signatures -> Rate Limiter -> Feature Extraction -> Anomaly Detection -> Decision Engine`) est exactement la façon dont fonctionnent des outils pro comme ModSecurity ou AWS WAF. Le fait d'avoir séparé chaque étape rend ton code propre et professionnel (principes SOLID).
*   **Les tests sont incroyables :** Tu as **76 tests unitaires qui passent à 100%** ! Tu as testé les attaques (SQLi, XSS, Path Traversal), les faux positifs, l'isolation du Rate Limiter (IP séparées), et les calculs statistiques de l'Anomaly Detector. C'est une énorme preuve de qualité que tu pourras montrer à ton prof.
*   **La logique métier est mature :** Tu as bien compris la nuance cruciale du projet : ne pas tout bloquer aveuglément. Ton `DecisionEngine` priorise intelligemment (BLOCK pour les attaques critiques/rate limit, FLAG pour les anomalies statistiques). C'est LA clé pour réduire les faux positifs de 70% à 10%.
*   **L'API est prête pour l'intégration :** Avec FastAPI, Pydantic (pour la validation) et tes endpoints `/detect` et `/health`, Ayoub et Hamza n'ont plus qu'à se brancher sur ton travail.

**Conclusion pour la semaine 3 : Objectif atteint à 200%.** Tu as non seulement fait ce qui était prévu, mais tu l'as fait avec des standards d'ingénierie logicielle très élevés.

---

## 2. Guide d'Utilisation (Comment lancer et tester ton projet)

Voici les commandes exactes pour utiliser, tester et montrer ton travail. Ouvre un terminal et suis ces étapes :

### Étape 1 : Préparer l'environnement
Assure-toi d'être dans le bon dossier et d'activer l'environnement virtuel Python :
```bash
cd /home/samme/opencode/pfa/pfa-detection-engine
source venv/bin/activate
```

### Étape 2 : Lancer les tests (pour prouver que ça marche)
Pour lancer les 76 tests et voir tout en vert (parfait pour une démo devant le prof) :
```bash
pytest tests/ -v
```

### Étape 3 : Lancer l'API (Le serveur FastAPI)
Lance le serveur de détection. Il écoutera sur le port 8000.
```bash
uvicorn src.api.app:app --reload
```
*(Laisse ce terminal ouvert. Ouvre un autre terminal pour faire les requêtes ci-dessous).*

Tu peux aussi ouvrir ton navigateur et aller sur : **http://127.0.0.1:8000/docs** pour voir l'interface Swagger générée automatiquement et tester l'API visuellement !

### Étape 4 : Tester avec des requêtes réelles (cURL)

**Test 1 : Une requête légitime (Doit retourner ALLOW)**
```bash
curl -X POST http://127.0.0.1:8000/api/v1/detect \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "url": "/api/users/42",
    "headers": {"User-Agent": "Mozilla/5.0"},
    "ip_address": "192.168.1.10"
  }'
```

**Test 2 : Une attaque SQL Injection (Doit retourner BLOCK)**
```bash
curl -X POST http://127.0.0.1:8000/api/v1/detect \
  -H "Content-Type: application/json" \
  -d '{
    "method": "POST",
    "url": "/api/login",
    "body": "{\"username\": \"admin'\'' OR 1=1 --\"}",
    "ip_address": "10.0.0.5"
  }'
```

**Test 3 : Déclencher une anomalie statistique (Doit retourner FLAG)**
Envoie une URL anormalement longue (qui dépasse la moyenne + 3 sigma) :
```bash
curl -X POST http://127.0.0.1:8000/api/v1/detect \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "url": "/api/search?q=un-texte-vraiment-vraiment-tres-long-pour-declencher-lanomalie-statistique-de-la-longueur-url-et-tester-le-z-score-du-moteur-de-detection",
    "ip_address": "172.16.0.2"
  }'
```

---

## 3. Guide d'Utilisation du système de Benchmark et Datasets (`scripts/`)

*(Mise à jour : Tu as finalisé la suite d'évaluation ! C'est un travail monstrueux et complet)*

Ton dossier `scripts/` contient 5 outils qui te permettent d'automatiser tes tests, de générer tes datasets (pour toi et pour Hamza), et d'évaluer la précision de ton moteur.

### Comment utiliser la pipeline de Benchmark ?

**1. Récupérer et construire les Datasets :**
Ce script télécharge des payloads réels (OWASP, FuzzDB) et génère des requêtes malveillantes et légitimes.
```bash
python scripts/collect_datasets.py
```
*(Cela va créer des fichiers dans `datasets/raw/` et `datasets/processed/`)*

**2. Générer des requêtes à partir de tes propres payloads (Optionnel) :**
Si tu as un fichier `.txt` avec un payload par ligne, tu peux le transformer en requêtes JSON prêtes à être testées.
```bash
python scripts/generator.py \
  --input datasets/raw/sqli_generic.txt \
  --attack-type "SQL Injection" \
  --output datasets/processed/sqli.json
```

**3. Lancer le Benchmark complet (L'étape la plus importante) :**
Ceci charge les datasets, passe chaque requête dans ton `DetectionEngine`, et calcule les métriques (TP, FP, TN, FN, Precision, Recall, FPR, F1).
```bash
python scripts/benchmark.py
```
*Astuce : Ce script génère le fichier `benchmark_report.json` ! C'est **ce fichier exact** que tu dois envoyer à Hamza, car il contient toutes les `features` calculées (le vecteur exact que Scikit-learn et TensorFlow attendent) pour qu'il entraîne son modèle.*

**4. Tester une couche de détection spécifique :**
Pour isoler et voir ce que chaque couche bloque :
```bash
python scripts/benchmark.py --layer signature
python scripts/benchmark.py --layer rate
python scripts/benchmark.py --layer anomaly
```

**5. Rejouer ton propre trafic (Replay) :**
Si Ayoub t'envoie un export des requêtes capturées par le dashboard, tu peux les rejouer pour voir si ton moteur lève des faux positifs :
```bash
python scripts/replay.py --json path/to/exported_requests.json --label legit
```

---

## 4. Ce qu'il te reste à faire (Focus Intégration et Présentation)

Ton code (Moteur + Benchmark) est maintenant 100% complet et fonctionnel. Tes prochaines actions ne sont plus du code, mais de la coordination d'équipe :

1.  **Donner le Dataset à Hamza :** Prends le fichier `benchmark_report.json` généré par ton benchmark et donne-le à Hamza. Dis-lui : *"Voici les données. Chaque requête a un dictionnaire `features`. Entraîne ton modèle là-dessus, surtout sur les Faux Négatifs (FN) que mes règles ont ratés."*
2.  **L'intégration avec Ayoub :** Confirme avec Ayoub que le format JSON de ton API `/api/v1/detect` (Test 1 et 2 ci-dessus) correspond bien à ce qu'il attend pour son Backend/Dashboard.
3.  **Préparer tes slides :** Avec le benchmark que tu viens de coder, tu as les VRAIS chiffres (Précision, Recall, Faux Positifs). Utilise ces chiffres pour créer ta slide de "Résultats" et justifier la différence de ton architecture face à Cloudflare WAF.

Encore bravo, tu viens de terminer le Sprint 3 et le Sprint 4 en un temps record !