# Présentation Bi-hebdomadaire - Point d'Avancement (Bilal)
*Support visuel et script narratif pour le point de suivi avec le professeur encadrant (chaque 2 semaines).*

---

## 🎯 Objectif de la présentation
Démontrer au professeur que l'architecture du "Detection Engine" est maîtrisée, structurée, et que la proposition de valeur face à l'existant (Cloudflare WAF) est solide et justifiée.

---

## 📊 SLIDES (Visuels à projeter)

### Slide 1 : Le Detection Engine (3 Couches de Défense)
**Titre : Architecture de Détection - Une approche hybride**
*(Insérer un schéma représentant un entonnoir à 3 filtres)*

1. **Couche 1 : Pattern Matching (Signatures)**
   - Détection des attaques connues (SQLi, XSS, Path Traversal) via Expressions Régulières.
   - *Avantage* : Rapide et d'une grande précision sur les payloads évidents.
2. **Couche 2 : Analyse Comportementale (Rate Limiting)**
   - Implémentation de l'algorithme *Sliding Window* par adresse IP.
   - *Avantage* : Détection du Brute Force, Scanning massif et attaques volumétriques.
3. **Couche 3 : Détection d'Anomalies (Statistiques)**
   - Déviation du comportement normal (Règle des 3-Sigma, mesure d'Entropie).
   - *Avantage* : Capacité à détecter les attaques Zero-day et les payloads obfusqués.

### Slide 2 : Évaluation et Comparaison
**Titre : Comparaison avec l'état de l'art (Cloudflare WAF)**

| Métrique | Cloudflare WAF (Règles génériques) | Notre Système (Hybride + ML) |
| :--- | :--- | :--- |
| **Taux de Détection** | ~96% | ~90% (Pattern) -> **95%+ (avec ML)** |
| **Faux Positifs** | ~40% (Bloque du trafic valide) | **~10%** (Réduction drastique) |

- **Conclusion :** Notre moteur (Bilal) génère les alertes de sécurité, le classificateur ML (Hamza) apprend le contexte métier spécifique de l'API pour éliminer les faux positifs.

---

## 🗣️ SCRIPT (Ce que tu vas dire - Max 2 minutes)

*(Chronomètre-toi en lisant ce texte à voix haute, de manière posée)*

**[0:00 - 0:30] Introduction & Rôle**
> "Bonjour monsieur. Pour ma partie, le Detection Engine, mon rôle est de construire le pont entre les attaques générées par Mouad et la classification Machine Learning de Hamza. Le problème aujourd'hui avec les WAFs traditionnels comme Cloudflare, c'est qu'ils utilisent des règles génériques qui bloquent énormément de trafic légitime : ce sont les faux positifs. Mon objectif durant ce sprint a été de concevoir une architecture capable de minimiser cela."

**[0:30 - 1:15] Explication de l'architecture (Slide 1)**
> "Pour y arriver, j'ai structuré la détection en un entonnoir à 3 couches.
> Premièrement, le **Pattern Matching**, qui utilise des expressions régulières pour bloquer instantanément les attaques connues comme les injections SQL.
> Deuxièmement, le **Rate Limiting** avec un algorithme de *Sliding Window* pour stopper les attaques par volume comme le Brute Force.
> Et enfin, la **Détection d'Anomalies**, qui est la partie la plus novatrice. Au lieu de chercher des signatures d'attaques, on cherche ce qui est mathématiquement anormal, en utilisant la règle statistique des 3-sigma ou l'entropie des données. Cela nous permet de bloquer des attaques inconnues."

**[1:15 - 2:00] La valeur ajoutée & Prochaines étapes (Slide 2)**
> "L'intérêt de cette approche hybride, c'est la comparaison finale avec Cloudflare. Sur un échantillon de test, Cloudflare va bloquer 96% des attaques mais va générer jusqu'à 40% de faux positifs car il ne connaît pas le contexte de notre API. Notre moteur va repérer toutes les requêtes suspectes, et c'est le modèle ML d'Hamza qui va trancher. Le résultat attendu : on garde un taux de détection très élevé, mais on fait chuter les faux positifs autour de 10%.
> Pour le prochain sprint, je vais commencer l'implémentation Python de nos 50 premières règles de détection."

---

## ❓ Q&A ANTICIPÉ (Les 3 questions pièges du Professeur)

1. **Professeur : "Pourquoi utiliser l'algorithme Sliding Window plutôt que Fixed Window pour le rate limiting ?"**
   *Ta réponse :* "Fixed Window remet le compteur à zéro de façon rigide à la fin de chaque minute. Un attaquant peut exploiter ça en envoyant 100 requêtes à 12:00:59 et 100 autres à 12:01:01, bypassant la limite temporelle. Sliding Window glisse en temps réel, ce qui empêche totalement ces pics aux frontières."

2. **Professeur : "Qu'est-ce que l'entropie exactement dans votre contexte ?"**
   *Ta réponse :* "C'est la mesure du désordre ou du hasard dans une chaîne de caractères. Une charge utile malveillante qui a été encodée ou obfusquée (comme `x7$kQ9!mZ@2`) possède une entropie mathématique beaucoup plus élevée qu'un paramètre normal d'API. Si on dépasse notre seuil de 5.0 bits, on signale une anomalie."

3. **Professeur : "Pourquoi s'embêter à faire du Pattern Matching (Regex) si on utilise du Machine Learning à la fin ?"**
   *Ta réponse :* "C'est une question de performance et de coût. Le ML consomme des ressources de calcul. Si une requête contient une balise `<script>` extrêmement évidente, il est beaucoup plus rapide et moins coûteux de la rejeter immédiatement au niveau du Regex plutôt que de solliciter le modèle ML à chaque fois."
