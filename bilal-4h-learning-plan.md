# Plan d'Apprentissage Express - 4 Heures (Bilal)
*Objectif : Maîtriser le contenu technique d'une semaine entière en seulement 4 heures grâce à la règle des 80/20, l'apprentissage actif et la pratique ciblée.*

---

## 🕒 Bloc 1 : Fondations et Problématique (45 min)
*Le but de ce bloc est de comprendre le "Pourquoi". Inutile d'apprendre par cœur, il faut saisir les concepts.*

- **[15 min] Les limites du WAF :** 
  - Lis l'article de Cloudflare sur les WAFs.
  - Comprends la différence entre approche *Whitelist* (autoriser le connu) et *Blacklist* (bloquer le malveillant).
  - **Concept clé à retenir :** Les WAFs traditionnels ont un taux énorme de **Faux Positifs** (bloquer des utilisateurs normaux). C'est le problème exact que votre projet résout.
- **[20 min] L'état de l'art (OWASP) :** 
  - Survole le Top 10 Web et API. 
  - Ne retiens que 3 attaques fondamentales : **Injection** (envoyer du code au lieu de données), **BOLA** (accès aux données d'un autre utilisateur), et le manque de **Rate Limiting**.
- **[10 min] Restitution active :** 
  - Ferme tous tes onglets. Prends un papier et écris ton rôle exact en une phrase simple, comme si tu l'expliquais à un enfant de 10 ans. 

## 🕒 Bloc 2 : Pratique Intensive - Regex (1h)
*Le but de ce bloc est de comprendre le "Comment" pour bloquer les attaques connues (Couche 1 : Pattern Matching).*

- **[15 min] Les bases des Regex :** 
  - Ne lis pas des tutoriels infinis. Apprends uniquement les symboles critiques : `.*` (n'importe quoi), `+` (1 ou plusieurs), `[]` (un parmi ces choix), `|` (OU logique), et `\b` (limite de mot).
- **[35 min] Lab Pratique sur regex101.com :** 
  - Copie les 6 requêtes de test de ton plan (1 légitime, 5 malveillantes : SQLi, XSS, Path Traversal, Command Injection).
  - **Ton défi :** Écris les expressions régulières pour détecter les 5 attaques SANS détecter la requête légitime (`GET /api/users?id=1`). C'est le seul moyen d'ancrer la connaissance.
- **[10 min] Synthèse :** 
  - Formule à voix haute comment la couche de "Signature" fonctionne, et quelles sont ses limites (elle est aveugle aux nouvelles attaques).

## 🕒 Bloc 3 : Comportement et Statistiques (1h)
*Le but de ce bloc est d'apprendre à bloquer l'inconnu et les attaques Zero-Day (Couches 2 & 3).*

- **[20 min] Rate Limiting (Le volume) :** 
  - Regarde un schéma comparant *Fixed Window* et *Sliding Window*. 
  - Comprends pourquoi le Sliding Window est supérieur (il empêche les attaquants de tricher en envoyant des requêtes à la frontière de deux minutes).
- **[25 min] Mathématiques des Anomalies (La statistique) :** 
  - Assimile la règle des **3 sigma** (Moyenne + 3 * Écart-type). Fais un calcul mental : si l'URL moyenne fait 40 caractères, avec un écart de 10, le seuil d'anomalie est à 70.
  - Comprends le concept d'**Entropie**. L'entropie mesure le chaos. Un payload encodé malveillant a une entropie élevée comparé à du texte normal.
- **[15 min] Restitution active :** 
  - Dessine le flux d'une requête HTTP qui traverse tes 3 filtres (1. Regex -> 2. Limite de vitesse -> 3. Stats).

## 🕒 Bloc 4 : Synthèse et Préparation Professeur (1h 15 min)
*Le but de ce bloc est de préparer la restitution pour être incollable devant l'encadrant.*

- **[20 min] La proposition de valeur vs Cloudflare :** 
  - Mémorise la méthodologie de test. Pourquoi Cloudflare n'est pas parfait ? (Il n'a pas le contexte métier de votre API).
  - Mémorise la force de votre architecture : Ton moteur génère l'alerte, et le ML de Hamza filtre les faux positifs (objectif : chuter à 10% d'erreurs).
- **[40 min] Répétition de la Présentation :** 
  - Ouvre le fichier de présentation (`bilal-weekly-presentation.md`).
  - Chronomètre-toi. Répète le script 5 à 6 fois debout, à voix haute, en mettant l'accent sur les mots clés (Hybride, Sliding Window, 3-Sigma, Faux Positifs).
- **[15 min] Le Crash-Test final :** 
  - Reprends la "Checklist" de ton plan de la semaine. Coche chaque case mentalement. Prépare la réponse aux 3 questions pièges du fichier de présentation.
