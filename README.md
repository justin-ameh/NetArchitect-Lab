# NetArchitect Lab

NetArchitect Lab est un simulateur pédagogique, léger et local, permettant de concevoir une architecture réseau d’entreprise segmentée et d’obtenir une première analyse de sécurité.

## Fonctionnalités

- topologie WAN → pfSense → switch → VLAN/DMZ ;
- score de posture de sécurité ;
- recommandations adaptées aux options sélectionnées ;
- règles pfSense proposées selon le principe du moindre privilège ;
- rapport autonome téléchargeable et imprimable en PDF ;
- dimensionnement visuel du nombre d’équipements par zone ;
- génération d’un plan de montage GNS3 adapté à la topologie ;
- génération d’une procédure pfSense avec VLAN, DHCP, alias et règles ;
- export combiné des guides GNS3 et pfSense ;
- simulation de paquets entre Internet, pfSense, switch, postes, Wi-Fi et DMZ ;
- décision autorisée/bloquée selon les VLAN et les règles de pare-feu ;
- animation du trajet et journal des communications testées ;
- fonctionnement local, sans compte, cloud ou API payante ;
- interface responsive en français.
- analyse d’un exercice réseau rédigé en français et détection des équipements demandés ;
- génération automatique d’un schéma de topologie téléchargeable au format SVG ;

## Démarrage rapide

1. Décompressez le fichier ZIP.
2. Ouvrez le dossier `netarchitect-lab`.
3. Double-cliquez sur `index.html`.

L’application s’ouvre directement dans le navigateur, sans installation.

## Générer le schéma d’un exercice

1. Copiez l’énoncé donné par le professeur.
2. Collez-le dans la zone **Générateur de schéma depuis un exercice**.
3. Cliquez sur **Générer le schéma**.
4. Vérifiez les équipements et les zones détectés.
5. Cliquez sur **Télécharger le schéma SVG** pour remettre ou imprimer le résultat.

Le bouton **Insérer un exemple** permet de tester immédiatement la fonction.

## Démarrage avec un serveur local

Cette méthode est utile pendant le développement :

```bash
cd netarchitect-lab
python3 -m http.server 8080
```

Ouvrez ensuite `http://localhost:8080`.

## Tests

Avec Node.js 20 ou supérieur :

```bash
npm test
```

## Limites

L’analyse d’énoncé fonctionne localement avec des règles de reconnaissance de mots-clés. Elle traite les exercices réseau courants, mais l’étudiant doit vérifier le schéma lorsque l’énoncé est ambigu. L’outil fournit des recommandations pédagogiques. Il ne scanne pas réellement un réseau, ne remplace pas un audit professionnel et ne doit pas appliquer automatiquement des règles sur un pare-feu de production.

## Auteur

Projet conçu par Amèh Justin ANAGO dans le cadre de son parcours en Systèmes, Réseaux et Cybersécurité.
