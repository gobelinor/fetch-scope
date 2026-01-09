# Bug Bounty Scope Collector

Script bash pour automatiser la récupération et le traitement des scopes HackerOne et YesWeHack.

## Installation
```bash
# Installer les dépendances
go install github.com/sw33tLie/bbscope@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

## Configuration

Créer un fichier `.env` :
```bash
# HackerOne
HACKERONE_API_KEY=votre_api_key
HACKERONE_USERNAME=votre_username

# YesWeHack (optionnel)
YWH_API_KEY=votre_JWT_YWH
(il faut se connecter à YWH et recuperer votre cookie de session JWT pour le .env)

```

## Usage
```bash
chmod +x scope_collector.sh
./scope_collector.sh
```

## Output

Le script génère dans `lists/` :
- `bbscope_h1_list_YYYY-MM-DD.txt` - Scope brute
- `domain_h1_list_YYYY-MM-DD.txt` - Domaines directs
- `wildcard_h1_list_YYYY-MM-DD.txt` - Wildcards
- `alive_from_wildcard_h1_YYYY-MM-DD.txt` - Sous-domaines actifs
- **`final_targets_h1_YYYY-MM-DD.txt`** - Liste finale à tester ✨

## Workflow

1. Récupère la scope via `bbscope`
2. Sépare domaines et wildcards
3. Énumère les sous-domaines des wildcards avec `assetfinder`
4. Vérifie les hosts actifs avec `httpx`
5. Génère la liste finale dédupliquée

## Note

Pour activer YesWeHack, décommenter les lignes finales du script
