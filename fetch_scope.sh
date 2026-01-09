#!/bin/bash
# Script pour récupérer la scope de HackerOne et YWH, traiter les wildcards et générer une liste de hosts à tester.
set -euo pipefail

# Load API keys
if [ ! -f .env ]; then
    echo "[-] Le fichier .env est manquant."
    exit 1
fi
source .env

DATE=$(date +%Y-%m-%d)
OUTDIR="lists"
mkdir -p "$OUTDIR"

# Vérifier les dépendances
function check_dependencies() {
    local deps=("bbscope" "assetfinder" "httpx" "grep" "sed" "sort" "cut")
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            echo "[-] Erreur : $cmd n'est pas installé."
            exit 1
        fi
    done
}

# Fonction pour récupérer la scope de HackerOne et YWH
function fetch_scope() {
    local platform="$1"
    local token="$2"
    local username="${3:-}"
    local raw_outfile="${OUTDIR}/bbscope_${platform}_list_${DATE}.txt"
    local domain_outfile="${OUTDIR}/domain_${platform}_list_${DATE}.txt"
    local wildcard_outfile="${OUTDIR}/wildcard_${platform}_list_${DATE}.txt"
    
    echo "[*] Récupération de la scope $platform..."
    
    if [ "$platform" == "h1" ]; then
        bbscope h1 -t "$token" -u "$username" -b -o t > "$raw_outfile"
    elif [ "$platform" == "ywh" ]; then
        bbscope ywh -t "$token" -b -o t > "$raw_outfile"
    else
        echo "[-] Plateforme inconnue : $platform"
        return 1
    fi
    
    # Extraire les domaines (avec || true pour éviter l'échec si grep ne trouve rien)
    grep -E '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$' "$raw_outfile" > "$domain_outfile" || true
    
    # Extraire les wildcards
    grep -E '^\*\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$' "$raw_outfile" > "$wildcard_outfile" || true
    
    echo "[+] Domaines extraits : $(wc -l < "$domain_outfile")"
    echo "[+] Wildcards extraits : $(wc -l < "$wildcard_outfile")"
}

# Fonction pour traiter les wildcards et générer la liste de sous-domaines
function process_wildcard_scope() {
    local platform="$1"
    local input_file="${OUTDIR}/wildcard_${platform}_list_${DATE}.txt"
    local output_file="${OUTDIR}/list_from_wildcard_${platform}_${DATE}.txt"
    local alive_output_file="${OUTDIR}/alive_from_wildcard_${platform}_${DATE}.txt"
    
    # Vérifier si le fichier existe et n'est pas vide
    if [ ! -s "$input_file" ]; then
        echo "[!] Aucun wildcard à traiter pour $platform"
        touch "$output_file" "$alive_output_file"
        return 0
    fi
    
    echo "[*] Traitement des wildcards depuis $input_file..."
    
    > "$output_file"
    
    # Retirer les wildcards et dédupliquer
    sed 's/^\*\.\(.*\)/\1/' "$input_file" | sort -u > "${input_file}.base_domains"
    
    # Traiter chaque domaine
    while IFS= read -r domain; do
        echo "[*] Recherche des sous-domaines de $domain"
        assetfinder --subs-only "$domain" >> "$output_file" 2>/dev/null || true
    done < "${input_file}.base_domains"
    
    sort -u "$output_file" -o "$output_file"
    echo "[+] Sous-domaines collectés : $(wc -l < "$output_file")"
    
    if [ ! -s "$output_file" ]; then
        echo "[!] Aucun sous-domaine trouvé"
        touch "$alive_output_file"
        return 0
    fi
    
    echo "[*] Scan HTTP avec httpx (exclusion des 404)..."
    httpx -silent -status-code < "$output_file" | grep -v " \[404\]" | awk '{print $1}' > "$alive_output_file" || true
    
    echo "[+] Sous-domaines vivants enregistrés dans : $alive_output_file"
    echo "[+] Total vivants : $(wc -l < "$alive_output_file")"
}

# Crée une liste finale de targets à tester (simple concat + dedup)
function build_final_targets() {
    local platform="$1"
    local out="${OUTDIR}/final_targets_${platform}_${DATE}.txt"
    
    cat \
        "${OUTDIR}/domain_${platform}_list_${DATE}.txt" \
        "${OUTDIR}/alive_from_wildcard_${platform}_${DATE}.txt" \
        2>/dev/null \
    | sort -u > "$out"
    
    echo "[+] Liste finale : $out ($(wc -l < "$out") lignes)"
}

# Exécution
check_dependencies

echo "=== Traitement HackerOne ==="
fetch_scope "h1" "$HACKERONE_API_KEY" "$HACKERONE_USERNAME"
process_wildcard_scope "h1"
build_final_targets "h1"

# Décommentez pour YesWeHack
# echo ""
# echo "=== Traitement YesWeHack ==="
# fetch_scope "ywh" "$YWH_API_KEY"
# process_wildcard_scope "ywh"
# build_final_targets "ywh"

echo ""
echo "[✓] Terminé !"
