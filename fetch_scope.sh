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
    fi

    grep -E '(^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$|^[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]+$)' "$raw_outfile" > "$domain_outfile"
    grep -E '^\*\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' "$raw_outfile" > "$wildcard_outfile"
}

# Fonction pour traiter les wildcards et générer la liste de sous-domaines
function process_wildcard_scope() {
	local platform="$1"
    local input_file="${OUTDIR}/wildcard_${platform}_list_${DATE}.txt"
    local output_file="${OUTDIR}/list_from_wildcard_${platform}_${DATE}.txt"
    local alive_output_file="${OUTDIR}/alive_from_wildcard_${platform}_${DATE}.txt"

    echo "[*] Traitement des wildcards depuis $input_file..."

    > "$output_file"
    > "$alive_output_file"

    sed 's/^\*\.\(.*\)/\1/' "$input_file" | sort -u | while read -r domain; do
        echo "[*] Recherche des sous-domaines de $domain"
        ./assetfinder --subs-only "$domain" >> "$output_file"
    done

    sort -u "$output_file" -o "$output_file"
    echo "[+] Sous-domaines collectés : $(wc -l < "$output_file")"

    echo "[*] Scan HTTP avec httpx (exclusion des 404)..."
    ./httpx -silent -status-code < "$output_file" | grep -v " 404" | cut -d' ' -f1 > "$alive_output_file"

    echo "[+] Sous-domaines vivants enregistrés dans : $alive_output_file"
    echo "[+] Total vivants : $(wc -l < "$alive_output_file")"
}

# Fonction pour lister les hosts déjà testés
function list_already_tested_hosts() {
    local logdir="logs"
    local output_file="${OUTDIR}/already_tested_hosts_${DATE}.txt"

    if [ ! -d "$logdir" ]; then
        echo "[-] Le dossier de logs '$logdir' est introuvable."
        return
    fi

    echo "[*] Extraction des hosts déjà testés depuis $logdir..."
    cat "$logdir"/* 2>/dev/null | grep 'host:' | awk '{print $NF}' | sort -u > "$output_file"

    echo "[+] Hosts déjà testés enregistrés dans : $output_file"
    echo "[+] Total trouvés : $(wc -l < "$output_file")"
}

# Fonction pour générer la liste finale des hosts à tester
function generate_hosts_to_test() {
    local platform="$1"
    local domain_file="${OUTDIR}/domain_${platform}_list_${DATE}.txt"
    local alive_file="${OUTDIR}/alive_from_wildcard_${platform}_${DATE}.txt"
    local tested_file="${OUTDIR}/already_tested_hosts_${DATE}.txt"
    local output_file="${OUTDIR}/hosts_to_test_${platform}_${DATE}.txt"

    echo "[*] Génération de la liste finale des hosts à tester pour $platform..."

    # Vérifier que les fichiers d'entrée existent
    if [[ ! -f "$domain_file" && ! -f "$alive_file" ]]; then
        echo "[-] Aucun fichier d'entrée trouvé pour $platform"
        return
    fi

    # Concaténer les deux fichiers d'entrée (s'ils existent), les trier et dédupliquer
    cat "$domain_file" "$alive_file" 2>/dev/null | sort -u > "${OUTDIR}/tmp_all_hosts_${platform}.txt"

    # Si la liste des hosts déjà testés existe, on les retire
    if [[ -f "$tested_file" ]]; then
        comm -23 <(sort "${OUTDIR}/tmp_all_hosts_${platform}.txt") <(sort "$tested_file") > "$output_file"
    else
        cp "${OUTDIR}/tmp_all_hosts_${platform}.txt" "$output_file"
    fi

    rm -f "${OUTDIR}/tmp_all_hosts_${platform}.txt"

    echo "[+] Hosts à tester enregistrés dans : $output_file"
    echo "[+] Total à tester : $(wc -l < "$output_file")"
	ntfy pub $subject "Hosts à tester pour $platform : $(wc -l < "$output_file")"
	echo "[+] Notification envoyée via ntfy"
}

# Exécution
fetch_scope "h1" "$HACKERONE_API_KEY" "$HACKERONE_USERNAME"
# fetch_scope "ywh" "$YWH_API_TOKEN"
process_wildcard_scope "h1"
# process_wildcard_scope "ywh"
list_already_tested_hosts
generate_hosts_to_test "h1"
# generate_hosts_to_test "ywh"
ntfy pub $subject "Récupération des scopes terminée"

