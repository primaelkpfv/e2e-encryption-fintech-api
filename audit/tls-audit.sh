#!/bin/bash
# Script daudit TLS complet — API Fintech
# Auteur : Fèmi KPONOU — ESAIP

TARGET=${1:-"api.fintech.local"}
PORT=${2:-443}
OUTPUT_DIR="./audit-results"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $OUTPUT_DIR

echo "======================================"
echo "  Audit TLS — $TARGET:$PORT"
echo "  Date : $(date)"
echo "======================================"

# 1. Vérification certificat
echo "[+] 1. Analyse du certificat..."
echo | openssl s_client -connect $TARGET:$PORT -servername $TARGET 2>/dev/null \
  | openssl x509 -noout -text \
  | grep -E "Subject:|Issuer:|Not Before:|Not After:|DNS:" \
  > "$OUTPUT_DIR/certificate_$DATE.txt"
cat "$OUTPUT_DIR/certificate_$DATE.txt"

# 2. Protocoles supportés
echo -e "\n[+] 2. Protocoles TLS supportés..."
for proto in ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3; do
  result=$(echo | openssl s_client -$proto -connect $TARGET:$PORT 2>&1)
  if echo "$result" | grep -q "CONNECTED"; then
    echo "  $proto : ✅ SUPPORTÉ"
  else
    echo "  $proto : ❌ Non supporté"
  fi
done

# 3. Ciphers supportés
echo -e "\n[+] 3. Cipher suites..."
nmap --script ssl-enum-ciphers -p $PORT $TARGET 2>/dev/null \
  > "$OUTPUT_DIR/ciphers_$DATE.txt"
echo "  Résultats dans $OUTPUT_DIR/ciphers_$DATE.txt"

# 4. Vulnérabilités connues
echo -e "\n[+] 4. Scan vulnérabilités TLS..."
if command -v testssl.sh &> /dev/null; then
  testssl.sh --json-pretty --logfile "$OUTPUT_DIR/testssl_$DATE.json" \
    $TARGET:$PORT
else
  echo "  [!] testssl.sh non installé"
  echo "  [!] Installer : git clone https://github.com/drwetter/testssl.sh"
fi

# 5. HSTS check
echo -e "\n[+] 5. Vérification HSTS..."
curl -sI https://$TARGET:$PORT 2>/dev/null | grep -i "strict-transport"

echo -e "\n======================================"
echo "  Audit terminé. Résultats : $OUTPUT_DIR/"
echo "======================================"
