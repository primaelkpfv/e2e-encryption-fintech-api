# 🔑 Chiffrement Bout-en-Bout — API REST Fintech

![Status](https://img.shields.io/badge/Status-Terminé-brightgreen)
![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Crypto](https://img.shields.io/badge/Crypto-AES--256--GCM%20%7C%20TLS%201.3-orange)
![Category](https://img.shields.io/badge/Catégorie-Cryptographie%20·%20PKI-blueviolet)

> Implémentation du chiffrement de bout en bout sur une API REST de transactions financières : AES-256-GCM, dérivation de clés PBKDF2, PKI interne OpenSSL et audit TLS complet.

## 🎯 Objectif

Sécuriser une API REST de paiement contre :
- Interception des transactions (MITM)
- Rejeu de requêtes
- Accès non autorisé aux données en transit et au repos
- Vulnérabilités TLS (downgrade, ciphers faibles)

## 🏗️ Architecture de sécurité

```
Client App                    API Fintech                  Base de données
    │                              │                              │
    │  HTTPS/TLS 1.3 (mTLS)        │                              │
    │──────────────────────────────▶│                              │
    │                              │  AES-256-GCM                 │
    │  AES-256-GCM payload         │──────────────────────────────▶│
    │  (chiffrement applicatif)    │  données chiffrées au repos  │
    │                              │                              │
    │◀──────────────────────────────│                              │
    │  Réponse chiffrée + HMAC     │                              │
    │                              │                              │
```

## 🛠️ Stack de sécurité

| Composant | Technologie | Usage |
|-----------|-------------|-------|
| Transport | TLS 1.3 + mTLS | Chiffrement canal |
| Payload | AES-256-GCM | Chiffrement données applicatif |
| Dérivation clés | PBKDF2-HMAC-SHA256 | Génération clés depuis secret |
| Rotation clés | Mensuelle automatique | Limiter exposition |
| PKI | OpenSSL (CA interne) | Certificats mTLS |
| Intégrité | HMAC-SHA256 | Anti-rejeu |
| Audit | testssl.sh + sslyze | Vérification config TLS |

## 🔐 Implémentation AES-256-GCM

```python
from src.crypto import PayloadCrypto

crypto = PayloadCrypto(master_secret="votre_secret_fort")

# Chiffrement dune transaction
transaction = {
    "amount": 1500.00,
    "currency": "EUR",
    "recipient_iban": "FR76...",
    "timestamp": "2025-01-15T10:30:00Z"
}

encrypted = crypto.encrypt(transaction)
# {"ciphertext": "...", "nonce": "...", "tag": "...", "version": "v1"}

# Déchiffrement
decrypted = crypto.decrypt(encrypted)
```

## 🏛️ PKI Interne — OpenSSL

```bash
# 1. Créer CA racine
openssl genrsa -aes256 -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=FR/O=TechCorp/CN=TechCorp Root CA"

# 2. Certificat serveur API
openssl genrsa -out api.key 2048
openssl req -new -key api.key -out api.csr \
  -subj "/C=FR/O=TechCorp/CN=api.fintech.local"
openssl x509 -req -days 365 -in api.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out api.crt -extensions v3_req

# 3. Certificat client (mTLS)
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
  -subj "/C=FR/O=TechCorp/CN=mobile-app-client"
openssl x509 -req -days 365 -in client.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt
```

## 🔍 Audit TLS

### Commandes daudit
```bash
# Audit complet avec testssl.sh
./testssl.sh --full --json-pretty api.fintech.local:443

# Analyse avec sslyze
sslyze --regular api.fintech.local:443

# Vérifier ciphers supportés
nmap --script ssl-enum-ciphers -p 443 api.fintech.local
```

### Résultats avant/après

| Vulnérabilité | Avant | Après |
|--------------|-------|-------|
| TLS 1.0/1.1 supportés | ❌ | ✅ Désactivés |
| Ciphers RC4/3DES | ❌ | ✅ Supprimés |
| HSTS activé | ❌ | ✅ max-age=31536000 |
| Certificate Transparency | ❌ | ✅ |
| OCSP Stapling | ❌ | ✅ |
| Perfect Forward Secrecy | ❌ | ✅ ECDHE uniquement |
| Résultat SSL Labs | C | **A+** |

## 🔄 Rotation des clés

```python
# Rotation mensuelle automatique (cron job)
from src.key_rotation import KeyRotationManager

manager = KeyRotationManager()

# Génère nouvelle clé et re-chiffre les données actives
manager.rotate()

# Les données chiffrées avec lancienne clé sont
# automatiquement migrées lors du prochain accès
```

## 🗂️ Structure du repo

```
e2e-encryption-fintech-api/
├── src/
│   ├── crypto.py            # AES-256-GCM chiffrement payload
│   ├── key_rotation.py      # Rotation mensuelle des clés
│   ├── pki.py               # Gestion certificats PKI
│   └── hmac_auth.py         # HMAC anti-rejeu
├── pki/
│   ├── setup-ca.sh          # Script création CA OpenSSL
│   └── gen-cert.sh          # Génération certificats
├── audit/
│   ├── tls-audit.sh         # Script audit TLS complet
│   └── audit-results.md     # Résultats audit SSL Labs A+
├── tests/
│   ├── test_crypto.py
│   └── test_key_rotation.py
├── requirements.txt
└── README.md
```

## 🔗 Références

- [NIST SP 800-38D — AES-GCM](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/)
- [ANSSI — Recommandations TLS](https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-tls/)

## 👤 Auteur

**Fèmi KPONOU** — Étudiant Bachelor Cybersécurité ESAIP  
🌐 [Portfolio](https://primaelkpfv.github.io) · 💼 [LinkedIn](https://linkedin.com/in/primaelkponou)
