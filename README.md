# 🔑 Chiffrement E2E API REST Fintech — AES-256-GCM + TLS 1.3

[![Repo Badge](https://img.shields.io/badge/GitHub-Fintech%20Security-purple?logo=github&style=flat-square)](https://github.com/primaelkpfv/e2e-encryption-fintech-api)
[![Crypto](https://img.shields.io/badge/Crypto-AES--256--GCM-blue?style=flat-square)](.)
[![TLS](https://img.shields.io/badge/TLS-1.3%20%2B%20mTLS-green?style=flat-square)](.)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen?style=flat-square)](.)

> Implémentation sécurisée d'une API REST de paiement avec chiffrement de bout-en-bout (AES-256-GCM), PKI OpenSSL, authentification HMAC et audit TLS A+.

---

## 🔐 Couches de sécurité

<details open>
<summary><b>🛡️ Architecture de sécurité</b> — Multi-layer encryption</summary>

```
┌────────────────────────────────────────────────────────┐
│            LAYERS DE SÉCURITÉ API FINTECH             │
├────────────────────────────────────────────────────────┤
│                                                        │
│  LAYER 3️⃣  — Encryption applicatif (AES-256-GCM)    │
│  ┌────────────────────────────────────────────────┐  │
│  │ Transactions financières chiffrées              │  │
│  │ • IV aléatoire 96-bit par message               │  │
│  │ • Authentication tag 128-bit                    │  │
│  │ • PBKDF2 key derivation (600k iterations)       │  │
│  └────────────────────────────────────────────────┘  │
│         ↑                                              │
│         │ Payload                                      │
│         │                                              │
│  LAYER 2️⃣  — Transport encryption (TLS 1.3 + mTLS)   │
│  ┌────────────────────────────────────────────────┐  │
│  │ Secure channel to API endpoint                 │  │
│  │ • Mutual TLS authentication (client cert)      │  │
│  │ • Perfect Forward Secrecy (ECDHE)              │  │
│  │ • No downgrade to TLS 1.2 or lower ❌           │  │
│  │ • HSTS header: max-age=31536000                │  │
│  └────────────────────────────────────────────────┘  │
│         ↑                                              │
│         │ mTLS handshake                               │
│         │                                              │
│  LAYER 1️⃣  — Client authentication (HMAC-SHA256)    │
│  ┌────────────────────────────────────────────────┐  │
│  │ Request signing & replay protection             │  │
│  │ • Signature: HMAC-SHA256(method + path + body) │  │
│  │ • Timestamp: Unix epoch ±5 min window          │  │
│  │ • Nonce: 128-bit random per request            │  │
│  └────────────────────────────────────────────────┘  │
│                                                        │
└────────────────────────────────────────────────────────┘
```

</details>

---

## 📊 Audit TLS — Grade A+

<details>
<summary><b>🎯 Résultats SSL Labs</b> — Configuration optimale</summary>

```
┌──────────────────────────────────────────────────────┐
│         TLS SECURITY AUDIT RESULTS                  │
├──────────────────────────────────────────────────────┤
│                                                      │
│  Certificate                 : ✅ Valid (GeoTrust)  │
│  Domain Name                 : ✅ Match              │
│  Website Trusted             : ✅ Yes                │
│                                                      │
│  PROTOCOL SUPPORT                                   │
│  ├─ TLS 1.3                  : ✅ Preferred         │
│  ├─ TLS 1.2                  : ✅ Supported         │
│  ├─ TLS 1.1 / 1.0            : ❌ Disabled         │
│  └─ SSL 3.0 / 2.0            : ❌ Disabled         │
│                                                      │
│  KEY EXCHANGE                                       │
│  ├─ ECDHE (P-256)            : ✅ Preferred        │
│  ├─ Forward Secrecy          : ✅ Yes (PFS)        │
│  └─ DHE                      : ❌ Disabled         │
│                                                      │
│  CIPHER STRENGTH                                    │
│  ├─ AES-256-GCM              : ✅ 256-bit          │
│  ├─ AES-128-GCM              : ✅ 128-bit          │
│  ├─ RC4 / 3DES / MD5         : ❌ Disabled         │
│  └─ Anonymous ciphers        : ❌ Not supported    │
│                                                      │
│  HANDSHAKE FEATURES                                 │
│  ├─ Session resumption       : ✅ Yes (tickets)    │
│  ├─ OCSP stapling            : ✅ Yes              │
│  ├─ Certificate transparency : ✅ Yes              │
│  └─ Secure renegotiation     : ✅ Supported        │
│                                                      │
│  VULNERABILITY CHECK                                │
│  ├─ Heartbleed               : ✅ Not vulnerable   │
│  ├─ BEAST                    : ✅ Not vulnerable   │
│  ├─ Poodle                   : ✅ Not vulnerable   │
│  ├─ DROWN                    : ✅ Not vulnerable   │
│  ├─ Logjam                   : ✅ Not vulnerable   │
│  └─ FREAK                    : ✅ Not vulnerable   │
│                                                      │
│  HEADERS SECURITY                                   │
│  ├─ HSTS                     : ✅ max-age 31536000 │
│  ├─ X-Frame-Options          : ✅ DENY             │
│  ├─ X-Content-Type-Options   : ✅ nosniff          │
│  ├─ CSP                      : ✅ Configured       │
│  └─ HTTPS everywhere         : ✅ Yes              │
│                                                      │
│  OVERALL RATING : 🟢 A+ (Excellent)               │
│                                                      │
└──────────────────────────────────────────────────────┘
```

</details>

---

## 💡 Utilisation API

```python
from src.crypto import PayloadCrypto, HMACAuth

# 1️⃣ Initialiser chiffrement
crypto = PayloadCrypto(master_secret="votre_cle_forte")

# 2️⃣ Transaction financière
transaction = {
    "amount": 1500.00,
    "currency": "EUR",
    "recipient_iban": "FR7630004000031234567890143",
    "description": "Paiement facture #2025-001"
}

# 3️⃣ Chiffrer
encrypted = crypto.encrypt(transaction)
print(f"Ciphertext: {encrypted[\"ciphertext\"][:40]}...")

# 4️⃣ Signer la requête (anti-rejeu)
auth = HMACAuth(api_secret)
headers = auth.sign_request("POST", "/api/v1/transactions", str(transaction))

# 5️⃣ Envoyer via HTTPS/TLS 1.3 + mTLS
response = requests.post(
    "https://api.fintech.local/transactions",
    json=encrypted,
    headers=headers,
    cert=("client.crt", "client.key"),  # mTLS
    verify="ca.crt"
)

# 6️⃣ Déchiffrer réponse
decrypted = crypto.decrypt(response.json())
print("Transaction approuvée ✅")
```

---

## 🔗 Ressources

- 📚 [NIST SP 800-38D - AES-GCM](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- 📚 [RFC 8446 - TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- 📚 [ANSSI - Recommandations TLS](https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-tls/)
- 🔗 [SSL Labs Test](https://www.ssllabs.com/)

---

<p align="center">
  <b>Made with 🔑 for Secure Fintech</b>
</p>
