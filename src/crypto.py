"""
Chiffrement AES-256-GCM pour API REST Fintech
Auteur : Fèmi KPONOU — ESAIP Bachelor Cybersécurité
"""

import os
import json
import base64
import hashlib
import hmac
from typing import Union
from datetime import datetime

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256, HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[!] pycryptodome requis : pip install pycryptodome")


class PayloadCrypto:
    """
    Chiffrement AES-256-GCM pour payloads API.
    
    Features:
    - AES-256-GCM (authentifié + chiffré)
    - Dérivation PBKDF2-HMAC-SHA256
    - Nonce aléatoire de 96 bits par opération
    - Versioning pour rotation de clés
    """

    KEY_VERSION = "v1"
    PBKDF2_ITERATIONS = 600_000  # NIST recommandation 2023
    SALT_SIZE = 32
    NONCE_SIZE = 12   # 96 bits — optimal GCM
    TAG_SIZE = 16     # 128 bits

    def __init__(self, master_secret: str):
        if not CRYPTO_AVAILABLE:
            raise ImportError("pycryptodome requis")
        self.master_secret = master_secret.encode()
        self._key_cache = {}

    def _derive_key(self, salt: bytes) -> bytes:
        """Dérive une clé AES-256 depuis le secret maître via PBKDF2."""
        cache_key = salt.hex()
        if cache_key not in self._key_cache:
            self._key_cache[cache_key] = PBKDF2(
                self.master_secret,
                salt,
                dkLen=32,
                count=self.PBKDF2_ITERATIONS,
                prf=lambda p, s: HMAC.new(p, s, SHA256).digest()
            )
        return self._key_cache[cache_key]

    def encrypt(self, data: Union[dict, str, bytes]) -> dict:
        """
        Chiffre des données avec AES-256-GCM.
        
        Args:
            data: Données à chiffrer (dict, str, ou bytes)
            
        Returns:
            dict avec ciphertext, nonce, tag, salt, version encodés en base64
        """
        # Sérialisation
        if isinstance(data, dict):
            plaintext = json.dumps(data, separators=(",", ":")).encode()
        elif isinstance(data, str):
            plaintext = data.encode()
        else:
            plaintext = data

        # Génération paramètres aléatoires
        salt = os.urandom(self.SALT_SIZE)
        nonce = os.urandom(self.NONCE_SIZE)

        # Dérivation clé
        key = self._derive_key(salt)

        # Chiffrement AES-256-GCM
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # AAD : métadonnées non chiffrées mais authentifiées
        aad = json.dumps({
            "version": self.KEY_VERSION,
            "timestamp": datetime.utcnow().isoformat()
        }).encode()
        cipher.update(aad)
        
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        return {
            "version": self.KEY_VERSION,
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "salt": base64.b64encode(salt).decode(),
            "aad": base64.b64encode(aad).decode()
        }

    def decrypt(self, encrypted: dict) -> Union[dict, bytes]:
        """
        Déchiffre et vérifie lintégrité des données.
        
        Args:
            encrypted: dict retourné par encrypt()
            
        Returns:
            Données déchiffrées (dict si JSON, bytes sinon)
            
        Raises:
            ValueError: Si lauthentification échoue
        """
        try:
            ciphertext = base64.b64decode(encrypted["ciphertext"])
            nonce = base64.b64decode(encrypted["nonce"])
            tag = base64.b64decode(encrypted["tag"])
            salt = base64.b64decode(encrypted["salt"])
            aad = base64.b64decode(encrypted["aad"])
        except KeyError as e:
            raise ValueError(f"Champ manquant dans le payload chiffré: {e}")

        # Dérivation clé
        key = self._derive_key(salt)

        # Déchiffrement et vérification GCM tag
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)

        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise ValueError(
                "Echec dauthentification GCM — données corrompues ou falsifiées"
            )

        # Désérialisation
        try:
            return json.loads(plaintext.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return plaintext


class HMACAuth:
    """
    Authentification HMAC pour prévenir les attaques par rejeu.
    Chaque requête API inclut un HMAC signé avec timestamp.
    """

    WINDOW_SECONDS = 300  # Fenêtre de validité : 5 minutes

    def __init__(self, secret_key: str):
        self.secret = secret_key.encode()

    def sign_request(self, method: str, path: str, body: str = "") -> dict:
        """Génère les headers dautentification pour une requête."""
        timestamp = str(int(datetime.utcnow().timestamp()))
        nonce = base64.b64encode(os.urandom(16)).decode()
        
        message = f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{body}"
        signature = hmac.new(
            self.secret,
            message.encode(),
            hashlib.sha256
        ).hexdigest()

        return {
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
            "X-Signature": signature
        }

    def verify_request(self, method: str, path: str,
                       headers: dict, body: str = "") -> bool:
        """Vérifie la signature HMAC et la fraicheur de la requête."""
        try:
            timestamp = int(headers["X-Timestamp"])
            nonce = headers["X-Nonce"]
            signature = headers["X-Signature"]
        except KeyError:
            return False

        # Vérification timestamp (anti-rejeu)
        now = int(datetime.utcnow().timestamp())
        if abs(now - timestamp) > self.WINDOW_SECONDS:
            return False

        # Recalcul signature
        message = f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{body}"
        expected = hmac.new(
            self.secret,
            message.encode(),
            hashlib.sha256
        ).hexdigest()

        # Comparaison en temps constant (anti timing attack)
        return hmac.compare_digest(signature, expected)


if __name__ == "__main__":
    print("=== Demo chiffrement AES-256-GCM ===\n")

    crypto = PayloadCrypto("super_secret_key_demo_2025")

    transaction = {
        "id": "TXN-20250115-001",
        "amount": 1500.00,
        "currency": "EUR",
        "sender": "FR7630006000011234567890189",
        "recipient": "FR7630004000031234567890143",
        "description": "Paiement facture #2025-001"
    }

    print("Transaction originale:")
    print(json.dumps(transaction, indent=2))

    encrypted = crypto.encrypt(transaction)
    print(f"\nPayload chiffré (extrait):")
    print(f"  ciphertext: {encrypted[\"ciphertext\"][:40]}...")
    print(f"  nonce: {encrypted[\"nonce\"]}")
    print(f"  tag: {encrypted[\"tag\"]}")

    decrypted = crypto.decrypt(encrypted)
    print(f"\nDéchiffrement réussi: {decrypted == transaction}")

    print("\n=== Demo HMAC Anti-Rejeu ===\n")
    auth = HMACAuth("api_secret_key_2025")
    headers = auth.sign_request("POST", "/api/v1/transactions",
                                 json.dumps(transaction))
    print("Headers générés:", headers)
    valid = auth.verify_request("POST", "/api/v1/transactions",
                                 headers, json.dumps(transaction))
    print(f"Signature valide: {valid}")
