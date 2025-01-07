from __future__ import annotations
import json
import time
import base64
import hashlib
import nkeys
import secrets
import crc32c
from collections import defaultdict


def get_sha256_checksum(byte_string):
    """
    :param byte_string: byte-string to create checksum from
    :return: b32-encoded sh256-checksum as string
    """
    sha256 = hashlib.sha256(byte_string)
    return base64.b32encode(sha256.hexdigest().encode("utf8")).decode("utf8").strip("=")


def url_base64_encode(byte_string):
    """
    :param byte_string: byte-string to encode
    :return: string
    """
    return base64.urlsafe_b64encode(byte_string).decode().strip("=")


def dict_to_bytestring(dictionary):
    """Converts a python dict to json formatted bytestring"""
    return json.dumps(dictionary).encode("utf8")


def generate_user_seed() -> bytes:
    # Generate 32 random bytes (Ed25519 private key)
    private_key = secrets.token_bytes(32)

    # Add the "SU" prefix for user seeds
    prefix = b'\x18'  # "SU" prefix in binary format (as per NATS encoding spec)
    payload = prefix + private_key

    # Compute CRC checksum (truncate to 16 bits)
    full_checksum = crc32c.crc32c(payload)
    truncated_checksum = full_checksum & 0xFFFF  # Keep only the lower 16 bits
    checksum_bytes = truncated_checksum.to_bytes(2, 'big')

    # Concatenate payload and checksum
    seed_with_checksum = payload + checksum_bytes

    # Encode in Base32
    seed_encoded = base64.b32encode(seed_with_checksum).decode('utf-8').rstrip('=')

    # Format the seed as a NATS user seed
    nats_user_seed = f"SU{seed_encoded}"
    return nats_user_seed.encode()


class NJWT:
    header = {"typ": "JWT", "alg": "ed25519-nkey"}

    def __init__(
        self,
        jwt_type=None,
        jti=None,
        iat=None,
        iss=None,
        name=None,
        sub=None,
        limits=None,
        revocations=None,
        expiry=None,
        token_key_pair=None,
        sign_seed=None,
    ):
        _default_limits = {
            "subs": -1,
            "data": -1,
            "payload": -1,
            "imports": -1,
            "exports": -1,
            "wildcards": True,
            "conn": -1,
            "leaf": -1,
        }
        self.jti = jti
        self.iat = iat if iat else int(time.time())
        self.iss = iss
        self.name = name
        self._sub = sub
        self.limits = limits if limits else _default_limits
        self.expiry = expiry
        self.token_key_pair = token_key_pair
        self.type = jwt_type
        self.revocations = revocations if revocations else {}
        self.sign_seed = sign_seed
        self.pub_claim = defaultdict(list)
        self.sub_claim = defaultdict(list)

    @property
    def sub(self):
        if self._sub:
            return self._sub
        return self.token_key_pair.public_key.decode("utf8")

    @property
    def claim(self):
        if self.type == "user":
            return self.user_claim
        elif self.type == "account":
            return self.account_claim
        raise Exception(f"Unsupported type '{self.type}'")

    @property
    def user_claim(self):
        claim = {
            "jti": self.jti,
            "iat": self.iat,
            "iss": self.iss,
            "name": self.name,
            "sub": self.sub,
            "nats": {
                "pub": dict(self.pub_claim),
                "sub": dict(self.sub_claim),
                "subs": -1,
                "data": -1,
                "payload": -1,
                "bearer_token": True,
                "type": "user",
                "version": 2,
            },
        }
        if self.expiry:
            claim["exp"] = self.expiry
        return claim

    @property
    def account_claim(self):
        return {
            "jti": self.jti,
            "iat": self.iat,
            "iss": self.iss,
            "name": self.name,
            "sub": self.sub,
            "nats": {
                "limits": {
                    "subs": -1,
                    "data": -1,
                    "payload": -1,
                    "imports": -1,
                    "exports": -1,
                    "wildcards": True,
                    "conn": -1,
                    "leaf": -1,
                },
                "revocations": self.revocations,
                "default_permissions": {"pub": {}, "sub": {}},
                "type": "account",
                "version": 2,
            },
        }

    def revoke(self, user_pub_key):
        """Used in account tokens. Revoke a certain user-id

        :param user_pub_key: Public-key / ID of the user
        """
        self.revocations[user_pub_key] = int(time.time())

    def add_pub_allow(self, subject):
        """Add an allow rule for the user to publish on a certain subject"""
        self.pub_claim["allow"].append(subject)

    def add_sub_allow(self, subject):
        """Add an allow rule for the user to subscribe on a certain subject"""
        self.sub_claim["allow"].append(subject)

    def add_pubsub_allow(self, subject):
        """Add an allow rule for the user to publish and subscribe on a certain subject"""
        self.pub_claim["allow"].append(subject)
        self.sub_claim["allow"].append(subject)

    def sign(self, sign_seed=None):
        """Returns the complete signed JWT

        :param sign_seed: raw byte-string seed to sign the JWT
                          operator-seed for account JWT's
                          and account-seed for user JWT's
        :return: base64 encoded and signed JWT
        """
        if sign_seed:
            self.sign_seed = sign_seed
        if not self.sign_seed:
            raise Exception("No seed provided to sing the JWT")

        # Remove jti, then generate hash, set jti to new hash
        claim = self.claim
        claim.pop("jti")
        self.jti = get_sha256_checksum(dict_to_bytestring(claim))

        # Get complete body / claim with checksum in jti; b64 encode it
        header = url_base64_encode(dict_to_bytestring(self.header))
        body = url_base64_encode(dict_to_bytestring(self.claim))

        # Sign header and body
        sing_key = nkeys.from_seed(self.sign_seed)
        signature = sing_key.sign(f"{header}.{body}".encode("utf8"))
        signature = url_base64_encode(signature)
        return f"{header}.{body}.{signature}"

    @staticmethod
    def from_account_jwt(jwt) -> NJWT:
        """New account JWT

        :param jwt: raw b64 encoded JWT
        :return: NJWT object
        """
        _, body, _ = jwt.split(".")
        claim = json.loads(base64.b64decode(body + "=="))
        jwt_type = claim["nats"]["type"]
        if jwt_type != "account":
            raise Exception(
                f"Only JWT of type 'account' supported, you supplied '{jwt_type}'"
            )
        return NJWT(
            jti=claim["jti"],
            iss=claim["iss"],
            name=claim["name"],
            sub=claim["sub"],
            limits=claim["nats"]["limits"],
            jwt_type="account",
            revocations=claim["nats"].get("revocations"),
        )

    @staticmethod
    def new_user(name, account_seed) -> NJWT:
        """New user NATS JWT

        :param name: user name included in the JWT
        :param account_seed: Seed of the account to which the user belongs to
        :return: NJWT object
        """
        # Create new user (priv / pub nkey-pair)
        user_seed = generate_user_seed()
        user_key = nkeys.from_seed(user_seed)
        account_key = nkeys.from_seed(account_seed)

        return NJWT(
            iss=account_key.public_key.decode("utf8"),
            name=name,
            token_key_pair=user_key,
            sign_seed=account_seed,
            jwt_type="user",
        )
