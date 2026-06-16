import pytest
import requests
import base64
import os
import urllib.parse
import pyotp

GATEWAY = os.getenv("OPENFAAS_GATEWAY", "http://openfaas.local")
GW_AUTH = (
    os.getenv("OPENFAAS_USER", "admin"),
    os.getenv("OPENFAAS_PASS", "xq0T6Ql35kaRBFVsYidT4Pmy2kU69Wrs")
)
TEST_USER = "pytest-testuser"


def call(function, payload):
    resp = requests.post(
        f"{GATEWAY}/function/{function}",
        json=payload,
        auth=GW_AUTH,
        timeout=30
    )
    return resp.status_code, resp.json()


# ─── generate-password ───────────────────────────────────────────────────────

class TestGeneratePassword:

    def test_returns_200(self):
        status, data = call("generate-password", {"username": TEST_USER})
        assert status == 200

    def test_password_length(self):
        _, data = call("generate-password", {"username": TEST_USER})
        assert len(data["password"]) == 24

    def test_password_complexity(self):
        _, data = call("generate-password", {"username": TEST_USER})
        pwd = data["password"]
        assert any(c.isupper() for c in pwd), "Pas de majuscule"
        assert any(c.islower() for c in pwd), "Pas de minuscule"
        assert any(c.isdigit() for c in pwd), "Pas de chiffre"
        assert any(not c.isalnum() for c in pwd), "Pas de caractère spécial"

    def test_qr_code_present(self):
        _, data = call("generate-password", {"username": TEST_USER})
        assert "qr_code" in data
        assert len(data["qr_code"]) > 100

    def test_qr_code_is_valid_base64(self):
        _, data = call("generate-password", {"username": TEST_USER})
        decoded = base64.b64decode(data["qr_code"])
        assert decoded[:8] == b'\x89PNG\r\n\x1a\n', "QR code n'est pas un PNG valide"

    def test_missing_username_returns_400(self):
        status, data = call("generate-password", {})
        assert status == 400

    def test_username_in_response(self):
        _, data = call("generate-password", {"username": TEST_USER})
        assert data["username"] == TEST_USER


# ─── generate-2fa ────────────────────────────────────────────────────────────

class TestGenerate2FA:

    def test_returns_200(self):
        status, _ = call("generate-2fa", {"username": TEST_USER})
        assert status == 200

    def test_totp_uri_present(self):
        _, data = call("generate-2fa", {"username": TEST_USER})
        assert "totp_uri" in data
        assert data["totp_uri"].startswith("otpauth://totp/")

    def test_totp_uri_contains_issuer(self):
        _, data = call("generate-2fa", {"username": TEST_USER})
        assert "COFRAP" in data["totp_uri"]

    def test_qr_code_present(self):
        _, data = call("generate-2fa", {"username": TEST_USER})
        assert "qr_code" in data
        assert len(data["qr_code"]) > 100

    def test_qr_code_is_valid_base64(self):
        _, data = call("generate-2fa", {"username": TEST_USER})
        decoded = base64.b64decode(data["qr_code"])
        assert decoded[:8] == b'\x89PNG\r\n\x1a\n'

    def test_missing_username_returns_400(self):
        status, _ = call("generate-2fa", {})
        assert status == 400


# ─── authenticate ────────────────────────────────────────────────────────────

def setup_user(username):
    """Helper: generate fresh password + 2FA for a user, return (password, totp_secret)."""
    status, data = call("generate-password", {"username": username})
    assert status == 200, f"generate-password failed: {data}"
    password = data["password"]

    status, data = call("generate-2fa", {"username": username})
    assert status == 200, f"generate-2fa failed: {data}"
    totp_uri = data["totp_uri"]
    params = urllib.parse.parse_qs(urllib.parse.urlparse(totp_uri).query)
    totp_secret = params["secret"][0]

    return password, totp_secret


class TestAuthenticate:

    def test_missing_fields_returns_400(self):
        status, _ = call("authenticate", {"username": TEST_USER})
        assert status == 400

    def test_unknown_user_returns_401(self):
        status, data = call("authenticate", {
            "username": "utilisateur-inexistant",
            "password": "mauvais",
            "totp_code": "000000"
        })
        assert status == 401
        assert data["authenticated"] is False

    def test_wrong_password_returns_401(self):
        password, totp_secret = setup_user(TEST_USER)
        totp_code = pyotp.TOTP(totp_secret).now()
        status, data = call("authenticate", {
            "username": TEST_USER,
            "password": "mauvais-mot-de-passe",
            "totp_code": totp_code
        })
        assert status == 401
        assert data["authenticated"] is False

    def test_wrong_totp_returns_401(self):
        password, _ = setup_user(TEST_USER)
        status, data = call("authenticate", {
            "username": TEST_USER,
            "password": password,
            "totp_code": "000000"
        })
        assert status == 401
        assert data["authenticated"] is False

    def test_success(self):
        password, totp_secret = setup_user(TEST_USER)
        totp_code = pyotp.TOTP(totp_secret).now()
        status, data = call("authenticate", {
            "username": TEST_USER,
            "password": password,
            "totp_code": totp_code
        })
        assert status == 200
        assert data["authenticated"] is True
        assert data["username"] == TEST_USER


# ─── renouvellement de compte ────────────────────────────────────────────────

class TestRenewFlow:

    def test_generate_password_updates_existing_user(self):
        _, _ = setup_user(TEST_USER)
        # Deuxième appel : renewal sur un utilisateur existant
        status, data = call("generate-password", {"username": TEST_USER})
        assert status == 200
        assert len(data["password"]) == 24

    def test_authenticate_after_renewal(self):
        password, totp_secret = setup_user(TEST_USER)
        totp_code = pyotp.TOTP(totp_secret).now()
        status, data = call("authenticate", {
            "username": TEST_USER,
            "password": password,
            "totp_code": totp_code
        })
        assert status == 200
        assert data["authenticated"] is True

    def test_old_password_rejected_after_renewal(self):
        old_password, _ = setup_user(TEST_USER)
        # Renouvellement : nouveau mot de passe
        new_password, new_totp_secret = setup_user(TEST_USER)
        totp_code = pyotp.TOTP(new_totp_secret).now()
        status, data = call("authenticate", {
            "username": TEST_USER,
            "password": old_password,
            "totp_code": totp_code
        })
        assert status == 401
        assert data["authenticated"] is False
