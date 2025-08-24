from __future__ import annotations
import jwt
import json
import logging
import base64
import requests
from typing import Dict, Tuple, Any
from urllib import parse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import (
    CertificateSigningRequestBuilder, Name, NameAttribute, 
    BasicConstraints, ObjectIdentifier, UnrecognizedExtension
)
from cryptography.x509.oid import NameOID
from securesystemslib.diverify.util import perf_utils
from securesystemslib.exceptions import UnsupportedLibraryError
from sigstore import hashes as sigstore_hashes
from securesystemslib.signer._signer import (
    Key,
    SecretsHandler,
    Signature,
    Signer,
)
from securesystemslib.signer._utils import compute_default_keyid
import configparser


config = configparser.ConfigParser()
config.read('stack_config.ini')

DEFAULT_FULCIO_URL = config['settings']['fulcio-url']
DEFAULT_REKOR_URL = config['settings']['rekor-url']
DEFAULT_OAUTH_ISSUER_URL = config['settings']['oauth_issuer-url']
SIGNING_CERT_ENDPOINT = "/api/v2/signingCert"
TRUST_BUNDLE_ENDPOINT = "/api/v2/trustBundle"

IMPORT_ERROR = "sigstore library required to use 'sigstore-oidc' keys"

logger = logging.getLogger(__name__)

class SigstoredKey(Key):
    DEFAULT_KEY_TYPE = "sigstore-oidc"
    DEFAULT_SCHEME = "Fulcio"

    def __init__(
        self,
        keyid: str,
        keytype: str,
        scheme: str,
        keyval: dict[str, Any],
        unrecognized_fields: dict[str, Any] | None = None,
    ):
        for content in ["identity", "issuer"]:
            if content not in keyval or not isinstance(keyval[content], str):
                raise ValueError(f"{content} string required for scheme {scheme}")
        super().__init__(keyid, keytype, scheme, keyval, unrecognized_fields)

    @classmethod
    def from_dict(cls, keyid: str, key_dict: dict[str, Any]) -> SigstoredKey:
        keytype, scheme, keyval = cls._from_dict(key_dict)
        return cls(keyid, keytype, scheme, keyval, key_dict)

    def to_dict(self) -> dict:
        return self._to_dict()

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        pass

class SigstoredSigner(Signer):

    SCHEME = "diverify"

    def __init__(self, token: Any, decoded_token:Any, public_key: Key):
        self._public_key = public_key
        # token is of type sigstore.oidc.IdentityToken but the module should be usable
        # without sigstore so it's not annotated
        self._token = token
        self._decoded_token = decoded_token

    @property
    def public_key(self) -> Key:
        return self._public_key

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
    ) -> SigstoredSigner:
        try:
            from sigstore.oidc import detect_credential
        except ImportError as e:
            raise UnsupportedLibraryError(IMPORT_ERROR) from e

        if not isinstance(public_key, SigstoredKey):
            raise ValueError(f"expected SigstoredKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"SigstoredSigner does not support {priv_key_uri}")

        params = dict(parse.parse_qsl(uri.query))
        ambient = params.get("ambient", "true") == "true"

        if not ambient:
            token, decoded_token = cls._get_dex_identity_token(limit_scope=secrets_handler)
        else:
            credential = detect_credential()
            if not credential:
                try:
                    from securesystemslib.diverify.daemon.scopes import get_identity_token
                    credential = get_identity_token()
                except:
                    raise RuntimeError("Failed to detect credentials")
            token, decoded_token = credential, jwt.decode(credential, options={"verify_signature": False})

        key_identity = public_key.keyval["identity"]
        key_issuer = public_key.keyval["issuer"]
        if key_issuer != decoded_token["iss"]:
            raise ValueError(
                f"Signer identity issuer {decoded_token["iss"]} "
                f"did not match key: {key_issuer}"
            )
        # TODO: should check ambient identity too: unfortunately IdentityToken does
        # not provide access to the expected identity value (cert SAN) in ambient case
        try:
            identry_from_token = decoded_token['email']
        except:
            identry_from_token = decoded_token['sub']
        if not ambient and key_identity != identry_from_token:
            raise ValueError(
                f"Signer identity {identry_from_token} did not match key: {key_identity}"
            )

        return cls(token, decoded_token, public_key), token

    @classmethod
    def _get_uri(cls, ambient: bool) -> str:
        return f"{cls.SCHEME}:{'' if ambient else '?ambient=false'}"

    @classmethod
    def import_(
        cls, identity: str, issuer: str, ambient: bool = True
    ) -> tuple[str, SigstoredKey]:
        """Create public key and signer URI.

        Returns a private key URI (for Signer.from_priv_key_uri()) and a public
        key. import_() should be called once and the returned URI and public
        key should be stored for later use.

        Arguments:
            identity: The OIDC identity to use when verifying a signature.
            issuer: The OIDC issuer to use when verifying a signature.
            ambient: Toggle usage of ambient credentials in returned URI.
        """
        keytype = SigstoredKey.DEFAULT_KEY_TYPE
        scheme = SigstoredKey.DEFAULT_SCHEME
        keyval = {"identity": identity, "issuer": issuer}
        keyid = compute_default_keyid(keytype, scheme, keyval)
        key = SigstoredKey(keyid, keytype, scheme, keyval)
        uri = cls._get_uri(ambient)

        return uri, key 
    
    @staticmethod
    def _get_dex_identity_token(limit_scope=False):
        """Retrieve an identity token using OAuth2 with Dex."""
        from jwt import decode

        client_id = "sigstore"
        client_secret = ""

        auth_code, redirect_uri, code_verifier = SigstoredSigner.get_authorization_code(client_id, client_secret, limit_scope=limit_scope)

        response = requests.post(
            f"{DEFAULT_OAUTH_ISSUER_URL}/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            }
        )

        response.raise_for_status() 
        response_json = response.json()
        
        raw_token = response_json.get("id_token")
        if not raw_token:
            raise KeyError("Response does not contain 'id_token'")

        return raw_token, decode(raw_token, options={"verify_signature": False})

    @staticmethod
    def get_authorization_code(client_id, client_secret, limit_scope=False):
        """Starts a temporary web server on an available port to capture the authorization code."""
        import webbrowser
        import http.server
        import socketserver
        from threading import Thread, Event
        import uuid

        class AuthHandler(http.server.BaseHTTPRequestHandler):
            """Handles the OAuth2 redirect and extracts the auth code."""
            def do_GET(self):
                parsed_path = parse.urlparse(self.path)
                query_params = parse.parse_qs(parsed_path.query)
                if "code" in query_params:
                    self.server.auth_code = query_params["code"][0]
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"Authentication successful. You can close this window.")
                    self.server.auth_event.set()  # Signal that auth is complete
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Authentication failed.")

        # Start a local web server to receive the authorization response
        server = socketserver.TCPServer(("localhost", 0), AuthHandler, bind_and_activate=False)
        server.allow_reuse_address = True
        server.server_bind()
        server.server_activate()
        port = server.server_address[1]
        redirect_uri = f"http://localhost:{port}/callback"
        
        # Generate PKCE parameters
        code_verifier, code_challenge = SigstoredSigner._generate_pkce_challenge()
        state, nonce = str(uuid.uuid4()), str(uuid.uuid4())

        # Commenting this off till Dex is updated to support repo scope
        scope = "openid+email"
        # if limit_scope:
        #     scope += "+repo" 

        auth_url = (
            f"{DEFAULT_OAUTH_ISSUER_URL}/auth?"
            f"response_type=code&client_id={client_id}&client_secret={client_secret}&"
            f"scope={scope}&redirect_uri={redirect_uri}&"
            f"code_challenge={code_challenge}&code_challenge_method=S256&"
            f"state={state}&nonce={nonce}"
        )

        print(f"Opening browser for login: {auth_url}")
        webbrowser.open(auth_url)
        server.auth_event = Event()
        server_thread = Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        print("Waiting for authentication...")
        server.auth_event.wait()  

        auth_code = server.auth_code
        server.shutdown()
        return auth_code, redirect_uri, code_verifier

    @classmethod
    def _generate_pkce_challenge(cls):
        import hashlib
        import os
        """Generates a PKCE challenge (S256)"""
        code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
        return code_verifier, code_challenge
    
    def generate_key_pair(self) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """Generate an EC key pair."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        return private_key

    def create_csr(self, email_address: str, diverify_proof: bytes) -> CertificateSigningRequestBuilder:
        DIVERIFY_PROOF_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.23")

        csr_builder = (
            CertificateSigningRequestBuilder()
            .subject_name(Name([NameAttribute(NameOID.EMAIL_ADDRESS, email_address)]))
            .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                UnrecognizedExtension(DIVERIFY_PROOF_OID, diverify_proof),
                critical=False
                )
            )
        return csr_builder
    
    def sign(self, payload: bytes, diverify_proof: Dict) -> Signature:
        """Signs payload using the OIDC token 
        Arguments:
            payload: bytes to be signed.
        Returns:
            Integrated entry
        """
        private_key = self.generate_key_pair()
        

        # Create CSR
        try:
            email_address = self._decoded_token['email']
        except:
            email_address = self._decoded_token['sub']
        csr = self.create_csr(email_address, json.dumps(diverify_proof).encode()).sign(private_key, hashes.SHA256())

        # We assume identity token is valid and send CSR to Fulcio
        certificate_response = self.get_fulcio_cert(csr, self._token)

        # Sign the payload
        hashed_input, artifact_signature = self.sign_artifact(private_key, payload)

        signature_material = {
                "hashed_input": hashed_input,
                "artifact_signature": artifact_signature,
                "signing_cert": certificate_response.cert
            }
        return signature_material

    
    from dataclasses import dataclass
    @dataclass(frozen=True)
    class FulcioCertificateSigningResponse:
        from typing import List
        cert: object
        chain: List[object]

    @perf_utils.measure_latency
    def get_fulcio_cert(self, csr, identity):
        from cryptography.x509 import load_pem_x509_certificate
        
        fulcio_url=parse.urljoin(DEFAULT_FULCIO_URL, SIGNING_CERT_ENDPOINT)

        certificate_request = json.dumps({"certificateSigningRequest": base64.b64encode(csr.public_bytes(serialization.Encoding.PEM)).decode()})
        headers = {
            "Authorization": f"Bearer {identity}",
            "Content-Type": "application/json",
            "Accept": "application/pem-certificate-chain",
        }
        resp = requests.post(fulcio_url, certificate_request, headers=headers)
        if not resp.ok:
            raise Exception(resp.json().get("message", "Fulcio request failed"))
        
        certs = resp.json().get("signedCertificateEmbeddedSct", {}).get("chain", {}).get("certificates", [])
        if len(certs) < 2:
            raise Exception("Certificate chain is too short")
        
        return self.FulcioCertificateSigningResponse(
            load_pem_x509_certificate(certs[0].encode()),
            [load_pem_x509_certificate(c.encode()) for c in certs[1:]]
        )
    
    def sign_artifact(
        self,
        private_key,
        input_: bytes | sigstore_hashes.Hashed,
    ) -> tuple[sigstore_hashes.Hashed, bytes]:
        
        """
       Sign an artifact and return the signed result as a tuple.
        """
        try:
            from sigstore._utils import sha256_digest
        except ImportError as e:
            raise UnsupportedLibraryError(IMPORT_ERROR) from e

        # Sign artifact
        hashed_input = sha256_digest(input_)

        artifact_signature = private_key.sign(
            hashed_input.digest, ec.ECDSA(hashed_input._as_prehashed())
        )

        return hashed_input, artifact_signature