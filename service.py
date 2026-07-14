"""
[EN]    Service for two-step PAdES (PDF) signing using PKCS#1 (external private key).
        The private key never leaves the client device; only the public certificate PEM is sent.

        Flow:
          1. prepare_signature — sends documents + certificate to SolidSign; receives hashes + finalNonce.
          2. finalize_signature — sends finalNonce + signed hashes; receives download links.

[PT-BR] Serviço para assinatura PAdES (PDF) em dois passos com PKCS#1 (chave privada externa).
        A chave privada nunca sai do dispositivo do cliente; apenas o PEM do certificado público é enviado.

        Fluxo:
          1. prepare_signature — envia documentos + certificado ao SolidSign; recebe hashes + finalNonce.
          2. finalize_signature — envia finalNonce + hashes assinados; recebe links para download.
"""

import io
import json
import logging
import os
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


def _index_field_configs(data: dict) -> None:
    """
    [EN]    Converts non-indexed visual-signature config keys into INDEXED params
            (signatureFieldConfig[0], [1], ...). The SolidSign API expects, e.g.,
            signatureFieldConfig[0]={...} per document, NOT signatureFieldConfig=[{...}] —
            otherwise the field is ignored and the visual stamp never appears.
    [PT-BR] Converte chaves de config de assinatura visual (sem índice) em parâmetros INDEXADOS
            (signatureFieldConfig[0], [1], ...). A API espera signatureFieldConfig[0]={...}
            por documento, e NÃO signatureFieldConfig=[{...}] — senão o campo é ignorado
            e o carimbo visual nunca aparece.
    """
    for key in ("signatureFieldConfig", "signatureTextConfig", "signatureQrCodeConfig"):
        raw = data.pop(key, None)
        if not raw:
            continue
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            data[f"{key}[0]"] = raw
            continue
        items = parsed if isinstance(parsed, list) else [parsed]
        for i, item in enumerate(items):
            data[f"{key}[{i}]"] = item if isinstance(item, str) else json.dumps(item)


class PdfPkcs1Service:

    def __init__(self):
        self.base_url = os.getenv("SOLIDSIGN_API_BASE_URL", "").rstrip("/")
        self.authorization = os.getenv("SOLIDSIGN_API_AUTHORIZATION", "")
        self.profile = os.getenv("SOLIDSIGN_SIG_PROFILE", "ADRB")
        self.hash_algorithm = os.getenv("SOLIDSIGN_SIG_HASH_ALGORITHM", "SHA256")
        self.sig_field_measurement_unit = os.getenv("SOLIDSIGN_SIG_FIELD_MEASUREMENT_UNIT", "PIXELS")
        self.signature_field_config = os.getenv("SOLIDSIGN_SIG_FIELD_CONFIG", "")
        self.reason = os.getenv("SOLIDSIGN_SIG_REASON", "")
        self.location = os.getenv("SOLIDSIGN_SIG_LOCATION", "")
        self.contact = os.getenv("SOLIDSIGN_SIG_CONTACT", "")
        self.signer_cert_pem = os.getenv("SOLIDSIGN_CERT_PEM", "")
        raw_paths = os.getenv("SOLIDSIGN_SIG_IMAGE_PATHS", "")
        self.signature_image_paths = [p.strip() for p in raw_paths.split(",") if p.strip()]

    # ─── Step 1: Prepare ──────────────────────────────────────────────────────

    def prepare_signature(self, documents: List[Tuple[bytes, str]]) -> Optional[dict]:
        """
        [EN]    Sends PDF documents + signer certificate to SolidSign sign-preparation endpoint.
                Returns the full JSON response with hashes and finalNonce for the browser extension to sign.
        [PT-BR] Envia documentos PDF + certificado do assinante para o endpoint sign-preparation do SolidSign.
                Retorna o JSON completo com hashes e finalNonce para a extensão do browser assinar.
        """
        prep_url = self.base_url + "/solidsign/dsig/pdf/pkcs1/sign-preparation"
        headers = {"Authorization": self.authorization}

        files: dict = {}
        for i, (content, name) in enumerate(documents):
            files[f"document[{i}]"] = (name, content, "application/pdf")

        for i, img_path in enumerate(self.signature_image_paths):
            img = Path(img_path)
            if img.exists():
                files[f"signatureImage[{i}]"] = (img.name, open(img, "rb"), "image/jpeg")

        data = {
            "profile": self.profile,
            "hashAlgorithm": self.hash_algorithm,
            "sigFieldMeasurementUnit": self.sig_field_measurement_unit,
            "signatureFieldConfig": self.signature_field_config,
            "reason": self.reason,
            "location": self.location,
            "contact": self.contact,
            "certificate": self.signer_cert_pem,
        }

        # [EN]    Optional parameters — uncomment to use
        # [PT-BR] Parâmetros opcionais — descomente para usar
        # data["signatureFieldName"]     = "SignatureField1"
        # data["signatureTextConfig"]    = '[{"pageNumber":1,"coordinateX":200,"coordinateY":460,"text":"Signed","fontSize":10,"textColor":"BLACK"}]'
        # data["mdpPermissionLevel"]     = "1"
        # data["passwordsForDecryption"] = '["password"]'
        # data["documentInfoMetadata"]   = '{"title":"My Doc"}'
        # data["signatureQrCodeConfig"]  = '[...]'

        try:
            _index_field_configs(data)
            resp = requests.post(prep_url, headers=headers, files=files, data=data, timeout=120)
            resp.raise_for_status()
            result = resp.json()
            logger.info("PDF PKCS1 preparation OK. finalNonce=%s", result.get("finalNonce"))
            return result
        except requests.HTTPError as e:
            logger.error("SolidSign prep error %s: %s", e.response.status_code, e.response.text)
        except Exception as e:
            logger.error("Unexpected error during PDF preparation: %s", e)
        return None

    # ─── Step 2: Finalize ─────────────────────────────────────────────────────

    def finalize_signature(self, all_params: Dict[str, str]) -> Optional[dict]:
        """
        [EN]    Sends finalNonce and signature values to SolidSign sign-finalization endpoint.
                all_params must contain: finalNonce, signatureValue[0], signatureValue[1], ...
        [PT-BR] Envia finalNonce e valores de assinatura para o endpoint sign-finalization do SolidSign.
                all_params deve conter: finalNonce, signatureValue[0], signatureValue[1], ...
        """
        final_url = self.base_url + "/solidsign/dsig/pdf/pkcs1/sign-finalization"
        headers = {"Authorization": self.authorization}

        try:
            resp = requests.post(final_url, headers=headers, data=all_params, timeout=120)
            resp.raise_for_status()
            result = resp.json()
            logger.info("PDF PKCS1 finalization OK. identifier=%s", result.get("identifier"))
            return result
        except requests.HTTPError as e:
            logger.error("SolidSign final error %s: %s", e.response.status_code, e.response.text)
        except Exception as e:
            logger.error("Unexpected error during PDF finalization: %s", e)
        return None

    # ─── Form endpoints (all params from caller) ──────────────────────────────

    def prepare_form(
        self,
        authorization: str,
        base_url: str,
        documents: List[Tuple[bytes, str]],
        signature_images: List[Tuple[bytes, str]],
        certificate: str,
        profile: Optional[str] = None,
        hash_algorithm: Optional[str] = None,
        policy_version: Optional[str] = None,
        sig_field_measurement_unit: Optional[str] = None,
        signature_field_config: Optional[str] = None,
        reason: Optional[str] = None,
        location: Optional[str] = None,
        contact: Optional[str] = None,
        signature_field_name: Optional[str] = None,
        signature_text_config: Optional[str] = None,
        mdp_permission_level: Optional[str] = None,
        passwords_for_decryption: Optional[str] = None,
        document_info_metadata: Optional[str] = None,
        signature_qr_code_config: Optional[str] = None,
    ) -> Optional[dict]:
        """
        [EN]    Step 1 form variant — all config supplied by the caller.
        [PT-BR] Variante de formulário do passo 1 — toda configuração fornecida pelo chamador.
        """
        prep_url = base_url.rstrip("/") + "/solidsign/dsig/pdf/pkcs1/sign-preparation"
        headers = {"Authorization": authorization}

        files: dict = {}
        for i, (content, name) in enumerate(documents):
            files[f"document[{i}]"] = (name, content, "application/pdf")
        for i, (content, name) in enumerate(signature_images or []):
            files[f"signatureImage[{i}]"] = (name, content, "image/jpeg")

        data: dict = {"certificate": certificate}
        if profile:                     data["profile"] = profile
        if hash_algorithm:              data["hashAlgorithm"] = hash_algorithm
        if policy_version:              data["policyVersion"] = policy_version
        if sig_field_measurement_unit:  data["sigFieldMeasurementUnit"] = sig_field_measurement_unit
        if signature_field_config:      data["signatureFieldConfig"] = signature_field_config
        if reason:                      data["reason"] = reason
        if location:                    data["location"] = location
        if contact:                     data["contact"] = contact
        if signature_field_name:        data["signatureFieldName"] = signature_field_name
        if signature_text_config:       data["signatureTextConfig"] = signature_text_config
        if mdp_permission_level:        data["mdpPermissionLevel"] = mdp_permission_level
        if passwords_for_decryption:    data["passwordsForDecryption"] = passwords_for_decryption
        if document_info_metadata:      data["documentInfoMetadata"] = document_info_metadata
        if signature_qr_code_config:    data["signatureQrCodeConfig"] = signature_qr_code_config

        try:
            _index_field_configs(data)
            resp = requests.post(prep_url, headers=headers, files=files, data=data, timeout=120)
            resp.raise_for_status()
            result = resp.json()
            logger.info("PDF PKCS1 form preparation OK. finalNonce=%s", result.get("finalNonce"))
            return result
        except requests.HTTPError as e:
            logger.error("SolidSign prep form error %s: %s", e.response.status_code, e.response.text)
        except Exception as e:
            logger.error("Unexpected error in PDF PKCS1 form preparation: %s", e)
        return None

    def finalize_form(self, authorization: str, base_url: str, all_params: Dict[str, str]) -> Optional[dict]:
        """
        [EN]    Step 2 form variant — auth and base_url supplied explicitly.
        [PT-BR] Variante de formulário do passo 2 — auth e base_url fornecidos explicitamente.
        """
        final_url = base_url.rstrip("/") + "/solidsign/dsig/pdf/pkcs1/sign-finalization"
        headers = {"Authorization": authorization}

        try:
            resp = requests.post(final_url, headers=headers, data=all_params, timeout=120)
            resp.raise_for_status()
            result = resp.json()
            logger.info("PDF PKCS1 form finalization OK.")
            return result
        except requests.HTTPError as e:
            logger.error("SolidSign final form error %s: %s", e.response.status_code, e.response.text)
        except Exception as e:
            logger.error("Unexpected error in PDF PKCS1 form finalization: %s", e)
        return None

    # ─── Helper: download signed files and zip them ───────────────────────────

    def download_and_zip(self, sign_response: dict, original_names: List[str], auth: str) -> bytes:
        """
        [EN]    Downloads each signed document from SolidSign response links and packages them into a ZIP.
        [PT-BR] Baixa cada documento assinado dos links da resposta SolidSign e os empacota em um ZIP.
        """
        headers = {"Authorization": auth}
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for i, doc in enumerate(sign_response.get("documents", [])):
                links_obj = doc.get("_links") or {}
                download_url = (links_obj.get("self") or {}).get("href")
                if not download_url:
                    # [EN]    Fallback to legacy array format: "links": [{"rel","href"}]
                    # [PT-BR] Fallback para o formato antigo em array: "links": [{"rel","href"}]
                    download_url = next(
                        (lnk["href"] for lnk in doc.get("links", []) if lnk.get("rel") == "self"),
                        None,
                    )
                if not download_url:
                    continue
                r = requests.get(download_url, headers=headers, timeout=120)
                if r.status_code == 200:
                    zf.writestr(f"signed_{original_names[i]}", r.content)
        return buf.getvalue()
