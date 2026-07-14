"""
[EN]    PAdES (PDF) two-step signing example using PKCS#1 (browser extension / external private key).
        Start: uvicorn main:app --port 8089 --reload

        Flow:
          Step 1 — POST /api/pdf/pkcs1/prepare       → returns hashes + finalNonce to the browser extension
          Step 2 — POST /api/pdf/pkcs1/finalize      → receives signed hashes + finalNonce, returns ZIP

[PT-BR] Exemplo de assinatura PAdES (PDF) em dois passos com PKCS#1 (extensão do browser / chave privada externa).
        Iniciar: uvicorn main:app --port 8089 --reload

        Fluxo:
          Passo 1 — POST /api/pdf/pkcs1/prepare      → retorna hashes + finalNonce para a extensão do browser
          Passo 2 — POST /api/pdf/pkcs1/finalize     → recebe hashes assinados + finalNonce, retorna ZIP
"""

import logging
from typing import Dict, List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import JSONResponse, Response

from service import PdfPkcs1Service

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")

app = FastAPI(title="SolidSign — PDF PKCS1 Example")
service = PdfPkcs1Service()


@app.post("/api/pdf/pkcs1/prepare")
async def prepare(
    document: List[UploadFile] = File(...),
    signatureImage: Optional[List[UploadFile]] = File(default=None),
):
    """
    [EN]    Step 1 — sends documents to SolidSign and returns the hashes + finalNonce for signing.
            Certificate PEM is read from .env (SOLIDSIGN_CERT_PEM).
    [PT-BR] Passo 1 — envia documentos ao SolidSign e retorna os hashes + finalNonce para assinatura.
            O PEM do certificado é lido do .env (SOLIDSIGN_CERT_PEM).
    """
    docs = [(await d.read(), d.filename) for d in document]
    imgs = [(await img.read(), img.filename) for img in (signatureImage or [])]

    result = service.prepare_signature(docs)
    if result:
        return JSONResponse(content=result)
    return Response(content="Preparation failed. Check logs.", status_code=500)


@app.post("/api/pdf/pkcs1/finalize")
async def finalize(request: Request):
    """
    [EN]    Step 2 — receives finalNonce and signatureValue[i] from the browser extension,
            forwards to SolidSign, and returns the ZIP of signed documents.
    [PT-BR] Passo 2 — recebe finalNonce e signatureValue[i] da extensão do browser,
            encaminha ao SolidSign e retorna o ZIP dos documentos assinados.
    """
    form = await request.form()
    all_params = {k: v for k, v in form.items()}
    result = service.finalize_signature(all_params)
    if result:
        return JSONResponse(content=result)
    return Response(content="Finalization failed. Check logs.", status_code=500)


# ─── Form endpoints (all params from request) ─────────────────────────────────

@app.post("/api/pdf/pkcs1/prepare/form")
async def prepare_form(
    document: List[UploadFile] = File(...),
    authorization: str = Form(...),
    baseUrl: str = Form(...),
    certificate: str = Form(...),
    signatureImage: Optional[List[UploadFile]] = File(default=None),
    profile: Optional[str] = Form(default=None),
    hashAlgorithm: Optional[str] = Form(default=None),
    policyVersion: Optional[str] = Form(default=None),
    sigFieldMeasurementUnit: Optional[str] = Form(default=None),
    signatureFieldConfig: Optional[str] = Form(default=None),
    reason: Optional[str] = Form(default=None),
    location: Optional[str] = Form(default=None),
    contact: Optional[str] = Form(default=None),
    signatureFieldName: Optional[str] = Form(default=None),
    signatureTextConfig: Optional[str] = Form(default=None),
    mdpPermissionLevel: Optional[str] = Form(default=None),
    passwordsForDecryption: Optional[str] = Form(default=None),
    documentInfoMetadata: Optional[str] = Form(default=None),
    signatureQrCodeConfig: Optional[str] = Form(default=None),
):
    """
    [EN]    Step 1 form variant — all config from the request.
    [PT-BR] Variante de formulário do passo 1 — toda configuração da requisição.
    """
    docs = [(await d.read(), d.filename) for d in document]
    imgs = [(await img.read(), img.filename) for img in (signatureImage or [])]

    result = service.prepare_form(
        authorization=authorization,
        base_url=baseUrl,
        documents=docs,
        signature_images=imgs,
        certificate=certificate,
        profile=profile,
        hash_algorithm=hashAlgorithm,
        policy_version=policyVersion,
        sig_field_measurement_unit=sigFieldMeasurementUnit,
        signature_field_config=signatureFieldConfig,
        reason=reason,
        location=location,
        contact=contact,
        signature_field_name=signatureFieldName,
        signature_text_config=signatureTextConfig,
        mdp_permission_level=mdpPermissionLevel,
        passwords_for_decryption=passwordsForDecryption,
        document_info_metadata=documentInfoMetadata,
        signature_qr_code_config=signatureQrCodeConfig,
    )
    if result:
        return JSONResponse(content=result)
    return Response(content="Preparation failed. Check logs.", status_code=500)


@app.post("/api/pdf/pkcs1/finalize/form")
async def finalize_form(
    authorization: str = Form(...),
    baseUrl: str = Form(...),
    finalNonce: str = Form(...),
    request: Request = None,
):
    """
    [EN]    Step 2 form variant — auth and baseUrl supplied in the request body.
    [PT-BR] Variante de formulário do passo 2 — auth e baseUrl fornecidos no corpo da requisição.
    """
    form = await request.form()
    params = {k: v for k, v in form.items() if k not in ("authorization", "baseUrl")}

    result = service.finalize_form(authorization=authorization, base_url=baseUrl, all_params=params)
    if result:
        return JSONResponse(content=result)
    return Response(content="Finalization failed. Check logs.", status_code=500)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8089)
