from loguru import logger

from fastapi import FastAPI, Request, Security, Depends
from fastapi.responses import JSONResponse
from fastapi.params import Query, Body
from fastapi.exceptions import HTTPException
from fastapi.security.api_key import APIKeyQuery

from config import settings
from teleTON.utils import _validate_client, _report_status, _get_data, _get_validator_country, _is_address_known


# FastAPI app
description = """TON Telemetry"""

app = FastAPI(
    title="TON Telemetry Service",
    description=description
)

@app.exception_handler(HTTPException)
async def httpexception_handler(request, exc):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

@app.exception_handler(Exception)
async def exception_handler(request, exc):
    return JSONResponse({"detail": "unknown"}, status_code=503)

api_keys = []

@app.on_event("startup")
def startup():
    with open(settings.api_keys_file, 'r') as f:
        global api_keys
        api_keys = json.load(f)


@app.post('/report_status')
def report_status(request: Request, data: dict=Body(...)):
    try: 
        adnl = data.pop('adnlAddr')
        data['gitHashes']
    except KeyError:
        raise HTTPException(status_code=422, detail="adnlAddr and gitHashes are required")

    if adnl is None:
        raise HTTPException(status_code=422, detail="adnlAddr cannot be null")

    ip = request.headers['x-real-ip']

    if _validate_client(adnl, ip):
        _report_status(adnl, ip, data)
    else:
        raise HTTPException(status_code=403)

    return "ok"

@app.post('/report_overlays')
def report_overlays(request: Request, data: dict=Body(...)):
    try:
        adnl = data.pop('adnlAddr')
    except KeyError:
        raise HTTPException(status_code=422, detail="adnlAddr is required")

    if adnl is None:
        raise HTTPException(status_code=422, detail="adnlAddr cannot be null")

    return "ok"

api_key_query = APIKeyQuery(name="api_key", description="API key sent as query parameter", auto_error=True)

def check_permissions(request: Request, api_key: str=Security(api_key_query)):
    if api_key not in api_keys:
        logger.info(f"Client {request.headers['x-real-ip']} tried to get data with unknown api key: {api_key}")
        raise HTTPException(status_code=401, detail="not authorized")
    if request.method not in api_keys[api_key]['methods']:
        logger.info(f"Client {request.headers['x-real-ip']} with api key {api_key} tried to get request {request.method} without permission")
        raise HTTPException(status_code=403, detail="not authorized")
    return api_key

@app.get('/getValidatorCountry', response_class=JSONResponse)
def get_validator_country(
    request: Request,
    adnl_address: str,
    api_key: str=Depends(check_permissions)):
    return _get_validator_country(adnl_address)
    

@app.get('/getTelemetryData', response_class=JSONResponse)
def get_telemetry_data(
    request: Request,
    timestamp_from: float=Query(...), 
    timestamp_to: float=Query(None),
    adnl_address: str=Query(None),
    ip_address: str=Query(None),
    api_key: str=Depends(check_permissions)):
    return _get_data(timestamp_from, timestamp_to, adnl_address, ip_address)

@app.get('/checkAddressKnown', response_class=JSONResponse)
def check_address_known(
    adnl_address: str,
    timestamp_from: float):

    return {
        'address_known': _is_address_known(adnl_address, timestamp_from)
    }
