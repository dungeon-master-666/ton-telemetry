import json
from loguru import logger

import httpx
from datetime import datetime

from fastapi import FastAPI, Request, Security, Depends
from fastapi.responses import JSONResponse
from fastapi.params import Query, Body
from fastapi.exceptions import HTTPException
from fastapi.security.api_key import APIKeyQuery

from fastapi_utils.tasks import repeat_every

from config import settings
from teleTON.utils import _validate_client, _report_status, _report_overlays, _get_telemetry_data, _get_overlays_data, _get_validator_country, _is_address_known, AdnlNotFound


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

current_validators_map = {}

@app.on_event("startup")
@repeat_every(seconds=5 * 60, logger=logger)  # 5 min
async def update_current_validation_cycle() -> None:
    async with httpx.AsyncClient() as client:
        r = await client.get('https://elections.toncenter.com/getValidationCycles?return_participants=true&offset=0&limit=3', timeout=5)
    data = r.json()
    timestamp_now = datetime.utcnow().timestamp()
    cur_cycle = None
    for val_cycle in data:
        if timestamp_now >= val_cycle['cycle_info']['utime_since'] and timestamp_now <= val_cycle['cycle_info']['utime_until']:
            cur_cycle = val_cycle
            break
    if cur_cycle is None:
        raise Exception("no current cycle")
    validators_map = {}
    for val in cur_cycle['cycle_info']['validators']:
        validators_map[val['adnl_addr']] = val

    global current_validators_map
    current_validators_map = validators_map

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

    logger.info(current_validators_map.get(adnl))
    if _validate_client(adnl, ip):
        _report_status(adnl, ip, data, current_validators_map.get(adnl))
    else:
        raise HTTPException(status_code=403)

    return "ok"

@app.post('/report_overlays')
def report_overlays(request: Request, data: dict=Body(...)):
    try:
        adnl = data.pop('adnlAddr')
        overlays_stats = data['overlaysStats']
    except KeyError:
        raise HTTPException(status_code=422, detail="adnlAddr and overlaysStats are required")

    if adnl is None:
        raise HTTPException(status_code=422, detail="adnlAddr cannot be null")

    ip = request.headers['x-real-ip']
    if _validate_client(adnl, ip):
        _report_overlays(adnl, ip, overlays_stats)
    else:
        raise HTTPException(status_code=403)

    return "ok"

api_key_query = APIKeyQuery(name="api_key", description="API key sent as query parameter", auto_error=True)

def check_permissions(request: Request, api_key: str=Security(api_key_query)):
    if api_key not in api_keys:
        logger.info(f"Client {request.headers['x-real-ip']} tried to get data with unknown api key: {api_key}")
        raise HTTPException(status_code=401, detail="not authorized")
    endpoint = request.url.path[1:] # skip / in the beginning
    if endpoint not in api_keys[api_key]['methods']:
        logger.info(f"Client {request.headers['x-real-ip']} with api key {api_key} tried to get request {endpoint} without permission")
        raise HTTPException(status_code=403, detail="not authorized")
    return api_key

@app.get('/getTelemetryData', response_class=JSONResponse)
def get_telemetry_data(
    request: Request,
    timestamp_from: float=Query(...), 
    timestamp_to: float=Query(None),
    adnl_address: str=Query(None),
    ip_address: str=Query(None),
    api_key: str=Depends(check_permissions)):
    return _get_telemetry_data(timestamp_from, timestamp_to, adnl_address, ip_address)

@app.get('/getOverlaysData', response_class=JSONResponse)
def get_overlays_data(
    request: Request,
    timestamp_from: float=Query(...), 
    timestamp_to: float=Query(None),
    adnl_address: str=Query(None),
    api_key: str=Depends(check_permissions)):
    return _get_overlays_data(timestamp_from, timestamp_to, adnl_address)

@app.get('/getValidatorCountry', response_class=JSONResponse)
def get_validator_country(
    request: Request,
    adnl_address: str,
    api_key: str=Depends(check_permissions)):
    try:
        country = _get_validator_country(adnl_address)
    except AdnlNotFound:
        raise HTTPException(status_code=404, detail="No validator with provided adnl sent telemetry data")

    return {
        'country': country
    }

@app.get('/checkAddressKnown', response_class=JSONResponse)
def check_address_known(
    adnl_address: str,
    timestamp_from: float):

    return {
        'address_known': _is_address_known(adnl_address, timestamp_from)
    }
