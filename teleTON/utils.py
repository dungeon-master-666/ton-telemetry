from datetime import datetime, timedelta
from typing import Optional

import inject

from pymongo import MongoClient, DESCENDING
from pymongo.errors import CollectionInvalid

from loguru import logger

from config import settings


# inject configure
def inject_config(binder):
    with open(settings.mongodb['password_file'], 'r') as f:
        password = f.read()
    client = MongoClient(host=settings.mongodb["host"], 
                         port=settings.mongodb["port"],
                         username=settings.mongodb["username"],
                         password=password)
    db_name = settings.mongodb.database

    try:
        client[db_name].create_collection(
            'telemetry_data', 
            timeseries={ 
                'timeField': 'timestamp',
                'metaField': 'data',
            },
            expireAfterSeconds=86400 * 90 # 90 days
        )
        logger.info("Collection created")
    except CollectionInvalid:
        logger.info("Collection already exists")

    binder.bind(MongoClient, client)

inject.configure_once(inject_config)


ADNL_IP_BOND_TTL = 3600 * 4 # 4 hours
@inject.autoparams()
def _validate_client(adnl: str, ip: str, client: MongoClient):
    start = datetime.utcnow() - timedelta(seconds=ADNL_IP_BOND_TTL)
    db_name = settings.mongodb.database

    # Check that last record within last ADNL_IP_BOND_TTL seconds
    # with `remote_address` == `ip` contains `adnl_address` == `adnl`
    ip_request = {'timestamp': {'$gt': start}, 'data.remote_address': {'$eq': ip}}
    ip_response = client[db_name].telemetry_data.find(ip_request).limit(1).sort('timestamp', DESCENDING)
    ip_response = list(ip_response)
    if len(ip_response):
        saved_adnl = ip_response[0]['data']['adnl_address']
        if saved_adnl != adnl:
            logger.info(f"{ip} - {adnl} request not allowed. Last submitted adnl for this ip: {saved_adnl}")
            return False

    # Check that last record within last ADNL_IP_BOND_TTL seconds
    # with `adnl_address` == `adnl` contains `remote_address` == `ip`
    adnl_request = {'timestamp': {'$gt': start}, 'data.adnl_address': {'$eq': adnl}}
    adnl_response = client[db_name].telemetry_data.find(adnl_request).limit(1).sort('timestamp', DESCENDING)
    adnl_response = list(adnl_response)
    if len(adnl_response):
        saved_ip = adnl_response[0]['data']['remote_address']
        if saved_ip != ip:
            logger.info(f"{ip} - {adnl} request not allowed. Last ip for this adnl: {saved_ip}")
            return False

    return True

@inject.autoparams()
def _report_status(adnl: str, ip: str, data: dict, client: MongoClient):
    record = {
        'timestamp': datetime.utcnow(),
        'data': {
            'adnl_address': adnl,
            'remote_address': ip,
            'data': data
        }
    }
    db = settings.mongodb.database
    client[db].telemetry_data.insert_one(record)

@inject.autoparams()
def _get_data(timestamp_from: float, timestamp_to: Optional[float], adnl: Optional[str], ip: Optional[str], client: MongoClient):
    start = datetime.fromtimestamp(timestamp_from)
    if timestamp_to is not None:
        end = datetime.fromtimestamp(timestamp_to)
    else:
        end = datetime.utcnow()
    request = {'timestamp': {'$gt': start, '$lt': end}}
    if adnl:
        request['data.adnl_address'] = {'$eq': adnl}
    if ip:
        request['data.remote_address'] = {'$eq': ip}
    db_name = settings.mongodb.database
    response = client[db_name].telemetry_data.find(request, {'_id': False})
    result = []
    for cur in response:
        data = cur['data']
        data['timestamp'] = cur['timestamp'].timestamp()
        result.append(data)
    return result
