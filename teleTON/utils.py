from datetime import datetime, timedelta
from typing import Optional
from hashlib import sha256

import inject
from pymongo import MongoClient, DESCENDING
from pymongo.errors import CollectionInvalid
from loguru import logger
import geoip2.database

from config import settings

class AdnlNotFound(Exception):
    pass

with open(settings.hash_salt_file, 'r') as f:
    hash_salt = f.read()

country_reader = geoip2.database.Reader(settings.geoip_country_db)
isp_reader = geoip2.database.Reader(settings.geoip_isp_db)

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
        client[db_name].telemetry_data.create_index([('data.adnl_address', 1), ('timestamp', 1)])
        client[db_name].create_collection(
            'overlays_data', 
            timeseries={ 
                'timeField': 'timestamp',
                'metaField': 'data',
            },
            expireAfterSeconds=86400 * 90 # 90 days
        )
        logger.info("Collections created")
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
    # with `remote_ip_hash` == `ip_hash` contains `adnl_address` == `adnl`
    ip_hash = sha256((ip + hash_salt).encode('utf-8')).hexdigest()
    ip_request = {'timestamp': {'$gt': start}, 'data.remote_ip_hash': {'$eq': ip_hash}}
    ip_response = client[db_name].telemetry_data.find(ip_request).limit(1).sort('timestamp', DESCENDING)
    ip_response = list(ip_response)
    if len(ip_response):
        saved_adnl = ip_response[0]['data']['adnl_address']
        if saved_adnl != adnl:
            logger.info(f"{ip_hash} - {adnl} request not allowed. Last submitted adnl for this ip: {saved_adnl}")
            return False

    # Check that last record within last ADNL_IP_BOND_TTL seconds
    # with `adnl_address` == `adnl` contains `remote_ip_hash` == `ip_hash`
    adnl_request = {'timestamp': {'$gt': start}, 'data.adnl_address': {'$eq': adnl}}
    adnl_response = client[db_name].telemetry_data.find(adnl_request).limit(1).sort('timestamp', DESCENDING)
    adnl_response = list(adnl_response)
    if len(adnl_response):
        saved_ip_hash = adnl_response[0]['data']['remote_ip_hash']
        if saved_ip_hash != ip_hash:
            logger.info(f"{ip_hash} - {adnl} request not allowed. Last ip hash for this adnl: {saved_ip_hash}")
            return False

    return True

@inject.autoparams()
def _report_status(adnl: str, ip: str, data: dict, client: MongoClient):
    ip_hash = sha256((ip + hash_salt).encode('utf-8')).hexdigest()
    try:
        remote_country = country_reader.country(ip).country.iso_code
    except:
        remote_country = None
    try:
        remote_isp = isp_reader.isp(ip).isp
    except:
        remote_isp = None

    record = {
        'timestamp': datetime.utcnow(),
        'data': {
            'adnl_address': adnl,
            'remote_ip_hash': ip_hash,
            'remote_country': remote_country,
            'remote_isp': remote_isp,
            'data': data
        }
    }
    db = settings.mongodb.database
    client[db].telemetry_data.insert_one(record)

@inject.autoparams()
def _report_overlays(adnl: str, ip: str, overlays_stats: dict, client: MongoClient):
    ip_hash = sha256((ip + hash_salt).encode('utf-8')).hexdigest()

    record = {
        'timestamp': datetime.utcnow(),
        'data': {
            'adnl_address': adnl,
            'remote_ip_hash': ip_hash,
            'data': overlays_stats
        }
    }
    db = settings.mongodb.database
    client[db].overlays_data.insert_one(record)

@inject.autoparams()
def _get_telemetry_data(timestamp_from: float, timestamp_to: Optional[float], adnl: Optional[str], ip: Optional[str], client: MongoClient):
    start = datetime.fromtimestamp(timestamp_from)
    if timestamp_to is not None:
        end = datetime.fromtimestamp(timestamp_to)
    else:
        end = datetime.utcnow()
    request = {'timestamp': {'$gt': start, '$lt': end}}
    if adnl:
        request['data.adnl_address'] = {'$eq': adnl}
    if ip:
        ip_hash = sha256((ip + hash_salt).encode('utf-8')).hexdigest()
        request['data.remote_ip_hash'] = {'$eq': ip_hash}
    db_name = settings.mongodb.database
    response = client[db_name].telemetry_data.find(request, {'_id': False})
    result = []
    for cur in response:
        data = cur['data']
        data['timestamp'] = cur['timestamp'].timestamp()
        result.append(data)
    return result

@inject.autoparams()
def _get_overlays_data(adnl: str, client: MongoClient):
    request = {'data.adnl_address': {'$eq': adnl}}
    db_name = settings.mongodb.database
    response = client[db_name].telemetry_data.find(request, {'_id': False}).limit(1).sort('timestamp', DESCENDING)
    if response is None:
        raise AdnlNotFound()
    return response['data']

COUNTRY_CHECK_TTL = 86400 # 1 day
@inject.autoparams()
def _get_validator_country(adnl: str, client: MongoClient):
    start = datetime.utcnow() - timedelta(seconds=COUNTRY_CHECK_TTL)
    request = {'timestamp': {'$gt': start}, 'data.adnl_address': {'$eq': adnl}}
    db_name = settings.mongodb.database
    response = client[db_name].telemetry_data.find_one(request).limit(1).sort('timestamp', DESCENDING)
    if response is None:
        raise AdnlNotFound()
    country = response[0]['data']['remote_country']
    return country

@inject.autoparams()
def _is_address_known(adnl_address: str, timestamp_from: float, client: MongoClient):
    timestamp = datetime.fromtimestamp(timestamp_from)
    request = {
        'timestamp': {'$gt': timestamp}, 
        'data.adnl_address': {'$eq': adnl_address}
    }
    db_name = settings.mongodb.database
    return client[db_name].telemetry_data.count_documents(request, limit=1) > 0

