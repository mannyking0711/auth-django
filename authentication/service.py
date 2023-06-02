from urllib.parse import urljoin

import requests

api_url = 'https://154.12.226.160:5000'


def startScan(domain):
    response = requests.get(urljoin(api_url, '/api/start'), params={'domain_name': domain}, verify=False, headers={
        'api_key': '9af95fa9-6991-44eb-8c1d-19ae0493ed67'
    })
    if response.status_code == 200:
        return response.json()['guid']
    else:
        raise RuntimeError('Failed')


def stopScan(guid):
    response = requests.get(urljoin(api_url, 'api/stop'), params={'guid': guid}, verify=False, headers={
        'api_key': '9af95fa9-6991-44eb-8c1d-19ae0493ed67'
    })
    if response.status_code == 200:
        return response
    else:
        raise RuntimeError('Failed')


def getScanResult(guid):
    response = requests.get(urljoin(api_url, 'api/result'), params={'guid': guid}, verify=False, headers={
        'api_key': '9af95fa9-6991-44eb-8c1d-19ae0493ed67'
    })
    if response.status_code == 200:
        return response.json()
    else:
        raise RuntimeError('Scan not started yet')
