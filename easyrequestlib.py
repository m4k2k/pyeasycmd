
import hashlib
import requests
import re
from requests import Session
import xml.etree.ElementTree as ET
import logging
import json

basic_header = {"content-type": "text/xml"}


def get_session(_verify=True):
    _se = requests.Session()
    _se.verify = _verify
    return _se


def print_raw_response(resp: requests.Response):
    print("Raw Cookie:")
    print(resp.cookies)
    print("Raw Header:")
    print(resp.headers)
    print("Raw Response")
    print(resp.text)


def send_emptyrequest(_session, _host):
    logging.debug("Enter send_emptyrequest")
    url = "https://" + _host + "/main.cgi"
    body = ""
    repl = _session.post(url, data=body, headers=basic_header)
    # print_raw_response(repl)
    return repl


def send_get_rsconfig(_session, _host):
    logging.debug("Enter send_get_rsconfig")
    url = "https://" + _host + "/main.cgi?js=rg_config.js"
    body = ""
    repl = _session.post(url, data=body, headers=basic_header)
    # print_raw_response(repl)
    return repl


def get_dm_cookie(_session, _host):
    logging.debug("Enter get_dm_cookie")
    resp = send_emptyrequest(_session, _host)
    # dm_cookie is the soap cookie used
    a = re.search("dm_cookie=\\'([\w\d]*)\\'", resp.text)
    # regex result is in capturegroup 1
    cookie = a[1]
    # print("Example for SOAP(DM) cookie = 'D647A60A019C08351F67ADD5DG705ED0'")
    logging.info("Found SOAP(DM) Cookie: " + cookie)
    return cookie


def send_get_property(_property, _session, _dmcookie, _host):
    logging.debug("Enter send_get_property")
    url_data_model = "https://" + _host + "/data_model.cgi"
    body_request = """
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
        <soapenv:Header>
            <DMCookie>#cookie#</DMCookie>
            <SessionNotRefresh>1</SessionNotRefresh>
        </soapenv:Header>
        <soapenv:Body>
            <cwmp:GetParameterValues xmlns="">
                <ParameterNames>
                    <string>#reqprop#</string>
                </ParameterNames>
            </cwmp:GetParameterValues>
        </soapenv:Body>
    </soapenv:Envelope>
    """

    body_request = body_request.replace("#cookie#", _dmcookie)
    body_request = body_request.replace("#reqprop#", _property)

    soap_header = basic_header
    soap_header.update(
        {"SOAPAction": "cwmp:GetParameterValues", "SOAPServer": ""})

    # print("Raw Request Body:")
    # print(body_request)

    resp_body = _session.post(
        url_data_model, data=body_request, headers=soap_header)

    # print_raw_response(resp_body)

    return resp_body


def print_element(_elem):
    print("attrib: ", end="")
    print(_elem.attrib)
    print("tag: ", end="")
    print(_elem.tag)
    print("text: ", end="")
    print(_elem.text)
    print("\n")


def get_authkey(_session, _host):
    logging.debug("Enter get_authkey")
    rsconfig = send_get_rsconfig(_session, _host)
    find_auth_key = re.search("var auth_key = \'(\d*)\'", rsconfig.text)
    # take auth_key from capture group
    find_auth_key = find_auth_key[1]
    logging.info("found authkey:")
    logging.info(find_auth_key)
    return find_auth_key


def get_login_cookie(_session, _passw, _host, _val_dm_cookie):
    auth_key = get_authkey(_session, _host)
    soap = """
    <soapenv:Envelope xmlns:soapenv= "http://schemas.xmlsoap.org/soap/envelope/">
        <soapenv:Header>
            <DMCookie>#cookie#</DMCookie>
        </soapenv:Header>
        <soapenv:Body>
            <cwmp:Login xmlns= "">
                <ParameterList>
                    <Username>vodafone</Username>
                    <Password>#hashed_pwd#</Password>
                    <AllowRelogin>0</AllowRelogin>
                </ParameterList>
            </cwmp:Login>
        </soapenv:Body>
    </soapenv:Envelope>
    """

    str_to_hash = _passw + auth_key
    str_hashed = hashlib.md5(str_to_hash.encode('utf-8')).hexdigest()

    soap = soap.replace("#cookie#", _val_dm_cookie)
    soap = soap.replace("#hashed_pwd#", str_hashed)

    soap_head = basic_header
    soap_head.update({"SOAPAction": "cwmp:Login", "SOAPServer": ""})
    url_data_model = "https://" + _host + "/data_model.cgi"

    logging.debug("session cookie before login")
    logging.debug(_session.cookies)
    repl = _session.post(url_data_model, data=soap, headers=soap_head)

    logging.debug("reply of login")
    # print_raw_response(repl)

    logging.debug("new session cookie after login")
    logging.debug(_session.cookies)

    logging.debug("get new soap cookie after login (old is automatically expiring)")
    return get_dm_cookie(_session, _host)


def get_single_value(_property, _session, _dm_cookie, _host):
    logging.debug("get_single_value")
    res = send_get_property(_property, _session, _dm_cookie, _host)
    tree = ET.fromstring(res.content)
    siva = tree.findtext("*//Value")
    if siva == None:
        logging.debug("no value received, returning error as value")
        siva = tree.findtext("*//FaultLang")
    else:
        # logging.debug("'", siva, "'")
        logging.debug("Got/Returning: " + siva)
    return siva

def post_close_con(_host, _session):
    logging.debug("Enter post_close_con")
    logging.info("Closing Connection")
    url = "https://" + _host + "/main.cgi?page=login.html"
    _session.post(url=url, data="", headers={'Connection': 'close'})

# key value handling:



def log_keyvalue(keyval):
    for key, val in keyval.items():
        logging.debug(key + ": " + val)   


def write_keyvalue_csv(keyval,filestream):
    for key, val in keyval.items():
        logging.debug(key + ": " + val)
        filestream.write(key + ": " + val + '\n')
    filestream.close()

def write_keyvalue_json(keyval,filestream):
    logging.debug("New Json Object:")
    # json_object = json.dumps(keyval, indent = 4)
    json_object = json.dumps(keyval)
    logging.debug(json_object)
    logging.debug("Writing JSON to file:")
    filestream.write(json_object)
    filestream.close()