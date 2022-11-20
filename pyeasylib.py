import hashlib
from typing import Any
import requests
import re
import xml.etree.ElementTree as ET
import logging
import json

basic_header = {"content-type": "text/xml"}

def get_session(_verify: bool = True) -> requests.Session:
    _se = requests.Session()
    _se.verify = _verify
    return _se


def send_emptyrequest(_session: requests.Session, _host: str) -> requests.Response:
    logging.debug("Enter send_emptyrequest")
    url: str = "https://" + _host + "/main.cgi"
    body = ""
    repl = _session.post(url, data=body, headers=basic_header)
    # print_raw_response(repl)
    return repl


def send_get_rsconfig(_session: requests.Session, _host: str) -> requests.Response:
    logging.debug("Enter send_get_rsconfig")
    url = "https://" + _host + "/main.cgi?js=rg_config.js"
    body = ""
    repl = _session.post(url, data=body, headers=basic_header)
    # print_raw_response(repl)
    return repl


def get_dm_cookie(_session: requests.Session, _host: str) -> str:
    logging.debug("Enter get_dm_cookie")
    resp = send_emptyrequest(_session, _host)
    logging.debug("dm_cookie is the soap cookie used")
    a: re.Match[str] | None = re.search("dm_cookie=\\'([\w\d]*)\\'", resp.text)
    logging.debug("regex result is in capturegroup 1")
    cookie: str = a[1]
    logging.info("Found SOAP(DM) Cookie: " + cookie)
    return cookie


def send_get_property(_property: str, _session: requests.Session, _dmcookie: str, _host: str) -> requests.Response:
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
    #returns requests.models.Response.content
    resp_body: requests.Response = _session.post(
        url_data_model, data=body_request, headers=soap_header)

    log_debug_raw_response(resp_body)
    #resp_body.content.decode("utf-8")
    return resp_body


def get_authkey(_session: requests.Session, _host: str) -> str:
    logging.debug("Enter get_authkey")
    rsconfig = send_get_rsconfig(_session, _host)
    find_auth_key: re.Match[str] = re.search("var auth_key = \'(\d*)\'", rsconfig.text)
    # take auth_key from capture group
    _auth_key: str = find_auth_key[1]
    logging.info("found authkey:")
    logging.info(_auth_key)
    return _auth_key


def get_login_cookie(_session: requests.Session, _passw: str, _host: str, _val_dm_cookie: str) -> str:
    logging.debug("Enter get_login_cookie")
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
    repl: requests.Response = _session.post(url_data_model, data=soap, headers=soap_head)
    #TODO: check if response holds info of result (success/fail)

    logging.debug("reply of login")
    # print_raw_response(repl)

    logging.debug("new session cookie after login")
    logging.debug(_session.cookies)

    logging.debug(
        "get new soap cookie after login (old is automatically expiring)")
    return get_dm_cookie(_session, _host)


def get_single_value(_property: str, _session: requests.Session, _dm_cookie: str, _host: str) -> str | None:
    logging.debug("get_single_value")
    res: requests.Response = send_get_property(_property, _session, _dm_cookie, _host)
    recon: str = res.content.decode("utf-8")
    tree = ET.fromstring(recon)
    siva = tree.findtext("*//Value")
    if siva == None:
        logging.debug("no value received, returning error as value")
        siva = tree.findtext("*//FaultLang")
    else:
        # logging.debug("'", siva, "'")
        logging.debug("Got/Returning: " + siva)
    return siva


def post_close_con(_host: str, _session: requests.Session) -> None:
    logging.debug("Enter post_close_con")
    logging.info("Closing Connection")
    url = "https://" + _host + "/main.cgi?page=login.html"
    _session.post(url=url, data="", headers={'Connection': 'close'})

#################################################################################
#                            HANDLE XML
#################################################################################


def ParameterValueStruct_to_dict(_xmltree: ET.Element) -> dict[str, str]:
    """transform the tr069 ParameterValueStruct to dict"""
    kvp: dict[str, str] = {}
    for elem in _xmltree:
        if (elem[0].text is not None):
            kvp[elem[0].text] = ""
            if (elem[1].text is not None):
                kvp[elem[0].text] = elem[1].text
    return kvp


# Gets down xml levels by a specified list of keys
def GetLowerElement(_root: ET.Element, _level: list[str]) -> ET.Element:
    logging.debug("Enter GetLowerElement")
    res: ET.Element = _root
    for _lev in _level:
        if (type(res)):
            logging.debug("getting down to: " + _lev)
            res: ET.Element = res.find(_lev)
    return res


# interprets the xml response of a parametervaluestruct
def interpret_ParameterValueStruct(val: ET.Element) -> dict[str, str]:
    logging.debug("interpret_ParameterValueStruct")
    logging.debug("defining level to get down:")
    lvl: list[str] = [
        '{http://schemas.xmlsoap.org/soap/envelope/}Body',
        '{urn:dslforum-org:cwmp-1-0}GetParameterValuesResponse',
        'ParameterList'
    ]
    logging.debug(lvl)
    le = GetLowerElement(_root=val, _level=lvl)
    return ParameterValueStruct_to_dict(le)


def log_debug_tree(_tree: ET.ElementTree):
    logging.debug("log_debug_tree:")
    for elem in _tree.iter():
        log_debug_element(elem)


def log_debug_element(_elem: ET.Element):
    logging.debug("attrib: %s", _elem.attrib)
    logging.debug("tag: %s", _elem.tag)
    logging.debug("text: %s\n", _elem.text)

#################################################################################

#                            IMPORT / EXPORT / LOG


def log_keyvalue(keyval: dict[str, str]):
    for key, val in keyval.items():
        logging.debug(key + ": " + val)


def log_type(_var: Any, _varname: str):
    logging.debug("type of " + _varname + " is currently:")
    logging.debug(type(_var))


def log_debug_raw_response(resp: requests.Response):
    logging.debug("Raw Cookie:")
    logging.debug(resp.cookies)
    logging.debug("Raw Header:")
    logging.debug(resp.headers)
    logging.debug("Raw Response")
    logging.debug(resp.text)


#TODO: check if type TextIOWrapper is better fitting
def write_keyvalue_csv(keyval: dict[str, str], filestream: Any):
    for key, val in keyval.items():
        logging.debug(key + ": " + val)
        filestream.write(key + ": " + val + '\n')
    filestream.close()


def write_keyvalue_json(keyval: dict[str, str], filestream: Any):
    logging.debug("New Json Object:")
    # json_object = json.dumps(keyval, indent = 4)
    json_object = json.dumps(keyval)
    logging.debug(json_object)
    logging.debug("Writing JSON to file:")
    filestream.write(json_object)
    filestream.close()


#################################################################################
