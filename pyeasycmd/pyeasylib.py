import ast
import hashlib
import json
import logging
import re
import ssl
import xml.etree.ElementTree as ET
from typing import Any

import aiohttp
import requests

basic_header = {"content-type": "text/xml"}


# LOG_LEVEL = logging.DEBUG
LOG_LEVEL = logging.INFO
# LOG_LEVEL = logging.ERROR

# logging.basicConfig(filename='example.log', encoding='utf-8', level=logging.DEBUG)
logging.basicConfig(encoding="utf-8", level=LOG_LEVEL, format="%(levelname)s:%(asctime)s %(message)s")

logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

logger = logging.getLogger("pyeasycmd")


async def get_session_async_aio(_verify: str) -> aiohttp.ClientSession:
    logger = logging.getLogger("pyeasycmd" + "." + "get_session_async_aio")
    logger.debug("ENTER get_session_async_aio")
    logger.debug("create context")
    sslcontext = ssl.create_default_context(cafile=_verify)
    logger.debug("create connector")
    conn = aiohttp.TCPConnector(ssl=sslcontext)
    logger.info("start session")
    _se = aiohttp.ClientSession(connector=conn)
    logger.debug("EXIT get_session_async_aio")
    return _se


def get_session(_verify: str | bool = True) -> requests.Session:
    _se = requests.Session()
    _se.verify = _verify
    return _se


async def send_emptyrequest_async_aio(_session: aiohttp.ClientSession, _host: str) -> aiohttp.ClientResponse:
    logger = logging.getLogger("pyeasycmd" + "." + "send_emptyrequest_async")
    logger.debug("ENTER send_emptyrequest")
    url: str = "https://" + _host + "/main.cgi"
    body = ""
    logger.debug("async post")
    req = _session.post(url=url, data=body, headers=basic_header)
    repl = await req
    logger.debug("##### reply:")
    log_debug_raw_response(repl)
    logger.debug("EXIT send_emptyrequest")
    return repl


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


async def send_get_lang_async_aio(_session: aiohttp.ClientSession, _host: str) -> aiohttp.ClientResponse:
    logger: logging.Logger = logging.getLogger("pyeasycmd" + "." + "send_get_lang_async_aio")
    logger.debug("ENTER send_get_lang_async_aio")
    url: str = "https://" + _host + "/js/lang.js"
    logger.debug("async post")
    repl: aiohttp.ClientResponse = await _session.get(url=url, allow_redirects=True)
    logger.debug("##### async reply:")
    log_debug_raw_response(repl)
    logger.debug("EXIT send_get_lang_async_aio")
    return repl


async def get_routername_from_lang(_lang: str) -> str:
    logger.debug("ENTER get_routername_from_lang")
    logger.debug("cleanup lang / remove javascript code")
    lang_clear_repl: str = _lang.replace("var _DICTIONARY=", "", 1)
    logger.debug("cleanup lang / remove last semicolon")
    lang_clear: str = lang_clear_repl[:-1]
    logger.debug("convert to dict")
    lang_dic = ast.literal_eval(lang_clear)
    rn: str = lang_dic["PRODUCT_NAME_INFO"]["DEF"]
    logger.info("RETURNING: %s", rn)
    logger.debug("EXIT get_routername_from_lang")
    return rn


async def get_dm_cookie_async_aio(_session: aiohttp.ClientSession, _host: str) -> str:
    logger = logging.getLogger("pyeasycmd" + "." + "get_dm_cookie_async")
    logger.debug("ENTER get_dm_cookie_async_aio")
    resp = await send_emptyrequest_async_aio(_session, _host)
    logger.debug("got response: ")
    logger.debug(resp)
    res_tx = await resp.text()
    logger.debug("dm_cookie is the soap cookie used")
    reg_match: (re.Match[str] | None) = re.search("dm_cookie=\\'([\\w\\d]*)\\'", res_tx)
    if reg_match is not None:
        # regex result is in capturegroup 1
        cookie: str = reg_match[1]
        logger.info("Found SOAP(DM) Cookie: %s", cookie)
    else:
        cookie: str = "No cookie found"
        logger.error("No cookie found")
    logger.debug("EXIT get_dm_cookie_async_aio")
    return cookie


def get_dm_cookie(_session: requests.Session, _host: str) -> str:
    logging.debug("Enter get_dm_cookie")
    resp = send_emptyrequest(_session, _host)
    logging.debug("dm_cookie is the soap cookie used")
    a: re.Match[str] | None = re.search("dm_cookie=\\'([\w\d]*)\\'", resp.text)
    logging.debug("regex result is in capturegroup 1")
    if a is not None:
        cookie: str = a[1]
        logging.info("Found SOAP(DM) Cookie: " + cookie)
        return cookie
    else:
        return ""


async def send_get_property_async_aio(
    _property: str, _session: aiohttp.ClientSession, _dmcookie: str, _host: str
) -> aiohttp.ClientResponse:
    loggger = logging.getLogger("pyeasycmd" + "." + "send_get_property_async_aio")
    loggger.debug("Enter send_get_property_async_aio")
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
    soap_header.update({"SOAPAction": "cwmp:GetParameterValues", "SOAPServer": ""})

    req = _session.post(url=url_data_model, data=body_request, headers=soap_header)
    resp_body = await req

    log_debug_raw_response(resp_body)
    # resp_body.content.decode("utf-8")
    return resp_body


def send_get_property(_property: str, _session: requests.Session, _dmcookie: str, _host: str) -> requests.Response:
    loggger = logging.getLogger("pyeasycmd" + "." + "send_get_property")
    loggger.debug("Enter send_get_property")
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
    soap_header.update({"SOAPAction": "cwmp:GetParameterValues", "SOAPServer": ""})

    # print("Raw Request Body:")
    # print(body_request)
    # returns requests.models.Response.content
    resp_body: requests.Response = _session.post(url_data_model, data=body_request, headers=soap_header)

    log_debug_raw_response(resp_body)
    # resp_body.content.decode("utf-8")
    return resp_body


def get_authkey(_session: requests.Session, _host: str) -> str:
    logging.debug("Enter get_authkey")
    rsconfig = send_get_rsconfig(_session, _host)
    find_auth_key: re.Match[str] | None = re.search("var auth_key = '(\\d*)'", rsconfig.text)
    # take auth_key from capture group
    if find_auth_key is not None:
        _auth_key: str = find_auth_key[1]
        logging.debug("Found Authkey:")
        logging.debug(_auth_key)
        return _auth_key
    else:
        return ""


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
    str_hashed = hashlib.md5(str_to_hash.encode("utf-8")).hexdigest()

    soap = soap.replace("#cookie#", _val_dm_cookie)
    soap = soap.replace("#hashed_pwd#", str_hashed)

    soap_head = basic_header
    soap_head.update({"SOAPAction": "cwmp:Login", "SOAPServer": ""})
    url_data_model = "https://" + _host + "/data_model.cgi"

    logging.debug("session cookie before login")
    logging.debug(_session.cookies)
    repl: requests.Response = _session.post(url_data_model, data=soap, headers=soap_head)
    # TODO: check if response holds info of result (success/fail)

    logging.debug("reply of login")
    # print_raw_response(repl)

    logging.debug("new session cookie after login")
    logging.debug(_session.cookies)

    logging.debug("get new soap cookie after login (old is automatically expiring)")
    return get_dm_cookie(_session, _host)


async def get_single_value_async_aio(
    _property: str, _session: aiohttp.ClientSession, _dm_cookie: str, _host: str
) -> str | None:
    logger = logging.getLogger("pyeasycmd" + "." + "get_single_value_async_aio")
    logger.debug("get_single_value")
    res: aiohttp.ClientResponse = await send_get_property_async_aio(_property, _session, _dm_cookie, _host)
    recon: str = await res.text("utf-8")
    tree = ET.fromstring(recon)
    siva = tree.findtext("*//Value")
    if siva == None:
        logger.debug("no value received, returning error as value")
        siva = tree.findtext("*//FaultLang")
    else:
        # logging.debug("'", siva, "'")
        logger.debug("Got/Returning: " + siva)
    return siva


def get_single_value(_property: str, _session: requests.Session, _dm_cookie: str, _host: str) -> str | None:
    logger = logging.getLogger("pyeasycmd" + "." + "get_single_value")
    logger.debug("get_single_value")
    res: requests.Response = send_get_property(_property, _session, _dm_cookie, _host)
    recon: str = res.content.decode("utf-8")
    tree = ET.fromstring(recon)
    siva = tree.findtext("*//Value")
    if siva == None:
        logger.debug("no value received, returning error as value")
        siva = tree.findtext("*//FaultLang")
    else:
        # logging.debug("'", siva, "'")
        logger.debug("Got/Returning: " + siva)
    return siva


async def post_close_con_async_aio(_host: str, _session: aiohttp.ClientSession) -> None:
    logger = logging.getLogger("pyeasycmd" + "." + "post_close_con_async_aio")
    logger.debug("ENTER post_close_con_async_aio")
    logger.debug("Tell site to close connection")
    url = "https://" + _host + "/main.cgi?page=login.html"
    await _session.post(url=url, data="", headers={"Connection": "close"})
    logger.debug("Close Session")
    await _session.close()
    logger.debug("LEAVE post_close_con_async_aio")


def post_close_con(_host: str, _session: requests.Session) -> None:
    logging.debug("Enter post_close_con")
    logging.info("Closing Connection")
    url = "https://" + _host + "/main.cgi?page=login.html"
    _session.post(url=url, data="", headers={"Connection": "close"})


#################################################################################
#                            HANDLE XML
#################################################################################


def ParameterValueStruct_to_dict(_xmltree: ET.Element) -> dict[str, str]:
    """transform the tr069 ParameterValueStruct to dict"""
    kvp: dict[str, str] = {}
    for elem in _xmltree:
        if elem[0].text is not None:
            kvp[elem[0].text] = ""
            if elem[1].text is not None:
                kvp[elem[0].text] = elem[1].text
    return kvp


# Gets down xml levels by a specified list of keys
def GetLowerElement(_root: ET.Element, _level: list[str]) -> ET.Element | None:
    logging.debug("Enter GetLowerElement")
    res: ET.Element | None = _root
    for _lev in _level:
        if type(res):
            logging.debug("getting down to: " + _lev)
            if res is not None:
                res = res.find(_lev)
    return res


# interprets the xml response of a parametervaluestruct
def interpret_ParameterValueStruct(val: ET.Element) -> dict[str, str]:
    logging.debug("interpret_ParameterValueStruct")
    logging.debug("defining level to get down:")
    lvl: list[str] = [
        "{http://schemas.xmlsoap.org/soap/envelope/}Body",
        "{urn:dslforum-org:cwmp-1-0}GetParameterValuesResponse",
        "ParameterList",
    ]
    logging.debug(lvl)
    le = GetLowerElement(_root=val, _level=lvl)
    if le is not None:
        return ParameterValueStruct_to_dict(le)
    else:
        return {}


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
    logger: logging.Logger = logging.getLogger("pyeasycmd" + "." + "log_keyvalue")
    for key, val in keyval.items():
        logger.info(key + ": " + val)


def log_type(_var: Any, _varname: str):
    logging.debug("type of " + _varname + " is currently:")
    logging.debug(type(_var))


def log_debug_raw_response(resp: requests.Response | aiohttp.ClientResponse):
    logger = logging.getLogger("pyeasycmd" + "." + "log_debug_raw_response")
    logger.debug("Raw Cookie:")
    logger.debug(resp.cookies)
    logger.debug("Raw Header:")
    logger.debug(resp.headers)
    logger.debug("Raw Response")
    logger.debug(resp.text)


# TODO: check if type TextIOWrapper is better fitting
def write_keyvalue_csv(keyval: dict[str, str], filestream: Any):
    for key, val in keyval.items():
        logging.debug(key + ": " + val)
        filestream.write(key + ": " + val + "\n")
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
