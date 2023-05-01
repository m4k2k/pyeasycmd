import logging
import os

import aiohttp
from pyeasycmd.pyeasylib import (
    get_dm_cookie_async_aio,
    get_routername_from_lang,
    get_session_async_aio,
    get_single_value_async_aio,
    log_keyvalue,
    post_close_con_async_aio,
    send_get_lang_async_aio,
    parse_config,
    get_userconfig_path,
)
import pyeasycmd.const

LOG_LEVEL = logging.DEBUG
# LOG_LEVEL = logging.INFO
# LOG_LEVEL = logging.ERROR

logger = logging.getLogger("pyeasycmd.api")


async def get_routerName() -> str:
    if not pyeasycmd.const.configloaded:
        usrpath: str = get_userconfig_path()
        if os.path.isfile(usrpath):
            parse_config(usrpath)
    # TODO: put host/cert in function args, with default filling
    router_ip_host: str = pyeasycmd.const.scr_ip_host
    router_pub_cert = pyeasycmd.const.scr_router_pub_cert

    logger.debug("ENTER get_routername")
    logger.debug("get session")
    s: aiohttp.ClientSession = await get_session_async_aio(_verify=router_pub_cert)
    logger.debug("request lang file from %s", router_ip_host)
    cr: aiohttp.ClientResponse = await send_get_lang_async_aio(_session=s, _host=router_ip_host)
    logger.debug("transform to string")
    tx = await cr.text()
    logger.debug("close session/connection")
    await post_close_con_async_aio(router_ip_host, s)
    logger.debug("grep string - get router name")
    rn = await get_routername_from_lang(tx)

    logger.debug("return %s", rn)
    logger.debug("EXIT get_routername")
    return rn


async def get_multi_key_value(_inputkeys: list[str] = []) -> dict[str, str]:
    # TODO: Implement get_multi_key_value with authentication
    logger.debug("ENTER get_multi_key_value")
    router_ip_host: str = pyeasycmd.const.scr_ip_host
    router_pub_cert = pyeasycmd.const.scr_router_pub_cert

    logger.debug("checking if certificate file %s exists", router_pub_cert)
    if os.path.exists(router_pub_cert):
        logger.info("cert file found: %s", router_pub_cert)
    else:
        logger.error("cert file not found: %s", router_pub_cert)
    logger.debug("get session async")
    s = await get_session_async_aio(_verify=router_pub_cert)
    logger.debug("get soap cookie async")
    val_dm_cookie = await get_dm_cookie_async_aio(_session=s, _host=router_ip_host)
    logger.info("got the cookie: %s", val_dm_cookie)
    logger.debug("prepare keys for fetch")
    newkeys = {key: "" for key in _inputkeys}
    logger.debug("keys:")
    logger.debug(newkeys)

    # singe with multi?
    # function that checks reply
    # if single or array, then interpret
    logger.debug("fetch data")
    for key, val in newkeys.items():
        newkeys[key] = await get_single_value_async_aio(key, s, val_dm_cookie, router_ip_host)
    logger.info("got data:")
    log_keyvalue(newkeys)
    logger.info("closing connection and session")
    await post_close_con_async_aio(router_ip_host, s)
    logger.debug("EXIT function/eof get_multi_key_value")
    return newkeys
