# import libraries
import argparse
import asyncio
import logging
import xml.etree.ElementTree as ET

import requests
from pyeasycmd.api import get_routerName
from pyeasycmd.pyeasylib import (
    get_dm_cookie,
    get_login_cookie,
    get_session,
    get_single_value,
    interpret_ParameterValueStruct,
    log_debug_tree,
    log_keyvalue,
    post_close_con,
    send_get_property,
    write_keyvalue_json,
)
from pyeasycmd.scr import scr_ip_host, scr_passw, scr_router_pub_cert

# LOG_LEVEL = logging.DEBUG
LOG_LEVEL = logging.INFO
# LOG_LEVEL = logging.ERROR

# logging.basicConfig(filename='example.log', encoding='utf-8', level=logging.DEBUG)
logging.basicConfig(encoding="utf-8", level=LOG_LEVEL, format="%(levelname)s:%(asctime)s %(message)s")

logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

logger = logging.getLogger("pyeasycmd")

# Disable HTTP Error 302 "Resetting dropped connection" beeing logged
# logging.getLogger("requests.packages.urllib3.connectionpool").setLevel(logging.WARNING)

logger.info("easycmd started")

secrets_file = "scr.py"
logger.debug("secrets_file: %s", secrets_file)
logger.debug("if required to change - remind the import statement")


def main():
    # TODO: Convert main to async
    additional_info_helptext = """
    --key | --inputfile     You are able to choose only one input method, either by file or by key
    """

    parser = argparse.ArgumentParser(description="Get metadata from EasyBox", epilog=additional_info_helptext)

    parser.add_argument(
        "-i",
        "--inputfile",
        type=argparse.FileType("r"),
        help="Path to textfile containing query keys separated by newlines (csv without heading and comma).",
    )
    parser.add_argument(
        "-a",
        "--authenticate",
        action="store_true",
        help='Use -a if authentication is required for router query, "'
        + secrets_file
        + '" is used for loading the secrets. Either supply no value or a boolean.',
    )
    parser.add_argument(
        "-e",
        "--exportfile",
        type=argparse.FileType("w"),
        help="File where the imported keys will be exported with values in flat json format.",
    )
    parser.add_argument("-rn", "--router_name", action="store_true", help="Get router name")
    parser.add_argument(
        "-k",
        "--key",
        type=str,
        nargs="*",
        help='The key to query, example: -k "InternetGatewayDevice.DeviceInfo.SoftwareVersion"',
    )
    parser.add_argument(
        "-m",
        "--multikey",
        type=str,
        nargs="*",
        help='A key to query with an array as a result, example: -m "InternetGatewayDevice.WANDevice.6.WANConnectionDevice.4.WANIPConnection.1.PortMapping."',
    )
    parser.add_argument("-config", "--config", type=str, nargs="*", help="???")
    logger.debug("Checking for Args..")
    args = parser.parse_args()
    logger.debug("Found Args:")
    logger.debug(args)
    logger.debug("Checking for argument combination --inputfile and --key - throw error if found")
    if (args.key) and (args.inputfile):
        parser.error("Combination of --inputfile and --key detected" + additional_info_helptext)

    logger.debug("Checking if we know what to do (if any argument is provided)")
    if args.router_name is False and args.inputfile is None and args.key is None and args.multikey is None:
        # (inputfile=None, authenticate=False, exportfile=None, router_name=False, key=None, multikey=None, config=None)
        parser.error("No argument passed, please provide an argument, try --help to get help")

    # import secrets
    passw: str = scr_passw
    router_ip_host: str = scr_ip_host
    router_pub_cert = scr_router_pub_cert

    # setup session and handle exit
    with get_session(_verify=router_pub_cert) as s:
        # get soap cookie, session cookie is stored in session
        val_dm_cookie = get_dm_cookie(_session=s, _host=router_ip_host)
        if args.authenticate:
            val_dm_cookie = get_login_cookie(s, passw, router_ip_host, val_dm_cookie)

        if args.multikey:
            logger.debug("multikey arg provided")
            logger.debug(args.multikey)
            # TODO: next -> get Multi Value Response (and understand it, see log ports)
            resp2: requests.models.Response = send_get_property(args.multikey[0], s, val_dm_cookie, router_ip_host)
            # woanders auch direkt als root bezeichnet
            tree: ET.ElementTree = ET.fromstring(resp2.content)
            log_debug_tree(tree)
            res = interpret_ParameterValueStruct(tree)
            logger.debug("returning dict:")
            log_keyvalue(res)
            #! alternate solution required, duplicate export code!
            if args.exportfile:
                write_keyvalue_json(res, args.exportfile)

        if args.key:
            logger.debug("key arg provided")
            logger.debug(args.key)
            newkeys = {key: "" for key in args.key}
            logger.debug(newkeys)

            # singe with multi?
            # function that checks reply
            # if single or array, then interpret
            for key, val in newkeys.items():
                newkeys[key] = get_single_value(key, s, val_dm_cookie, router_ip_host)

            log_keyvalue(newkeys)
            # write_keyvalue_csv(newkeys, args.exportfile)
            if args.exportfile:
                write_keyvalue_json(newkeys, args.exportfile)

        if args.inputfile:
            logger.debug("inputfile arg provided")
            str_readdata = args.inputfile.read()
            logger.debug(str_readdata)
            logger.debug("check file")
            ary_readdata = str_readdata.split()
            logger.debug(ary_readdata)

            newkeys = {key: "" for key in ary_readdata}
            logger.debug(newkeys)

            # if (args.authenticate):
            #     val_dm_cookie = get_login_cookie(s, passw, router_ip_host, val_dm_cookie)

            for key, val in newkeys.items():
                newkeys[key] = get_single_value(key, s, val_dm_cookie, router_ip_host)

            log_keyvalue(newkeys)
            # write_keyvalue_csv(newkeys, args.exportfile)
            if args.exportfile:
                write_keyvalue_json(newkeys, args.exportfile)

        if args.router_name:
            logger.warning("router_name arg provided")
            loop = asyncio.get_event_loop()
            rou = loop.run_until_complete(get_routerName())
            logger.warning("routername: %s", rou)

        post_close_con(router_ip_host, s)
        logger.debug("app exit/eof")


if __name__ == "__main__":
    # TODO: Run main async
    main()