# import libraries
import logging
from scr import scr_ip_host, scr_passw, scr_router_pub_cert
from pyeasylib import *
from datetime import datetime
import argparse
import requests


LOG_LEVEL = logging.ERROR
LOG_LEVEL = logging.DEBUG

# logging.basicConfig(filename='example.log', encoding='utf-8', level=logging.DEBUG)
logging.basicConfig(encoding='utf-8', level=LOG_LEVEL,
                    format='%(levelname)s:%(asctime)s %(message)s')

logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Disable HTTP Error 302 "Resetting dropped connection" beeing logged
# logging.getLogger("requests.packages.urllib3.connectionpool").setLevel(logging.WARNING)

logging.info("easycmd started")

secrets_file = "scr.py"
logging.debug("secrets_file: " + secrets_file)
logging.debug("if required to change - remind the import statement")

additional_info_helptext = """
--key | --inputfile     You are able to choose only one input method, either by file or by key
"""

parser = argparse.ArgumentParser(
    description='Get metadata from easybox', epilog=additional_info_helptext)

parser.add_argument('-i', '--inputfile', type=argparse.FileType('r'),
                    help='Path to textfile containing query keys seperated by newlines (csv without heading and comma).')
parser.add_argument('-a', '--authenticate', default=False, type=bool, const=True, nargs='?', metavar="No-Value/True/False",
                    help='Use -a if authentication is required for router query, "' + secrets_file + '" is used for loading the secrets. Either supply no value or a boolean.')
parser.add_argument('-e', '--exportfile', type=argparse.FileType('w'),
                    help='File where the imported keys will be exported with values in flat json format.')
# parser.add_argument('-e', '--exportfile', type=argparse.FileType('w'),
#                     help='File where the imported keys will be exported with values as csv, seperated by newlines and semicolon.')
parser.add_argument('-k', '--key', type=str, nargs='*',
                    help='The key to query, example: -k "InternetGatewayDevice.DeviceInfo.SoftwareVersion"')
parser.add_argument('-m', '--multikey', type=str, nargs='*',
                    help='A key to query with an array as a result, example: -m "InternetGatewayDevice.WANDevice.6.WANConnectionDevice.4.WANIPConnection.1.PortMapping."')

logging.debug("Checking for Args..")
args = parser.parse_args()
logging.debug("Found Args:")
logging.debug(args)
logging.debug(
    "Checking for argument combination --inputfile and --key - throw error if found")
if((args.key) and (args.inputfile)):
    parser.error("Combination of --inputfile and --key detected" +
                 additional_info_helptext)


def get_print_unauth():

    logging.debug("Entering get_print_unauth")

    unauth_host = {
        "InternetGatewayDevice.LANDevice.1.Hosts.": "",
        "InternetGatewayDevice.LANDevice.1.Hosts.Host.": ""
    }

    # CSV according to RFC 4180
    # single property keys which are working unauthenticated
    unauth_sp = {
        "InternetGatewayDevice.DeviceInfo.SoftwareVersion": "",
        "InternetGatewayDevice.LANDevice.1.Hosts.HostNumberOfEntries": "",
        "InternetGatewayDevice.WANDevice.6.WANConnectionDevice.4.WANPPPConnection.1.ExternalIPAddress": "",
        "InternetGatewayDevice.WANDevice.6.WANDSLInterfaceConfig.Stats.Total.ReceiveBlocks": "",
        "InternetGatewayDevice.WANDevice.6.WANDSLInterfaceConfig.Stats.Total.TransmitBlocks": "",
        "InternetGatewayDevice.WANDevice.6.WANDSLInterfaceConfig.Status": "",
        "InternetGatewayDevice.WANDevice.6.WANDSLInterfaceConfig.DataPath": "",
        "InternetGatewayDevice.WANDevice.6.WANDSLInterfaceConfig.UpstreamCurrRate": "",
        "InternetGatewayDevice.WANDevice.6.WANDSLInterfaceConfig.DownstreamCurrRate": "",
        "InternetGatewayDevice.WANDevice.6.WANDSLInterfaceConfig.UpstreamMaxRate": "",
        "InternetGatewayDevice.WANDevice.6.WANDSLInterfaceConfig.DownstreamMaxRate": ""
    }

    for key, val in unauth_sp.items():
        unauth_sp[key] = get_single_value(
            key, s, val_dm_cookie, router_ip_host)

    for key, val in unauth_sp.items():
        logging.debug("%s: %s", key, val)


def get_print_auth(_val_dm_cookie):

    # only authenticated
    auth_sp = {
        "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.Status": "",
        "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID": "",
        "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.TotalAssociations": "",
        "InternetGatewayDevice.LANDevice.2.WLANConfiguration.1.SSID": "",
        "InternetGatewayDevice.LANDevice.1.LANWLANConfigurationNumberOfEntries": "",
        "InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DNSServers": "",
        "InternetGatewayDevice.WANDevice.6.WANConnectionDevice.4.WANPPPConnection.1.DNSServers": "",
        "InternetGatewayDevice.WANDevice.6.WANConnectionDevice.4.WANPPPConnection.1.PortMappingNumberOfEntries": "",
        "InternetGatewayDevice.WANDevice.6.WANConnectionDevice.4.WANPPPConnection.1.PortMapping.": ""
    }

    auth_sp = {
        "InternetGatewayDevice.WANDevice.6.WANConnectionDevice.4.WANPPPConnection.1.PortMappingNumberOfEntries": "",
        "InternetGatewayDevice.WANDevice.6.WANConnectionDevice.4.WANPPPConnection.1.PortMapping.": "",
        "InternetGatewayDevice.WANDevice.6.WANConnectionDevice.4.WANIPConnection.1.PortMapping.": ""
    }

    # get authenticated soap login cookie (overwrite existing)
    # logging.debug("Current val_dm_cookie: " + val_dm_cookie)
    val_dm_cookie = get_login_cookie(s, passw, router_ip_host, _val_dm_cookie)

    for key, val in auth_sp.items():
        auth_sp[key] = get_single_value(key, s, val_dm_cookie, router_ip_host)

    log_key_value(auth_sp)

if __name__ == '__main__':

    # import secrets
    passw = scr_passw
    router_ip_host = scr_ip_host
    router_pub_cert = scr_router_pub_cert

    # setup session and handle exit
    with get_session(_verify=router_pub_cert) as s:

        # get soap cookie, session cookie is stored in session
        val_dm_cookie = get_dm_cookie(_session=s, _host=router_ip_host)

        if(args.multikey):
            logging.debug("multikey arg provided")
            logging.debug(args.multikey)
            # TODO: next -> get Multi Value Response (and understand it, see log ports)
            # do auth
            val_dm_cookie = get_login_cookie(s, passw, router_ip_host, val_dm_cookie)
            resp2: requests.models.Response.content = send_get_property(
                args.multikey[0], s, val_dm_cookie, router_ip_host)
            # woanders auch direkt als root bezeichnet
            tree = ET.fromstring(resp2.content)
            log_debug_tree(tree)
            res = interpret_ParameterValueStruct(tree)
            logging.debug("returning dict:")
            log_key_value(res)
            #! alternate solution required, duplicate export code!
            if(args.exportfile):
                write_keyvalue_json(res, args.exportfile)

        if(args.key):
            logging.debug("key arg provided")
            logging.debug(args.key)
            newkeys = {key: "" for key in args.key}
            logging.debug(newkeys)

            # singe with multi?
            # function that checks reply
            # if single or array, then interpret
            for key, val in newkeys.items():
                newkeys[key] = get_single_value(
                    key, s, val_dm_cookie, router_ip_host)

            log_keyvalue(newkeys)
            # write_keyvalue_csv(newkeys, args.exportfile)
            if(args.exportfile):
                write_keyvalue_json(newkeys, args.exportfile)

        if(args.inputfile):
            logging.debug("inputfile arg provided")
            str_readdata = args.inputfile.read()
            logging.debug(str_readdata)
            logging.debug("check file")
            ary_readdata = str_readdata.split()
            logging.debug(ary_readdata)

            newkeys = {key: "" for key in ary_readdata}
            logging.debug(newkeys)

            for key, val in newkeys.items():
                newkeys[key] = get_single_value(
                    key, s, val_dm_cookie, router_ip_host)

            log_keyvalue(newkeys)
            # write_keyvalue_csv(newkeys, args.exportfile)
            if(args.exportfile):
                write_keyvalue_json(newkeys, args.exportfile)

        # get_print_unauth()
        # get_print_auth(val_dm_cookie)

        post_close_con(router_ip_host, s)
        logging.debug("app exit/eof")
