DEFAULT_SYS_CONFIG_PATH: str = "./pyeasycmd_config.ini"
DEFAULT_USR_CONFIG_PATH: str = "#USERHOME#/.pyeasycmd_config.ini"

scr_passw: str | None = None
scr_ip_host: str | None = None
scr_router_pub_cert: str | bool | None = None

ERROR_MSG_CONFIG_PARSER_FAILED = "config parsing failed, variable not available"
ERROR_MSG_CONFIG_FILE_NOTFOUND = "config file not found"
