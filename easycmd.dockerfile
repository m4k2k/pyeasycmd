FROM python:3.10-slim

ENV cmd=""

RUN python3 -m pip install requests
COPY ./pyeasycmd /scripts

WORKDIR /scripts
CMD python3 /scripts/easystats.py $cmd

# manually run
# python3 /scripts/easystats.py -k "InternetGatewayDevice.DeviceInfo.SoftwareVersion"

# run one level up of "pyeasymeta"
# docker build --tag easymeta:latest --file ./pyeasycmd/easymeta.dockerfile .

# for debug/dev: run bash inside the container
# docker run -it --rm easymeta:latest /bin/bash

# get information for one key
# docker run -it -e "cmd=-k InternetGatewayDevice.DeviceInfo.SoftwareVersion" --rm easymeta:latest
