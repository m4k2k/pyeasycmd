FROM python:3.10-slim

ENV cmd=""

RUN python3 -m pip install requests
COPY ./pyeasycmd /scripts

WORKDIR /scripts
CMD python3 /scripts/pyeasycmd.py $cmd

# manually run
# python3 /scripts/pyeasycmd.py -k "InternetGatewayDevice.DeviceInfo.SoftwareVersion"

# run one level up of the root folder "pyeasycmd"
# docker build --tag pyeasycmd:latest --file ./pyeasycmd/pyeasycmd.dockerfile .

# for debug/dev: run bash inside the container
# docker run -it --rm pyeasycmd:latest /bin/bash

# get information for one key
# docker run -it -e "cmd=-k InternetGatewayDevice.DeviceInfo.SoftwareVersion" --rm pyeasycmd:latest
