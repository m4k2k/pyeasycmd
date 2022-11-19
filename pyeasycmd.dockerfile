FROM python:3.10-slim

ENV cmd=""

RUN python3 -m pip install requests
COPY ./ /scripts

WORKDIR /scripts
CMD python3 /scripts/pyeasycmd.py $cmd
