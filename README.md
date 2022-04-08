# pyeasycmd

Simple python tool for communicating with an easybox router

## WARNING - WORK IN PROGRESS

- **experimental**
- **use at your own risk**

## general info

- currently only unauthenticated requests are possible
- tested with vodafone easybox 804

## dev info

### work in progress

- authenticated requests are already working/tested but not yet activated as arguments
- more unauthenticated keys are beeing tested
- alternative export is already working/tested but not yet activated as arguments
- write boolean / change states / control easybox

### contribution

- suggestions welcome
- codereview welcome
- pull-requests welcome

## files and what they do

| File | Description |
| --- | ---|
| pyeasycmd.dockerfile | docker file if you dont want to install dependencies or run shielded |
| pyeasylib.py | lib file providing functions to the main executable |
| pyeasycmd.py | main executable - run this file |
| scr.example.py | Example secrets file |
| inputua.csv | Example file containing tested keys for unauthenticated requests |

## how to get started

### lets start with help

`python3 easystats.py -h`

### current output

```
usage: easystats.py [-h] [-i INPUTFILE] [-a [No-Value/True/False]] [-e EXPORTFILE] [-k [KEY ...]]

Get metadata from easybox

options:
  -h, --help            show this help message and exit
  -i INPUTFILE, --inputfile INPUTFILE
                        Path to textfile containing query keys seperated by newlines (csv without heading and comma).
  -a [No-Value/True/False], --authenticate [No-Value/True/False]
                        Use -a if authentication is required for router query, "scr.py" is used for loading the secrets. Either supply no value or a boolean.
  -e EXPORTFILE, --exportfile EXPORTFILE
                        File where the imported keys will be exported with values in flat json format.
  -k [KEY ...], --key [KEY ...]
                        The key to query, example: -k "InternetGatewayDevice.DeviceInfo.SoftwareVersion"

--key | --inputfile You are able to choose only one input method, either by file or by key
```

## example usage

### homeassistant - example sensor in `configuration.yaml`

```
sensor:
  - platform: file
    name: DSLUpstreamMaxRate
    file_path: /config/export/outputua.json
    value_template: "{{ value_json['InternetGatewayDevice.WANDevice.6.WANDSLInterfaceConfig.UpstreamMaxRate'] }}"
    unit_of_measurement: "kbit/s"
```
### create start script

example shell (linux) script:
`start_script.sh`
```
#!/bin/sh

echo "current time $(date)"
echo "script started at $(date)" >> /home/user/log/start_script.log

sleep 1

docker run \
	--rm \
	--mount type=bind,src=/home/user/scripts/pyeasycmd,dst=/scripts \
	pyeasycmd:latest \
	python3 /scripts/pyeasycmd.py --inputfile /scripts/inputua.csv --exportfile /scripts/outputua.json

sleep 3
echo copy file to folder where home assistant has access
cp --force /home/user/scripts/pyeasycmd/outputua.txt /home/user/homeass_config/export/outputua.json
```

### cron job runing the `start_script.sh`

use `crontab -e` to 'edit' the crontab file
once done, use `crontab -l` to see if the crontab has been added sucessfully
with `service cron status` check the current cron log
restart the cron service with `service cron restart` to enforce creating a log

example crontab entry to run the script hourly

`@hourly sh /home/user/scripts/start_script.sh`

(dont forget to chmod +x the script file)

### misc example scripts

```
# manually run - get information for one key
python3 /home/user/scripts/pyeasycmd.py -k "InternetGatewayDevice.DeviceInfo.SoftwareVersion"

# build the docker image - run one level up of the root folder "pyeasycmd"
docker build --tag pyeasycmd:latest --file ./pyeasycmd/pyeasycmd.dockerfile .

# for debug/dev: run bash inside the container
docker run -it --rm pyeasycmd:latest /bin/bash

# get information for one key using docker
docker run -it -e "cmd=-k InternetGatewayDevice.DeviceInfo.SoftwareVersion" --rm pyeasycmd:latest
```