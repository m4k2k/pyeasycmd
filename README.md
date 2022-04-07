# pyeasycmd

Simple python tool for communicating with an easybox router

## WARNING - WORK IN PROGRESS

- **experimental**
- **use at your own risk**

## general info

- currently only unauthenticated requests are possible
- tested with easybox 804

## dev info

- authenticated requests are already working/tested but not yet activated as arguments
- more unauthenticated keys are beeing tested

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
