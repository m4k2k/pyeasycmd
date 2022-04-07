# pyeasycmd

Simple python tool for communicating with an easybox router

## general info

* currently only unauthenticated requests are possible
* tested with easybox 804

## dev info

* authenticated requests are already working/tested but not yet activated as arguments
* more unauthenticated keys are beeing tested

## files and what they do

| File | Description |
| --- | ---|
| easycmd.dockerfile | docker file if you dont want to install dependencies or run shielded |
| easyrequestlib.py | lib file providing functions to the main executable |
| easystats.py | main executable - run this file |
| scr.example.py | Example secrets file |
| inputua.csv | Example file containing tested keys for unauthenticated requests |
