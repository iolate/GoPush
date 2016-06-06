GoPush
====

Simple asynchronous APNS / GCM service written in Go

License
--------

The MIT License

Download
--------
    $ go get github.com/iolate/GoPush

Usage
--------
    $ GoPush [OPTIONS]

##### Run Options

    --conf: Configuration JSON file path (required)
    --host: Listening IP (optional, default: 127.0.0.1)
    --port: Listening Port (optional, default: 5481)
    --logfile: Path to log file (optional, default: stdout)


Example
--------

#### Configuration Directory Tree

    /path/to/config
    ├── apns.pem
    ├── apns-dev.pem
    └── apps.json


#### Configuration JSON file (apps.json)

    {
        "myapp_ios": {"key": "apns.pem", "type": "apns"},
        "myapp_ios/sandbox": {"key": "apns-dev.pem", "type": "apns_sandbox"},
        "myapp_android": {"key": "GCM_API_KEY", "type": "gcm"}
    }


#### Start the service

    $ GoPush --conf /path/to/config/apps.json


#### Send messages (Python)

    import requests, json
    
    # iOS APNS
    payload = {'aps': {'alert': 'Push Test', 'sound': 'default'}}
    data = {'app': 'myapp_ios', 'token': '<DEVICE_TOKEN>', 'payload': json.dumps(payload)}
    requests.get('http://127.0.0.1:5481/send', data=data)
    
    # Android GCM
    payload = {'title': 'GoPush', 'message': 'Push Test'}
    data = {'app': 'myapp_android', 'token': '<DEVICE_TOKEN>', 'payload': json.dumps(payload)}
    requests.get('http://127.0.0.1:5481/send', data=data)


Daemonize
--------
#### Ubuntu 14.04

##### Copy daemon script
    $ sudo cp $GOPATH/bin/GoPush /usr/bin/GoPush
    $ sudo cp $GOPATH/src/github.com/iolate/GoPush/gopushd /etc/init.d/gopushd
    $ sudo chmod +x /etc/init.d/gopushd

##### Create config directory and json

    $ sudo mkdir /etc/gopush
    $ sudo vi /etc/gopush/apps.json
        ...

or modify default path...

    $ sudo vi /etc/init.d/gopushd
        ...
        DAEMON_ARGS="--conf /etc/gopush/apps.json" # <- Modify here!
        ...

##### Start daemon

    $ sudo update-rc.d gopushd defaults
    $ sudo service gopushd start

