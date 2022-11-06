# hap-proxy

`hap-proxy` is a transparent proxy for the HomeKit Accessory Protocol (HAP).
On the one hand it acts as an HomeKit accessory and exposes and HAP server (to which you would connect to)
and on the other hand it acts as an HomeKit controller to an existing HomeKit accessory.
`hap-proxy` is compliant with hap v1.1.0 meaning it is also capable of proxying HomeKit Data Streams (v1.0) used for
HomeKit Remotes and Secure Video.

`hap-proxy` is currently work in progress and definitely not finished.
Currently, the ambition of the project is to have a hap proxy which can be used for research and reverse engineering.
The goal is that  `hap-proxy` outputs the communication made between the HomeKit controller (iOS device etc.) and the
proxied accessory in a format like pcap.

If there is interest I could imagine adding functionality which could be helpful to more people.
For example features like integrating one HomeKit accessory into multiple HomeKit homes or adding some kind of
plugin based filtering, which could be used to alter behaviour of certified HomeKit accessories or adding custom
capabilities programmatically to certified HomeKit accessories.
Hit me up if you are interested or have any additional ideas.

## Installation

```
sudo npm install -g hap-proxy
```

## Command Line

When installing `hap-proxy` globally the command-line program `hap-proxy` will be added to your system.  
Running `hap-proxy -h` will display the following help menu:
```
Usage: hap-proxy [options]

Options:
  -V, --version                      output the version number
  -p, --port <port>                  define the proxy port (default: 60141)
  -t, --target-name <instance name>  define the instance name of the device which should be proxied
  -c, --target-pincode <pincode>     define the pincode with dashes of the homekit device to be proxied
  --proxy-pincode <pincode>          define a separate pincode for the proxy server
  --hostname <hostname>              define an overwrite for the hostname of the target device. By default the hostname is learned from mDNS service discovery
  -h, --help                         display help for command
```

When you want to proxy an existing homekit device you must first ensure that the device is unpaired and added to you Wi-Fi.

In order to start up a basic proxy you must supply `--target-name` and `--target-pincode`.  
The first name give the **Instance Name** of the accessory. The easiest way to get that is to open the Home App,
open the pairing menu and copy the name of the desired accessory.

The target pincode is the pincode of the HomeKit accessory. If `--proxy-pincode` is not defined the proxy server
will use the same pincode.

## API

Once I reached a point where the API can be considered stable I'm going to update this section.

## Notes

This project is heavily inspired by the code base of [HAP-NodeJS](https://github.com/homebridge/HAP-NodeJS)
(most of the encryption and decryption layers) and [hap-client](https://github.com/forty2/hap-client).
