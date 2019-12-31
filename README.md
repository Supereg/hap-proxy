# hap-proxy

`hap-proxy` is a transparent proxy for the HomeKit Accessory Protocol (HAP).
On the one hand it acts as an HomeKit accessory and exposes and HAP server (to which you would connect to)
and on the other hand it acts as an HomeKit controller to an existing HomeKit accessory.
`hap-proxy` is compliant with hap v1.1.0 and _will_ also support proxying HomeKit Data Streams (v1.0).

`hap-proxy` is currently work in progress and definitely not finished.
Currently the ambition of the project is to have an hap proxy which can be used for research and reverse engineering.
The goal is that  `hap-proxy` outputs the communication made between the HomeKit controller (iOS device etc) and the
proxied accessory in an format like pcap.

If there is interest I could imagine adding functionality which could be helpful to more people.
For example features like integrating one HomeKit accessory into multiple HomeKit homes or adding some kind of
plugin based filtering, which could be used to alter behaviour of certified HomeKit accessories or adding custom
capabilities programmatically to certified HomeKit accessories.
Hit me up if you are interested or have any additional ideas.

## Installation

```
npm install -g hap-proxy
```

## API

Once I reached a point where the API can be considered stable I'm gonna update this section.

## Notes

This project is heavily inspired by the code base of [HAP-NodeJS](https://github.com/KhaosT/HAP-NodeJS)
(most of the encryption and decryption layers) and [hap-client](https://github.com/forty2/hap-client).
