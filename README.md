# OCPP transport extension for libafb

AFB micro-service framework extension for OCPP 1.6 + 2.0.1

## Usage

```bash
afb-binder --name=ocpp-client --verbose \
   --extension=package/lib/libafb-ocpp-ext.so \
   --ocpp-client=csms-host:9310/ws/Tux-Basic \
   --ocpp-pwd-base64=VHV4LUJhc2ljOnNub29weQ==  #pwd=snoopy
```

## Dependencies

* afb micro-service development rpm. <https://docs.redpesk.bzh/docs/en/master/getting_started/host-configuration/docs/1-Setup-your-build-host.html>
* occp/csms server to connect. <https://github.com/tux-evse/ocpp-csms>

## Build from source

```bash
mkdir build
cd build
cmake ..
make
```
