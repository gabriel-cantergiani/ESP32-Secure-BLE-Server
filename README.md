# ESP32-Secure-BLE-Server
Implementation of a Bluetooth Low Energy (BLE) Security Protocol for ESP32 or Arduino Devices.

## Description
This project is an implementation of the EdgeSec Security Protocol [https://ieeexplore.ieee.org/document/8241993] on Smart Objects (IoT devices and sensors).

EdgeSec is a security architecture designed as an extension of ContextNet, an Internet of Mobile Things (IoMT) middleware solution created at PUC-Rio [http://wiki.lac.inf.puc-rio.br/doku.php].
It provides authentication, authorization and encryption features to all parts of communication between processing servers in a cloud, smart objects generating sensor data and mobile devices working as a bridge between the two.

This project focuses on the Smart Object part, implementing the authentication and encryption processes in ESP32 or Arduino Devices with BLE capabilities. It has no commercial purposes, and it uses other public projects for the implementation of MD5 hashing algorithms and RC4 encryption algorithms, with some changes and adaptions, as listed below:

* MD5 Hashing Library: 2014,2015 Stephan Brumme, [https://create.stephan-brumme.com/hash-library/], [https://github.com/stbrumme/hash-library].

* Other MD5 Hashing Library: [http://spaniakos.github.io/ArduinoMD5/], [https://github.com/spaniakos/ArduinoMD5]

* RC4 encryption Library: Espressif Arduino ESP32 mbedtls: [https://github.com/espressif/arduino-esp32/blob/master/tools/sdk/include/mbedtls/mbedtls/arc4.h]


For more information on ContextNet, EdgeSec or the goal of this project, please visit http://wiki.lac.inf.puc-rio.br/doku.php.


