# ESP32-Secure-BLE-Server
Implementation of a Bluetooth Low Energy (BLE) Security Protocol for ESP32 or Arduino Devices.

## Description
This project is an implementation of the EdgeSec Security Protocol [https://ieeexplore.ieee.org/document/8241993] on Smart Objects (IoT devices and sensors).

EdgeSec is a security architecture designed as an extension of ContextNet, an Internet of Mobile Things (IoMT) middleware solution created at PUC-Rio [http://wiki.lac.inf.puc-rio.br/doku.php].
It provides authentication, authorization and encryption features to all parts of communication between processing servers in a cloud, smart objects generating sensor data and mobile devices working as a bridge between the two.

This project focuses on the Smart Object part, implementing the authentication and encryption processes in ESP32 or Arduino Devices with BLE capabilities. For more information on ContextNet, EdgeSec or the goal of this project, please visit http://wiki.lac.inf.puc-rio.br/doku.php.
