/*
 *   BLE_SERVER:
 *   This module implements the Bluetooth Low Energy Server, including the callbacks for when a Characteristic is read and write.
 *
 *   Created by: Gabriel Cantergiani, February 2023
 */

#include <BLEDevice.h>
#include <BLEDescriptor.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <string.h>

// Defining Security Service and Characteristics
#define SECURITY_SERVICE_UUID "dc33e26c-a82e-4fea-82ab-daa5dfac3dd3"
#define HANDSHAKE_RESPONSE_UUID "65d89516-59fd-453b-91a7-861982bbd8eb"
#define HANDSHAKE_HELLO_UUID "2c093c70-8b7c-4398-bda1-8340dfd50bae"
#define HANDSHAKE_FINISH_UUID "67d13516-22fd-346b-93a7-861982bbd8ea"
#define SEND_HELLO_MESSAGE_UUID "35875610-380a-4cfb-aa9e-6efcea4803ea"
#define READ_HELLO_MESSAGE_UUID "8b81383b-1136-4df2-85a4-dd29a7a4e81b"
#define READ_DATA_UUID "f86db954-a0d0-4d99-b27f-bb8d42585e97"
#define WRITE_DATA_UUID "2cb4b710-9ec7-47bf-bfc7-ad9341a0773e"
#define DESCRIPTOR_UUID "8e1251d2-bba7-47d7-904e-fcea2ab50953"

// Defining variables
extern bool isConnected;
extern bool isAuthenticated;

BLECharacteristic *pCharacteristic_HANDSHAKE_RESPONSE;
BLECharacteristic *pCharacteristic_HANDSHAKE_HELLO;
BLECharacteristic *pCharacteristic_SEND_HELLO_MESSAGE;
BLECharacteristic *pCharacteristic_READ_HELLO_MESSAGE;
BLECharacteristic *pCharacteristic_READ_DATA;
BLECharacteristic *pCharacteristic_WRITE_DATA;
BLEServer *pServer;

// Current sensor Data
std::string data = "data";
int data_length = 4;

// Device edgesec ID
std::string DEVICE_ID = "ID_DEVICE0";

// Defining Callback functions

class ServerCallbacks : public BLEServerCallbacks
{
    void onConnect(BLEServer *pServer)
    {
        isConnected = true;
        Serial.println(">> [BLE_SERVER] Device Connected!");

        // Stop Advertising
        pServer->getAdvertising()->stop();

        // Create Mobile Hub Object
        createMobileHub();
    }

    void onDisconnect(BLEServer *pServer)
    {
        isConnected = false;
        Serial.println(">> [BLE_SERVER] Device Disconnected!");

        // Remove connectedHub
        removeConnectedHub();

        // Start advertising again
        pServer->getAdvertising()->start();
        Serial.println(">> [BLE_SERVER] Restarted Advertising. Listening for connection...");
    }
};

class CharacteristicCallbacks : public BLECharacteristicCallbacks
{

    // When a write request arrives
    void onWrite(BLECharacteristic *pCharacteristic)
    {
        Serial.print(">> [BLE_SERVER] Characteristic onWrite: ");
        Serial.println(pCharacteristic->getUUID().toString().c_str());

        // SET_MAC -> Stores Hub Mac Address in MobileHub Object
        if (pCharacteristic->getUUID().toString() == HANDSHAKE_HELLO_UUID)
        {
            std::string data = pCharacteristic->getValue();
            std::string version = data.substr(0, 3);
            std::string HubID = data.substr(3);
            
            // std::string HubID = pCharacteristic->getValue();
            Serial.print(">>> [BLE_SERVER] [SET_MAC] Hub ID received: ");
            Serial.println(HubID.c_str());
            setHubID(HubID);
        }
        // AUTH_WRITE -> Receives Authentication Package, in 3 parts
        else if (pCharacteristic->getUUID().toString() == SEND_HELLO_MESSAGE_UUID)
        {
            if (isHubAuthenticated())
            {
                Serial.println(">>> [BLE_SERVER] [AUTH_WRITE] Device already authenticated!");
                return;
            }

            if (!isReceivingHelloMessage()){
              setIsReceivingHelloMessage(true);
            }

            Serial.print(">>>> [BLE_SERVER] [AUTH_WRITE] Copying packet value. In State: ");
            Serial.println(getHubState());

            // Get characteristic value
            std::string data = pCharacteristic->getValue();

            copyPacketToHub(data.c_str(), 20);
        }
    }

    // When a read request arrives
    void onRead(BLECharacteristic *pCharacteristic)
    {
        Serial.print(">> [BLE_SERVER] Characteristic onRead: ");
        Serial.println(pCharacteristic->getUUID().toString().c_str());

        // GET_MAC -> Sends the MacAddress of this device to the Mobile Hub
        if (pCharacteristic->getUUID().toString() == HANDSHAKE_RESPONSE_UUID)
        {
            // std::string macAddress = BLEDevice::getAddress().toString();
            Serial.print(">>> [BLE_SERVER] [GET_MAC] Sending device ID: ");
            Serial.println(DEVICE_ID.c_str());

            pCharacteristic->setValue(DEVICE_ID);
            pCharacteristic->notify();
            Serial.println(">>> [BLE_SERVER] [GET_MAC] Device ID sent!");
        }
        // GET_HELLO -> Sends AcceptedHelloMessage to Mobile Hub after authentication is complete
        else if (pCharacteristic->getUUID().toString() == READ_HELLO_MESSAGE_UUID)
        {
            if (isReceivingHelloMessage()){
              setIsReceivingHelloMessage(false);

              Serial.println(">>>> [BLE_SERVER] [AUTH_WRITE] Authentication Pack is complete! Starting to check Authentication...");

              bool auth_result = checkAuthentication((char *)DEVICE_ID.c_str());

              // If authentication fails, disconnects and starts listenning for new connections again
              if (!auth_result)
              {
                  Serial.println(">>>> [BLE_SERVER] Authentication failed.");
                  removeConnectedHub();
                  pServer->disconnect(pServer->getConnId());
                  return;
                }

              // Set as authenticated
              isAuthenticated = true;
              Serial.println(">> [BLE_SERVER] Device Authenticated!");
            }
          
            if (!isHubAuthenticated())
            {
                Serial.println(">>> [BLE_SERVER] [GET_HELLO] Unauthenticated Mobile Hub trying to read Accepted Hello Message.");
                return;
            }

            Serial.println(">>> [BLE_SERVER] [GET_HELLO] Sendind Accepted Hello Message to Authenticated MHub.");

            pCharacteristic->setValue((uint8_t *)getHubAcceptedMessage(), 16);
            pCharacteristic->notify();
            Serial.println(">>> [BLE_SERVER] [GET_HELLO] Accepted Hello Message sent!");
        }
        // READ -> Sends this device sensor data securely, encrypted with Ksession
        else if( pCharacteristic->getUUID().toString() == READ_DATA_UUID && isAuthenticated){

            char * secureMessage = generateSecureMessage(data, data_length);
            Serial.print(">>> [BLE_SERVER] [READ] Sending (encrypted) data: ");
            Serial.println(data.c_str());


            pCharacteristic->setValue( (uint8_t *) secureMessage, 20);
            pCharacteristic->notify();
            Serial.println(">>> [BLE_SERVER] [READ] Encrypted Data sent!");

        }
    }
};

// Initialize BLE Server, Service and Characteristics

void initializeServer()
{
    isConnected = false;

    // Create device
    BLEDevice::init("BLE_Server");

    // Configure Device as a Server
    pServer = BLEDevice::createServer();
    pServer->setCallbacks(new ServerCallbacks());

    // Create Security Service
    BLEService *pService = pServer->createService(SECURITY_SERVICE_UUID);

    // Create all characteristic
    pCharacteristic_HANDSHAKE_RESPONSE = pService->createCharacteristic(HANDSHAKE_RESPONSE_UUID, BLECharacteristic::PROPERTY_READ);
    pCharacteristic_HANDSHAKE_HELLO = pService->createCharacteristic(HANDSHAKE_HELLO_UUID, BLECharacteristic::PROPERTY_WRITE);
    pCharacteristic_SEND_HELLO_MESSAGE = pService->createCharacteristic(SEND_HELLO_MESSAGE_UUID, BLECharacteristic::PROPERTY_WRITE);
    pCharacteristic_READ_HELLO_MESSAGE = pService->createCharacteristic(READ_HELLO_MESSAGE_UUID, BLECharacteristic::PROPERTY_READ);
    pCharacteristic_READ_DATA = pService->createCharacteristic(READ_DATA_UUID, BLECharacteristic::PROPERTY_READ);
    pCharacteristic_WRITE_DATA = pService->createCharacteristic(WRITE_DATA_UUID, BLECharacteristic::PROPERTY_WRITE);

    // Set callback functions to all characteritics
    pCharacteristic_HANDSHAKE_RESPONSE->setCallbacks(new CharacteristicCallbacks());
    pCharacteristic_HANDSHAKE_HELLO->setCallbacks(new CharacteristicCallbacks());
    pCharacteristic_SEND_HELLO_MESSAGE->setCallbacks(new CharacteristicCallbacks());
    pCharacteristic_READ_HELLO_MESSAGE->setCallbacks(new CharacteristicCallbacks());
    pCharacteristic_READ_DATA->setCallbacks(new CharacteristicCallbacks());
    pCharacteristic_WRITE_DATA->setCallbacks(new CharacteristicCallbacks());

    // Set Descriptors to all characteristics
    pCharacteristic_HANDSHAKE_RESPONSE->addDescriptor(new BLE2902());
    pCharacteristic_HANDSHAKE_HELLO->addDescriptor(new BLE2902());
    pCharacteristic_SEND_HELLO_MESSAGE->addDescriptor(new BLE2902());
    pCharacteristic_READ_HELLO_MESSAGE->addDescriptor(new BLE2902());
    pCharacteristic_READ_DATA->addDescriptor(new BLE2902());
    pCharacteristic_WRITE_DATA->addDescriptor(new BLE2902());

    // Start service
    pService->start();

    // Start advertising
    pServer->getAdvertising()->start();
    Serial.println(">> [BLE_SERVER] BLE Server started. Listening for connections...");
}
