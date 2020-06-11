// Aqui vao: criacao do Servico e das characteristicas  , callbacks (onReq.. onWrite..OnRead..), envio de mensagens, lista de Mhubs conectados

#include <BLEDevice.h>
#include <BLEDescriptor.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include "mhub.cpp"
#include <string.h>

// Defining Security Service and Characteristics
#define SECURITY_SERVICE_UUID   "dc33e26c-a82e-4fea-82ab-daa5dfac3dd3"
#define GET_HELLO_UUID          "8b81383b-1136-4df2-85a4-dd29a7a4e81b"
#define GET_MAC_UUID            "65d89516-59fd-453b-91a7-861982bbd8eb"
#define SET_MAC_UUID            "2c093c70-8b7c-4398-bda1-8340dfd50bae"
#define AUTH_WRITE_UUID         "35875610-380a-4cfb-aa9e-6efcea4803ea"
#define READ_UUID               "f86db954-a0d0-4d99-b27f-bb8d42585e97"
#define WRITE_UUID              "2cb4b710-9ec7-47bf-bfc7-ad9341a0773e"
#define DESCRIPTOR_UUID         "8e1251d2-bba7-47d7-904e-fcea2ab50953"


// Defining variables
extern bool isConnected;
extern bool isAuthenticated;
MobileHub *connectedHub;

BLECharacteristic *pCharacteristic_GET_MAC;
BLECharacteristic *pCharacteristic_SET_MAC;
BLECharacteristic *pCharacteristic_AUTH_WRITE;
BLECharacteristic *pCharacteristic_GET_HELLO;
BLECharacteristic *pCharacteristic_READ;
BLECharacteristic *pCharacteristic_WRITE;


// Defining Callback functions

class ServerCallbacks: public BLEServerCallbacks {
    void onConnect(BLEServer* pServer) {
        isConnected = true;
        Serial.println(">> Device Connected!");

        // Stop Advertising
        pServer->getAdvertising()->stop();
    
        // Create Mobile Hub Object
        connectedHub = new MobileHub(0);
    
    }

    void onDisconnect(BLEServer* pServer) {
        isConnected = false;
        Serial.println(">> Device Disconnected!");

        // Remove connectedHub
        connectedHub = NULL;

        // Start advertising again
        pServer->getAdvertising()->start();
        Serial.println(">> Restarted Advertising. Listening for connection...");

    }
};

class CharacteristicCallbacks: public BLECharacteristicCallbacks {
    
    // When a write request arrives
    void onWrite(BLECharacteristic *pCharacteristic) {
        Serial.print(">> Characteristic onWrite: ");
        Serial.println(pCharacteristic->getUUID().toString().c_str());

        // SET_MAC -> Stores Hub Mac Address in MobileHub Object
        if (pCharacteristic->getUUID().toString() == SET_MAC_UUID) {
            std::string HubAddress = pCharacteristic->getValue();
            Serial.print(">>> [SET_MAC] Hub Address received: ");
            Serial.println(HubAddress.c_str());
            connectedHub->HubAddress = HubAddress;
        }
        // AUTH_WRITE -> Receives Authentication Package, in 3 parts
        else if (pCharacteristic->getUUID().toString() == AUTH_WRITE_UUID) {
            if (connectedHub->Authenticated) {
                Serial.println(">>> [AUTH_WRITE] Device already authenticated!");
                return;
            }

            Serial.print(">>>> [AUTH_WRITE] Copying value into PACK. In State: ");
            Serial.println(connectedHub->STATE);

            // Get characteristic value
            std::string value = pCharacteristic->getValue();

            // Copy value to Package
            memcpy( connectedHub->pack , value.c_str() , value.size() );

            // Increase pack position by value size
            connectedHub->lastPackSize = connectedHub->lastPackSize + value.size();

            // Increase STATE
            connectedHub->STATE++;

            if (connectedHub->STATE == 4) {
                Serial.print(">>>> [AUTH_WRITE] Pack complete! Content: ");
                Serial.println(connectedHub->pack.toString().c_str());

            }

        }


    }

    // When a read request arrives
    void onRead(BLECharacteristic *pCharacteristic) {
        Serial.print(">> Characteristic onRead: ");
        Serial.println(pCharacteristic->getUUID().toString().c_str());

        // GET_MAC -> Sends the MacAddress of this device to the Mobile Hub
        if (pCharacteristic->getUUID().toString() == GET_MAC_UUID) {
            std::string macAddress = BLEDevice::getAddress().toString();
            Serial.print(">>> [GET_MAC] Sending device Address: ");
            Serial.println(macAddress.c_str());

            pCharacteristic->setValue(macAddress);
            pCharacteristic->notify();
            Serial.println(">>> [GET_MAC] MacAddress sent!");
        }

    }
};



// Func que inicializa servidor, servico e characteristics

void initializeServer() {
    isConnected = false;

    // Create device
    BLEDevice::init("BLE_Server");

    // Configure Device as a Server
    BLEServer *pServer = BLEDevice::createServer();
    pServer->setCallbacks(new ServerCallbacks());

    // Create Security Service
    BLEService *pService = pServer->createService(SECURITY_SERVICE_UUID);

    // Create all characteristic
    pCharacteristic_GET_MAC = pService->createCharacteristic(GET_MAC_UUID, BLECharacteristic::PROPERTY_READ);
    pCharacteristic_SET_MAC = pService->createCharacteristic(SET_MAC_UUID, BLECharacteristic::PROPERTY_WRITE);
    pCharacteristic_AUTH_WRITE = pService->createCharacteristic(AUTH_WRITE_UUID, BLECharacteristic::PROPERTY_WRITE);
    pCharacteristic_GET_HELLO = pService->createCharacteristic(GET_HELLO_UUID, BLECharacteristic::PROPERTY_READ);
    pCharacteristic_READ = pService->createCharacteristic(READ_UUID, BLECharacteristic::PROPERTY_READ);
    pCharacteristic_WRITE = pService->createCharacteristic(WRITE_UUID, BLECharacteristic::PROPERTY_WRITE);

    // Set callback functions to all characteritics
    pCharacteristic_GET_MAC->setCallbacks(new CharacteristicCallbacks());
    pCharacteristic_SET_MAC->setCallbacks(new CharacteristicCallbacks());
    pCharacteristic_AUTH_WRITE->setCallbacks(new CharacteristicCallbacks());
    pCharacteristic_GET_HELLO->setCallbacks(new CharacteristicCallbacks());
    pCharacteristic_READ->setCallbacks(new CharacteristicCallbacks());
    pCharacteristic_WRITE->setCallbacks(new CharacteristicCallbacks());

    // Set Descriptors to all characteristics
    pCharacteristic_GET_MAC->addDescriptor(new BLEDescriptor(DESCRIPTOR_UUID));
    pCharacteristic_SET_MAC->addDescriptor(new BLEDescriptor(DESCRIPTOR_UUID));
    pCharacteristic_AUTH_WRITE->addDescriptor(new BLEDescriptor(DESCRIPTOR_UUID));
    pCharacteristic_GET_HELLO->addDescriptor(new BLEDescriptor(DESCRIPTOR_UUID));
    pCharacteristic_READ->addDescriptor(new BLEDescriptor(DESCRIPTOR_UUID));
    pCharacteristic_WRITE->addDescriptor(new BLEDescriptor(DESCRIPTOR_UUID));

    // Start service
    pService->start();

    // Start advertising
    pServer->getAdvertising()->start();
    Serial.println(">> BLE Server started. Listening for connections...");
}


// funcao que dá start no processo de autenticação
