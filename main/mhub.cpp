#include <Arduino.h>
// aqui vão a struct do Mobile Hub e os métodos get e set

// struct record
// {
//    int one;
//    int two;
//    int three;
// };

// typedef struct record Record;

// Record aRec;
// aRec.one = 12;

// typedef char byte;

class MobileHub {

    public:
        std::string HubAddress;
        int STATE;
        char *pack;
        int lastPackSize;
        bool Authenticated;
        char *OTP;
        char *timestamp;
        char *AcceptedMessage;
        char *Ksession;

        MobileHub(int packSize) {
            Serial.println(">> Creating Mobile Hub Object");
            STATE = 1;
            Authenticated = false;
            lastPackSize = packSize;
            AcceptedMessage = NULL;
            pack = new char[60];
        }

};