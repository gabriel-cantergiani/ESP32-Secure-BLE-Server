#include <Arduino.h>

class MobileHub {

    public:
        char *HubAddress;
        int STATE;
        char *pack;
        int lastPackSize;
        bool Authenticated;
        char *OTP;
        char *timestamp;
        char *AcceptedMessage;
        char *Ksession;

        MobileHub() {
            STATE = 1;
            Authenticated = false;
            lastPackSize = 0;
            AcceptedMessage = NULL;
            pack = new char[60];
        }

};