/*
*
*   MOBILE HUB
*   This module defines the MobileHub class, which holds data and information about a connected MobileHub
*
*   Created by: Gabriel Cantergiani, June 2020
*/


#include <Arduino.h>

class MobileHub {

    public:
        char *HubID;
        int HubIDLen;
        int STATE;
        char *pack;
        int lastPackSize;
        bool Authenticated;
        char *OTP;
        char *timestamp;
        char *AcceptedMessage;
        char *Ksession;
        bool isReceivingHelloMessage;

        MobileHub() {
            STATE = 0;
            Authenticated = false;
            lastPackSize = 0;
            AcceptedMessage = NULL;
            pack = new char[60];
            isReceivingHelloMessage = false;
        }

};