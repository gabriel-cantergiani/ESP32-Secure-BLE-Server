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
        char *HubAddress;
        int HubAddressLen;
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