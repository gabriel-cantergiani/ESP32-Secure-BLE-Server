/*
*
*   AUTH
*   This module implements all Authentication and encryption functions related to the Authentication process
*
*   Created by: Gabriel Cantergiani, June 2020
*/

#include "src/MD5/MD5_hmac.h"
#include "src/MD5/MD5_hash.h"
#include "src/RC4/rc4.h"
#include "src/MobileHub/mhub.cpp"
#include <string.h>

/**********************

Initializing variables

************************/

// SDDL authentication symmetric key
char *Kauth_sddl = "Kauth_sddl";

// This Smart Object authentication symmetric key
char *Kauth_obj = "Kauth_obj";

// This Smart Object cipher symmetric key
char *Kcipher_obj = "Kcipher_obj"; 

//RC4 encryption structure
arc4_context rc4;

//MD5 Hashing structure
MD5_hmac  MD5_hmac;
MD5_hash MD5_hash;

// Mobile Hub Object
MobileHub *connectedHub;


/*****************

Mobile Hub control functions

********************/

void createMobileHub(){
    connectedHub = new MobileHub();
}

void removeConnectedHub(){
    connectedHub = NULL;
}

void setHubAddress(std::string HubAddress) {
    connectedHub->HubAddress = new char[HubAddress.length()];
    connectedHub->HubAddressLen = HubAddress.length();
    memcpy( connectedHub->HubAddress, HubAddress.c_str(), HubAddress.length() );
}

bool isHubAuthenticated(){
    if (connectedHub->Authenticated)
        return true;
    return false;
}

int getHubState(){
    return connectedHub->STATE;
}

void copyPacketToHub(const char * data, int datalen){
    // Copy value to Package
    memcpy( (connectedHub->pack + connectedHub->lastPackSize)  , data , datalen );

    // Increase pack position by value size
    connectedHub->lastPackSize = connectedHub->lastPackSize + datalen;

    // Increase STATE
    connectedHub->STATE++;
}

char * getHubAcceptedMessage(){
    return connectedHub->AcceptedMessage;
}



/*********************

checkAuthentication

*********************/

bool checkAuthentication(char * SObjectAddress){
    Serial.println(">> [AUTH] Checking Device Authentication. Pack Content: ");
    printByteArray(connectedHub->pack, 60);

    // Checks PackageK HMAC authentication
    char * PackageK = checkPackageK();

    if (PackageK == NULL){
        Serial.println(">> [AUTH] Failed to check PackageK HMAC");
        return false;
    }

    // Decrypt Package K
    char * decryptedPackageK = decryptPackageK( PackageK );

    // get OTPChallenge from PackageK
    char * OTPChallenge = new char[13];
    memcpy( OTPChallenge , decryptedPackageK , 13 );

    // generate OTP
    char * OTP = generateOTP( SObjectAddress, OTPChallenge, 13);

    /* Getting the HelloMessage and HelloMessage_HMAC */
    char * HelloMessage = new char[44];
    char * HelloMessage_HMAC = new char[16];

    memcpy( HelloMessage, connectedHub->pack, 44 );
    memcpy( HelloMessage_HMAC, (connectedHub->pack + 44), 16 );

    // Checking integrity of HelloMessage
    if ( !checkSignForHelloMessage( OTP, HelloMessage, HelloMessage_HMAC ) ){
        Serial.println(">> [AUTH] Failed to check Hello Message HMAC");
        return false;
    }

    // Getting Ksession
    char * Ksession = new char[13];

    memcpy( Ksession, ( decryptedPackageK + 13), 11 );

    // Gets timestamp
    char * timestamp = new char[4];

    memcpy( timestamp, (connectedHub->pack + 40), 4 );

    // Generate and Sign Hello Accepted Message
    char * SignedAcceptedMessage = signHelloAcceptedMessage( SObjectAddress, OTP, timestamp);

    // Store all values in MHub Object
    connectedHub->Ksession = Ksession;
    connectedHub->OTP = OTP;
    connectedHub->timestamp = timestamp;
    connectedHub->AcceptedMessage = SignedAcceptedMessage;
    connectedHub->Authenticated = true;

    Serial.println(">> [AUTH] Authentication process finished successfully.");
    return true;

}


/*********************

checkPackageK

*********************/

char * checkPackageK(){
    Serial.println(">> [AUTH] Checking Package Authentication");

    char * PackageK = new char[24];
    char * PackageK_HMAC = new char[16];

    // Copy first 24 bytes to Package K
    memcpy( PackageK , connectedHub->pack, 24 );
    Serial.print(">>> [AUTH] PackageK: ");
    printByteArray( PackageK, 24 );

    // Copy from byte 24 through 40 to Package K HMAC
    memcpy( PackageK_HMAC, (connectedHub->pack + 24), 16 );
    Serial.print(">>> [AUTH] PackageK_HMAC: ");
    printByteArray( PackageK_HMAC, 16 );

    // Call Check Sign, passing PackageK, PackageK_HMAC
    if ( checkSignForPackageK( PackageK, PackageK_HMAC )) {
        return PackageK;
    }

    return NULL;
}


/*********************

checkSignForPackageK

*********************/

bool checkSignForPackageK( char * PackageK, char * Received_PackageK_HMAC ) {
    Serial.println(">> [AUTH] Checking Sign for PackageK");

    char * Generated_PackageK_HMAC;

    Generated_PackageK_HMAC = MD5_hmac.hmac_md5(PackageK, 24, Kauth_sddl, strlen(Kauth_sddl));

    for (int i=0; i < 16; i++){
        if (Received_PackageK_HMAC[i] != Generated_PackageK_HMAC[i]){
            Serial.println(">>> [AUTH] PackageK verification failed!");
            return false;
        }
    }

    Serial.println(">>> [AUTH] PackageK verified successfully!");
    return true;

}

/*********************

decryptPackageK

*********************/

char * decryptPackageK( char * cipherPackage) {
    Serial.println(">> [AUTH] Decrypting PackageK");

    char * decryptedData;

    decryptedData = (char*) rc4_do_crypt(&rc4, (unsigned char *) cipherPackage, 24, (unsigned char *) Kcipher_obj, strlen(Kcipher_obj));

    Serial.print(">>> [AUTH] Decrypted! Content: ");
    printByteArray(decryptedData, 24);

    return decryptedData;
}


/*********************

Generate OTP

*********************/

char * generateOTP( char * SObjectAddress, char * OTPChallenge, unsigned int OTPChallengeLen) {
    Serial.println(">> [AUTH] Generating OTP");

    char * concatData;
    unsigned char * OTP;
    unsigned int memoryPosition = 0;

    concatData = new char[strlen(SObjectAddress) + connectedHub->HubAddressLen +  OTPChallengeLen + strlen(Kauth_obj)];

    memcpy( concatData, SObjectAddress, strlen(SObjectAddress) );
    memoryPosition += strlen(SObjectAddress);

    memcpy( (concatData + memoryPosition) , connectedHub->HubAddress, connectedHub->HubAddressLen );
    memoryPosition += connectedHub->HubAddressLen;

    memcpy( (concatData + memoryPosition) , OTPChallenge, OTPChallengeLen );
    memoryPosition += OTPChallengeLen;

    memcpy( (concatData + memoryPosition) , Kauth_obj, strlen(Kauth_obj) );

    OTP = new unsigned char[16];
    MD5_hash.add(concatData, 56);
    MD5_hash.getHash(OTP);

    Serial.print(">>> [AUTH] OTP generated! Content: ");
    printByteArray(OTP, 16);

    return (char *) OTP;
}

/*********************

checkSignForHelloMessage

*********************/

bool checkSignForHelloMessage( char * OTP, char * HelloMessage, char * Received_HelloMessage_HMAC) {
    Serial.println(">> [AUTH] Checking Hello Message Signature");

    char * Generated_HelloMessage_HMAC;
    char * concatData;

    concatData = new char[connectedHub->HubAddressLen + 44];

    memcpy( concatData, connectedHub->HubAddress, connectedHub->HubAddressLen );
    memcpy( (concatData + connectedHub->HubAddressLen), HelloMessage, 44 );

    Generated_HelloMessage_HMAC = MD5_hmac.hmac_md5(concatData, connectedHub->HubAddressLen + 44, OTP, 16);

    for (int i=0; i < 16; i++){
        if (Received_HelloMessage_HMAC[i] != Generated_HelloMessage_HMAC[i]){
            Serial.println(">>> [AUTH] HelloMessage verification failed!");
            return false;
        }
    }

    Serial.println(">>> [AUTH] HelloMessage verified successfully!");
    return true;
    
}


/*********************

signHelloAcceptedMessage

*********************/

char * signHelloAcceptedMessage( char * SObjectAddress, char * OTP, char * timestamp) {
    Serial.println(">> [AUTH] Signing Hello Accepted Message");

    char * HelloAcceptedMessage_HMAC;
    char * concatData;
    unsigned int memoryPosition = 0;
    int totalLen = connectedHub->HubAddressLen + strlen(SObjectAddress) + 4;

    concatData = new char[totalLen];

    memcpy( concatData, connectedHub->HubAddress, connectedHub->HubAddressLen );
    memoryPosition += connectedHub->HubAddressLen;

    memcpy( (concatData + memoryPosition), SObjectAddress, strlen(SObjectAddress) );
    memoryPosition += strlen(SObjectAddress);

    memcpy( (concatData + memoryPosition), timestamp, 4 );
    
    HelloAcceptedMessage_HMAC = MD5_hmac.hmac_md5(concatData, connectedHub->HubAddressLen + strlen(SObjectAddress) + 4, OTP, 16);

    Serial.print("HelloAcceptedMessage HMAC generated: ");
    printByteArray(HelloAcceptedMessage_HMAC, 16);

    return HelloAcceptedMessage_HMAC;
    
}


/*******************

encryptData

*******************/

char * encryptData(std::string data) {

    char * cipherData = new char[data.length()];

    cipherData = (char*) rc4_do_crypt(&rc4, (unsigned char *) data.c_str(), data.length(), (unsigned char *) connectedHub->Ksession, 11);
    
    Serial.print("Cipher Data: ");
    printByteArray(cipherData, data.length());

    return cipherData;
}


/*******************

printByteArray

*******************/

void printByteArray( char * content , int content_len){
    for(int i=0; i<content_len; i++)
        Serial.print(content[i], HEX);
    Serial.println();
}

void printByteArray( unsigned char * content , int content_len){
    for(int i=0; i<content_len; i++)
        Serial.print(content[i], HEX);
    Serial.println();
}