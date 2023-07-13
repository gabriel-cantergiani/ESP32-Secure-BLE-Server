/*
*
*   AUTH
*   This module implements all Authentication and encryption functions related to the Authentication process
*
*   Created by: Gabriel Cantergiani, February 2023
*/

#include "src/HMAC_SHA1/hmac.h"
#include "src/HMAC_SHA1/sha1.h"
#include "src/MD5/MD5_hmac.h"
#include "src/MD5/MD5_hash.h"
#include "src/RC4/rc4.h"
#include "src/MobileHub/mhub.cpp"
#include <string.h>

/**********************

Initializing variables

************************/

// SDDL authentication symmetric key
char *Kauth_sddl = "Kauth_core";

// This Smart Object authentication symmetric key
char *Kauth_obj = "Kauth_obj";

// This Smart Object cipher symmetric key
char *Kcipher_obj = "Kcipher_obj"; 

//RC4 encryption structure
arc4_context rc4;

//MD5 Hashing structure
MD5_hmac  MD5_hmac;
MD5_hash MD5_hash;

//SHA1
struct sha1 sha1_context;

int otp_challenge_size = 13;
int session_key_size = 11;
int timestamp_size = 4;
int hmac_size = 20;
int packagek_size = otp_challenge_size + session_key_size;
int hello_message_size = packagek_size + timestamp_size + hmac_size;
int auth_pack_size = hello_message_size + hmac_size;


// Mobile Hub Object
MobileHub *connectedHub;

// EdgeSec Version data length
char *EdgeSecVersion = "1.0";


/*****************

Mobile Hub control functions

********************/

void createMobileHub(){
    connectedHub = new MobileHub(auth_pack_size);
}

void removeConnectedHub(){
    connectedHub = NULL;
}

void setHubID(std::string HubID) {
    connectedHub->HubID = new char[HubID.length()];
    connectedHub->HubIDLen = HubID.length();
    memcpy( connectedHub->HubID, HubID.c_str(), HubID.length() );
}

bool isHubAuthenticated(){
    if (connectedHub->Authenticated)
        return true;
    return false;
}

int getHubState(){
    return connectedHub->STATE;
}

bool isReceivingHelloMessage(){
    return connectedHub->isReceivingHelloMessage;
}

void setIsReceivingHelloMessage(bool state){
  connectedHub->isReceivingHelloMessage = state;
}

void copyPacketToHub(const char * data){
    // Copy value to Package
     memcpy( (connectedHub->pack + connectedHub->lastPackSize) , data , strlen(data) );

     // Increase pack position by value size
     connectedHub->lastPackSize = connectedHub->lastPackSize + strlen(data);

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
    printByteArray(connectedHub->pack, auth_pack_size);

    // Checks PackageK HMAC authentication
    char * PackageK = checkPackageK();

    if (PackageK == NULL){
        Serial.println(">> [AUTH] Failed to check PackageK HMAC");
        return false;
    }

    // Decrypt Package K
    char * decryptedPackageK = decryptPackageK( PackageK );

    // get OTPChallenge from PackageK
    char * OTPChallenge = new char[otp_challenge_size];
    memcpy( OTPChallenge , decryptedPackageK , otp_challenge_size );

    Serial.print("OTPChallenge: ");
    printByteArray(OTPChallenge, otp_challenge_size);

    // generate OTP
    char * OTP = generateOTP( SObjectAddress, OTPChallenge, otp_challenge_size);

    /* Getting the HelloMessage and HelloMessage_HMAC */
    char * HelloMessage = new char[hello_message_size];
    char * HelloMessage_HMAC = new char[hmac_size];

    memcpy( HelloMessage, connectedHub->pack, hello_message_size );
    memcpy( HelloMessage_HMAC, (connectedHub->pack + hello_message_size), hmac_size );

    // Checking integrity of HelloMessage
    if ( !checkSignForHelloMessage( OTP, HelloMessage, HelloMessage_HMAC ) ){
        Serial.println(">> [AUTH] Failed to check Hello Message HMAC");
        return false;
    }

    // Getting Ksession
    char * Ksession = new char[session_key_size];

    memcpy( Ksession, ( decryptedPackageK + otp_challenge_size), session_key_size );

    // Gets timestamp
    char * timestamp = new char[timestamp_size];

    memcpy( timestamp, (connectedHub->pack + (hello_message_size - timestamp_size)), timestamp_size );

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

    char * PackageK = new char[packagek_size];
    char * PackageK_HMAC = new char[hmac_size];

    // Copy first 24 bytes to Package K
    memcpy( PackageK , connectedHub->pack, packagek_size );
    Serial.print(">>> [AUTH] PackageK: ");
    printByteArray( PackageK, packagek_size );

    // Copy from byte 24 through 40 to Package K HMAC
    memcpy( PackageK_HMAC, (connectedHub->pack + packagek_size), hmac_size );
    Serial.print(">>> [AUTH] PackageK_HMAC: ");
    printByteArray( PackageK_HMAC, hmac_size );

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
    Serial.println(">>[DEBUG] [AUTH] Checking Sign for PackageK");

    // char * Generated_PackageK_HMAC;
    uint8_t * Generated_PackageK_HMAC = new uint8_t[hmac_size];

    // hmac_sha1(Generated_PackageK_HMAC, Kauth_sddl, strlen(Kauth_sddl)*8, PackageK, 24*8);
    // Generated_PackageK_HMAC = MD5_hmac.hmac_md5(PackageK, 24, Kauth_sddl, strlen(Kauth_sddl));
    hmac_sha1( (uint8_t*) Kauth_sddl, (uint32_t) strlen(Kauth_sddl), (uint8_t*) PackageK, packagek_size, Generated_PackageK_HMAC);
    Serial.print(">>[DEBUG] [AUTH] Generated PackageK HMAC: ");
    printByteArray(Generated_PackageK_HMAC, hmac_size);

    for (int i=0; i < hmac_size; i++){
        if (Received_PackageK_HMAC[i] != Generated_PackageK_HMAC[i]){
            Serial.print("received: ");
            Serial.print(Received_PackageK_HMAC[i], HEX);
            Serial.print("generated: ");
            Serial.println(Generated_PackageK_HMAC[i], HEX);
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

    decryptedData = (char*) rc4_do_crypt(&rc4, (unsigned char *) cipherPackage, packagek_size, (unsigned char *) Kcipher_obj, strlen(Kcipher_obj));

    Serial.print(">>> [AUTH] Decrypted! Content: ");
    printByteArray(decryptedData, packagek_size);

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
    unsigned int concatDataLength = strlen(SObjectAddress) + connectedHub->HubIDLen +  OTPChallengeLen + strlen(Kauth_obj);

    concatData = new char[concatDataLength];

    memcpy( concatData, SObjectAddress, strlen(SObjectAddress) );
    memoryPosition += strlen(SObjectAddress);

    memcpy( (concatData + memoryPosition) , connectedHub->HubID, connectedHub->HubIDLen );
    memoryPosition += connectedHub->HubIDLen;

    memcpy( (concatData + memoryPosition) , OTPChallenge, OTPChallengeLen );
    memoryPosition += OTPChallengeLen;

    memcpy( (concatData + memoryPosition) , Kauth_obj, strlen(Kauth_obj) );

    Serial.println(">> [AUTH] OTP concat data: ");
    printByteArray(concatData, concatDataLength);

    OTP = new unsigned char[hmac_size];
    // MD5_hash.reset();
    sha1_reset(&sha1_context);
    // MD5_hash.add(concatData, concatDataLength);
    sha1_input(&sha1_context, (const uint8_t*) concatData, (unsigned int) concatDataLength);
    // MD5_hash.getHash(OTP);
    sha1_result(&sha1_context, (uint8_t*) OTP);
    // MD5_hash.reset();
    sha1_reset(&sha1_context);


    Serial.print(">>> [AUTH] OTP generated! Content: ");
    printByteArray(OTP, hmac_size);

    return (char *) OTP;
}

/*********************

checkSignForHelloMessage

*********************/

bool checkSignForHelloMessage( char * OTP, char * HelloMessage, char * Received_HelloMessage_HMAC) {
    Serial.println(">> [AUTH] Checking Hello Message Signature");

    uint8_t * Generated_HelloMessage_HMAC = new uint8_t[hmac_size];
    char * concatData;

    concatData = new char[connectedHub->HubIDLen + hello_message_size];

    memcpy( concatData, connectedHub->HubID, connectedHub->HubIDLen );
    memcpy( (concatData + connectedHub->HubIDLen), HelloMessage, hello_message_size );

    // Generated_HelloMessage_HMAC = MD5_hmac.hmac_md5(concatData, connectedHub->HubIDLen + hello_message_size, OTP, hmac_size);
    hmac_sha1( (uint8_t*) OTP, (uint32_t) hmac_size, (uint8_t*) concatData, connectedHub->HubIDLen + hello_message_size, Generated_HelloMessage_HMAC);

    Serial.print(">> [AUTH] Received HelloMessage HMAC: ");
    printByteArray(Received_HelloMessage_HMAC, hmac_size);

    Serial.print(">> [AUTH] Generated_HelloMessage_HMAC: ");
    printByteArray(Generated_HelloMessage_HMAC, hmac_size);

    for (int i=0; i < hmac_size; i++){
        if (Received_HelloMessage_HMAC[i] != Generated_HelloMessage_HMAC[i]){
            Serial.print("received: ");
            Serial.print(Received_HelloMessage_HMAC[i], HEX);
            Serial.print("generated: ");
            Serial.println(Generated_HelloMessage_HMAC[i], HEX);
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

    uint8_t * HelloAcceptedMessage_HMAC = new uint8_t[hmac_size];;
    char * concatData;
    unsigned int memoryPosition = 0;
    int totalLen = connectedHub->HubIDLen + strlen(SObjectAddress) + timestamp_size;

    concatData = new char[totalLen];

    memcpy( concatData, connectedHub->HubID, connectedHub->HubIDLen );
    memoryPosition += connectedHub->HubIDLen;

    memcpy( (concatData + memoryPosition), SObjectAddress, strlen(SObjectAddress) );
    memoryPosition += strlen(SObjectAddress);

    memcpy( (concatData + memoryPosition), timestamp, timestamp_size );
    
    // HelloAcceptedMessage_HMAC = MD5_hmac.hmac_md5(concatData, connectedHub->HubIDLen + strlen(SObjectAddress) + timestamp_size, OTP, hmac_size);
    hmac_sha1( (uint8_t*) OTP, (uint32_t) hmac_size, (uint8_t*) concatData, connectedHub->HubIDLen + strlen(SObjectAddress) + timestamp_size, HelloAcceptedMessage_HMAC);


    Serial.print("HelloAcceptedMessage HMAC generated: ");
    printByteArray(HelloAcceptedMessage_HMAC, hmac_size);

    return (char *) HelloAcceptedMessage_HMAC;
    
}

/*******************

generateSecureMessage

*******************/

char * generateSecureMessage(std::string data, int data_length) {

    char * cipherData;
    uint8_t * messageHMAC = new uint8_t[hmac_size];
    char * secureMessage;
    unsigned int memoryPosition = 0;

    // Data + HMAC
    secureMessage = new char[data_length + hmac_size];

    Serial.print(">>> [AUTH][SECURE_MESSAGE] Raw Data: ");
    Serial.println(data.c_str());

    // Encrypt data
    cipherData = encryptData(data);

    Serial.print(">>> [AUTH][SECURE_MESSAGE] Encrypted Data: ");
    printByteArray(cipherData, data_length);

    // Copy encrypted data to message
    memcpy(secureMessage, cipherData, data.length() );
    memoryPosition += data_length;

    // Generate a message HMAC using OTP as key
    // messageHMAC = MD5_hmac.hmac_md5(secureMessage, memoryPosition, connectedHub->OTP, hmac_size);
    hmac_sha1( (uint8_t*) connectedHub->OTP, (uint32_t) hmac_size, (uint8_t*) secureMessage, memoryPosition, messageHMAC);


    Serial.print(">>> [AUTH][SECURE_MESSAGE] Message HMAC: ");
    printByteArray(messageHMAC, hmac_size);

    // Append HMAC to encrypted data
    memcpy( (secureMessage + memoryPosition), messageHMAC, hmac_size );

    Serial.print(" [AUTH][SECURE_MESSAGE] Secure Message generated (message + hmac): ");
    printByteArray(secureMessage, data_length + hmac_size);

    // Return message
    return secureMessage;
    
}


/*******************

encryptData

*******************/

char * encryptData(std::string data) {

    char * cipherData = new char[data.length()];

    cipherData = (char*) rc4_do_crypt(&rc4, (unsigned char *) data.c_str(), data.length(), (unsigned char *) connectedHub->Ksession, session_key_size);
    
    Serial.print("Cipher Data: ");
    printByteArray(cipherData, data.length());

    return cipherData;
}

/*******************

generateNewTimestamp

*******************/

char * generateNewTimestamp() {

    int newTimestamp;
    char * newTimestampBytes = new char[timestamp_size];

    // Convert timestamp bytes to int
    memcpy(&newTimestamp, connectedHub->timestamp, timestamp_size);

    // Increment current timestamp by one
    newTimestamp += 1;

    // Convert timestamp int to bytes
//    memcpy(newTimestampBytes, (void*) newTimestamp, 4);
    newTimestampBytes[0] = (newTimestamp >> 24) & 0xFF;
    newTimestampBytes[1] = (newTimestamp >> 16) & 0xFF;
    newTimestampBytes[2] = (newTimestamp >> 8) & 0xFF;
    newTimestampBytes[3] = newTimestamp & 0xFF;

//    connectedHub->timestamp = newTimestampBytes;
    memcpy(connectedHub->timestamp, newTimestampBytes, timestamp_size);

    return newTimestampBytes;
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
