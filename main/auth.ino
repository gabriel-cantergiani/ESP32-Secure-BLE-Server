// aqui vão: métodos do processo de autenticação, e métodos criptográficos

#include "src/MD5/MD5.h"
#include "src/RC4/rc4.h"

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
MD5  hashMD5;


/*********************

checkAuthentication

*********************/

char * checkAuthentication(char *pack){
    Serial.println(">> [AUTH] Checking Package Authentication");

    char * PackageK = new char[24];
    char * PackageK_HMAC = new char[16];

    // Copy first 24 bytes to Package K
    memcpy( PackageK , pack, 24 );
    Serial.print(">>> [AUTH] PackageK: ");
    printByteArray( PackageK, 24 );

    // Copy from byte 24 through 40 to Package K HMAC
    memcpy( PackageK_HMAC, (pack + 24), 16 );
    Serial.print(">>> [AUTH] PackageK_HMAC: ");
    printByteArray( PackageK_HMAC, 16 );

    // Call Check Sign, passing PackageK, PackageK_HMAC
    if ( CheckSignForPackageK( PackageK, PackageK_HMAC )) {
        return PackageK;
    }

    return NULL;
}


/*********************

checkSignForPackage

*********************/

bool CheckSignForPackageK( char * PackageK, char * Received_PackageK_HMAC ) {
    Serial.println(">> [AUTH] Checking Sign for PackageK");

    // Generate HMAC_MD5 of PackageK, using Kauth_sddl
    char * Generated_PackageK_HMAC;

    Generated_PackageK_HMAC = hashMD5.hmac_md5(PackageK, 24, Kauth_sddl, strlen(Kauth_sddl));

    for (int i=0; i < 16; i++){
        if (Received_PackageK_HMAC[i] != Generated_PackageK_HMAC[i]){
            Serial.println(">>> [AUTH] PackageK verification failed!");
            return false;
        }
    }

    Serial.println(">>> [AUTH] PackageK verified successfully!");
    return true;

}


/*******************

print_byte_array

*******************/

void printByteArray( char * content , int content_len){
    for(int i=0; i<content_len; i++)
        Serial.print(content[i], HEX);
    Serial.println();
}