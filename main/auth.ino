// aqui vão: métodos do processo de autenticação, e métodos criptográficos

#include <MD5.h>

// SDDL auth symmetric key
char * Kauth_sddl = "Kauth_sddl"
// This Smart Object auth symmetric key
// This Smart Object cipher symmetric key

// MD5  hashMD5;
// char *md5str = hashMD5.hmac_md5(text, text_len, key, key_len);

    // private static SecretKeySpec Kauth_sddl;
    // private static byte[] Kauth_obj;

    // /* Symetric Cipher Key (S-OBJ)*/
    // private byte[] Kcipher_obj = "Kcipher_obj".getBytes("ASCII");

    // /* Initializing Authentications Keys */
    // static {
    //     try {
    //         Kauth_sddl = new SecretKeySpec(("Kauth_sddl").getBytes("ASCII"), "hmacMD5");
    //         Kauth_obj = ("Kauth_obj").getBytes("ASCII");
    //     } catch (UnsupportedEncodingException e) {
    //         e.printStackTrace();
    //     }
    // }



char * checkAuthentication(char *pack){
    Serial.println(">> Checking Package Authentication");

    char * PackageK;
    char * PackageK_HMAC;

    // Copy first 24 bytes to Package K


    // Copy from byte 24 through 40 to Package K HMAC


    // Call Check Sign, passing PackageK, PackageK_HMAC, and Kauth_SDDL


}


// private byte[] CheckAuthentication(ConnectedHub Hub){
//         Log.i(TAG, "DEBUG >> Checking Authentication");
//         print_hex(Hub.getPack());
//         byte[] PackageK = Arrays.copyOfRange(Hub.getPack(), 0, 24);
//         Log.d(TAG, "PackageK: ");
//         print_hex(PackageK);
//         byte[] Package_K_With_HMAC = Arrays.copyOfRange(Hub.getPack(), 24, 40);
//         Log.d(TAG, "PackageK_HMAC: ");
//         print_hex(Package_K_With_HMAC);
//         boolean CheckSign = CheckSignForPackage(PackageK, Package_K_With_HMAC, Kauth_sddl);
//         if(CheckSign) {
//             return PackageK;
//         }else{
//             return null;
//         }
//     }