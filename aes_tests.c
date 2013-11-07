
// try some test vectors.

#include "aes.h"
#include "aes_testvectors.h"
#include <string.h> // memcpy()
#include <stdio.h>

int test_AES_Encrypt(void)
{
    unsigned char testkey[AES_TESTVECTORS_SIZE];
    unsigned char testpt[AES_TESTVECTORS_SIZE];
    int i,j;
    int totCount = sizeof(aestestvectors)/sizeof(aestestvectors_t);
    char strrep1[AES_TESTVECTORS_SIZE*2 + 1];
    char hexstr1[3];
    char strrep2[AES_TESTVECTORS_SIZE*2 + 1];
    char hexstr2[3];

    for(i=0; i<totCount; i++){
        // copy the test data over
        memcpy(testkey, aestestvectors[i].key, AES_TESTVECTORS_SIZE);
        memcpy(testpt, aestestvectors[i].plaintext, AES_TESTVECTORS_SIZE);

        // test encryption
        AES_Encrypt(testpt, testkey);
        if(memcmp(testpt, aestestvectors[i].ciphertext, AES_TESTVECTORS_SIZE) != 0){
            strrep1[0] = '\0';
            strrep2[0] = '\0';
            for(j=0; j<AES_TESTVECTORS_SIZE; j++){
                sprintf(hexstr1, "%02X", testpt[j]);
                strcat(strrep1, hexstr1);
                sprintf(hexstr2, "%02X", aestestvectors[i].ciphertext[j]);
                strcat(strrep2, hexstr2);
            }
            printf("AES_Encrypt failed on count %d,\n\tcomputed:  %s\n\treference: %s",
                   aestestvectors[i].idx, strrep1, strrep2);
            return -1;
        }
    }

    // all vectors passed
    return 0;
}

int test_AES_Decrypt(void)
{
    unsigned char testkey[AES_TESTVECTORS_SIZE];
    unsigned char testct[AES_TESTVECTORS_SIZE];
    int i,j;
    int totCount = sizeof(aestestvectors)/sizeof(aestestvectors_t);
    char strrep1[AES_TESTVECTORS_SIZE*2 + 1];
    char hexstr1[3];
    char strrep2[AES_TESTVECTORS_SIZE*2 + 1];
    char hexstr2[3];

    for(i=0; i<totCount; i++){
        // copy the test data over
        memcpy(testkey, aestestvectors[i].key, AES_TESTVECTORS_SIZE);
        memcpy(testct, aestestvectors[i].ciphertext, AES_TESTVECTORS_SIZE);

        // test encryption
        AES_Decrypt(testct, testkey);
        if(memcmp(testct, aestestvectors[i].plaintext, AES_TESTVECTORS_SIZE) != 0){
            strrep1[0] = '\0';
            strrep2[0] = '\0';
            for(j=0; j<AES_TESTVECTORS_SIZE; j++){
                sprintf(hexstr1, "%02X", testct[j]);
                strcat(strrep1, hexstr1);
                sprintf(hexstr2, "%02X", aestestvectors[i].plaintext[j]);
                strcat(strrep2, hexstr2);
            }
            printf("AES_Decrypt failed on count %d,\n\tcomputed:  %s\n\treference: %s",
                   aestestvectors[i].idx, strrep1, strrep2);
            return -1;
        }
    }

    // all vectors passed
    return 0;
}

int main(void)
{
    if(test_AES_Encrypt()){
        printf("AES_Encrypt test Passed.\n");
        return -1;
    }
    printf("AES_Encrypt test Passed.\n");

    if(test_AES_Decrypt()){
        printf("AES_Decrypt test failed.\n");
        return -1;
    }
        printf("AES_Encrypt test Passed.\n");

    printf("All tests Passed.\n");

    return 0;
}
