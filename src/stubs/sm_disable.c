#include "reactive_stubs_support.h"

#define AD_SIZE 2
#define CIPHER_SIZE 2

uint16_t SM_ENTRY(SM_NAME) __sm_disable(const uint8_t* ad, const uint8_t* cipher,
                                    const uint8_t* tag)
{
    if( !sancus_is_outside_sm(SM_NAME, (void *) ad, AD_SIZE) ||
        !sancus_is_outside_sm(SM_NAME, (void *) cipher, CIPHER_SIZE) ||
        !sancus_is_outside_sm(SM_NAME, (void *) tag, SANCUS_TAG_SIZE) ) {
      return BufferInsideSM;
    }

    uint16_t nonce = (ad[0] << 8) | ad[1];

    // check nonce
    if(nonce != __sm_nonce) {
      return MalformedPayload;
    }

    if (!sancus_unwrap(ad, AD_SIZE, cipher, CIPHER_SIZE, tag, (uint8_t *) &nonce)) {
      return CryptoError;
    }

    __sm_nonce++;
    __sm_num_connections = 0;

    return Ok;
}
