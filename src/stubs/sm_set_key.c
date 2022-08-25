#include "reactive_stubs_support.h"

#define AD_SIZE 6

uint16_t SM_ENTRY(SM_NAME) __sm_set_key(const uint8_t* ad, const uint8_t* cipher,
                                    const uint8_t* tag, uint16_t *conn_idx)
{
    if( !sancus_is_outside_sm(SM_NAME, (void *) ad, AD_SIZE) ||
        !sancus_is_outside_sm(SM_NAME, (void *) cipher, SANCUS_KEY_SIZE) ||
        !sancus_is_outside_sm(SM_NAME, (void *) tag, SANCUS_TAG_SIZE) ||
        !sancus_is_outside_sm(SM_NAME, (void *) conn_idx, sizeof(uint16_t)) ) {
      return BufferInsideSM;
    }

    // Note: make sure we only use AD_SIZE bytes of the buffer `ad`
    conn_index conn_id = (ad[0] << 8) | ad[1];
    io_index io_id = (ad[2] << 8) | ad[3];
    uint16_t nonce = (ad[4] << 8) | ad[5];

    // check nonce
    if(nonce != __sm_nonce) {
      return MalformedPayload;
    }

    Connection *conn = NULL;
    uint16_t num_c = __sm_num_connections;

    if(*conn_idx < __sm_num_connections &&
        __sm_io_connections[*conn_idx].conn_id == conn_id) {
      // replace an existing connection
      conn = &__sm_io_connections[*conn_idx];
    } 
    else if(__sm_num_connections < SM_MAX_CONNECTIONS) {
      // use new connection 
      *conn_idx = num_c;
      conn = &__sm_io_connections[num_c++];
    } 
    else {
      return InternalError;
    }

    if (!sancus_unwrap(ad, AD_SIZE, cipher, SANCUS_KEY_SIZE, tag, conn->key)) {
      return CryptoError;
    }

    __sm_nonce++;
    __sm_num_connections = num_c;

    conn->io_id = io_id;
    conn->conn_id = conn_id;
    conn->nonce = 0;

    return Ok;
}
