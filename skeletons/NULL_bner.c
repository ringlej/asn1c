/*
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info> and contributors.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <NULL.h>
#include <asn_internal.h>

asn_dec_rval_t
NULL_decode_bner(const asn_codec_ctx_t *opt_codec_ctx,
                 const asn_TYPE_descriptor_t *td, void **struct_ptr,
                 const void *buf_ptr, size_t size, ber_tlv_tag_t tag,
                 int tag_mode) {
    asn_dec_rval_t rval;
    bner_tag_lvt_t bner_tag;

    (void)opt_codec_ctx;
    (void)td;
    (void)tag_mode;

    rval = bner_fetch_tag_lvt(buf_ptr, size, &bner_tag);
    if(rval.code != RC_OK) return rval;

    if(!BER_TAGS_EQUAL(bner_tag.tag, convert_ber_to_bner_tag(tag))) {
        rval.code = RC_FAIL;
        rval.consumed = 0;
        return rval;
    }

    if(!*struct_ptr) {
        *struct_ptr = MALLOC(sizeof(NULL_t));
        if(*struct_ptr) {
            *(NULL_t *)*struct_ptr = 0;
        } else {
            ASN__DECODE_FAILED;
        }
    }

    buf_ptr = ((const char *)buf_ptr) + rval.consumed;
    size -= rval.consumed;

    /*
     * NULL type does not have content octets.
     */

    rval.code = RC_OK;
    return rval;
}

asn_enc_rval_t
NULL_encode_bner(const asn_TYPE_descriptor_t *td, const void *sptr,
                 int tag_mode, ber_tlv_tag_t tag, asn_app_consume_bytes_f *cb,
                 void *app_key) {
    (void)td;
    (void)sptr;
    (void)tag_mode;
    (void)tag;
    (void)cb;
    (void)app_key;

    ASN_DEBUG("%s Not yet implemented. Failed to encode %s", __func__,
              td->name);
    ASN__ENCODE_FAILED;
}
