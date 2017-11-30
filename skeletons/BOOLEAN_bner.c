/*
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info> and contributors.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <BOOLEAN.h>
#include <asn_internal.h>

asn_dec_rval_t
BOOLEAN_decode_bner(const asn_codec_ctx_t *opt_codec_ctx,
                    const asn_TYPE_descriptor_t *td, void **bool_value,
                    const void *buf_ptr, size_t size, ber_tlv_tag_t tag,
                    int tag_mode) {
    BOOLEAN_t *st = (BOOLEAN_t *)*bool_value;
    asn_dec_rval_t rval;
    bner_tag_lvt_t bner_tag;

    if(st == NULL) {
        st = (BOOLEAN_t *)(*bool_value = CALLOC(1, sizeof(*st)));
        if(st == NULL) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
            return rval;
        }
    }

    ASN_DEBUG("Decoding %s as BOOLEAN (tm=%d)", td->name, tag_mode);

    rval = bner_fetch_tag_lvt(buf_ptr, size, &bner_tag);
    if(rval.code != RC_OK) return rval;

    if(!BER_TAGS_EQUAL(bner_tag.tag, convert_ber_to_bner_tag(tag))) {
        rval.code = RC_FAIL;
        rval.consumed = 0;
        return rval;
    }

    buf_ptr = ((const char *)buf_ptr) + rval.consumed;
    size -= rval.consumed;

    switch(bner_tag.lvt_type) {
    case BNER_LVT_LENGTH:
        if(!tag_mode || bner_tag.u.length != 1) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
            return rval;
        }
        if(bner_tag.u.length > size) {
            rval.code = RC_WMORE;
            rval.consumed = 0;
            return rval;
        }
        *st = ((const uint8_t *)buf_ptr)[0];
        rval.consumed += bner_tag.u.length;
        break;
    case BNER_LVT_VALUE:
        if(tag_mode) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
            return rval;
        }
        *st = bner_tag.u.value;
        break;
    case BNER_LVT_TYPE:
    default:
        rval.code = RC_FAIL;
        rval.consumed = 0;
        return rval;
    }


    ASN_DEBUG("Took %ld bytes to decode %s, value=%d", (long)rval.consumed,
              td->name, *st);

    rval.code = RC_OK;
    return rval;
}

asn_enc_rval_t
BOOLEAN_encode_bner(const asn_TYPE_descriptor_t *td, const void *sptr,
                    int tag_mode, ber_tlv_tag_t tag,
                    asn_app_consume_bytes_f *cb, void *app_key) {
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
