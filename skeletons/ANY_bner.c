/*
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info> and contributors.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <ANY.h>
#include <asn_codecs_prim.h>
#include <asn_internal.h>

/*
 * This macro "eats" the part of the buffer which is definitely "consumed",
 * i.e. was correctly converted into local representation or rightfully skipped.
 */
#undef ADVANCE
#define ADVANCE(num_bytes)                       \
    do {                                         \
        size_t num = num_bytes;                  \
        buf_ptr = ((const char *)buf_ptr) + num; \
        size -= num;                             \
        consumed_myself += num;                  \
    } while(0)

/*
 * Return a standardized complex structure.
 */
#undef RETURN
#define RETURN(_code)                    \
    do {                                 \
        rval.code = _code;               \
        rval.consumed = consumed_myself; \
        return rval;                     \
    } while(0)

asn_dec_rval_t
ANY_decode_bner(const asn_codec_ctx_t *opt_codec_ctx,
                const asn_TYPE_descriptor_t *td, void **sptr,
                const void *buf_ptr, size_t size, ber_tlv_tag_t tag,
                int tag_mode) {
    asn_dec_rval_t rval = {RC_OK, 0};
    ANY_t *st = (ANY_t *)*sptr;
    size_t consumed_myself = 0; /* Consumed bytes from ptr */
    bner_tag_lvt_t bner_tag;

    rval = bner_fetch_tag_lvt(buf_ptr, size, &bner_tag);
    ASN_DEBUG("Decoding %s as ANY (tm=%d, tc=%d): %s", td->name, tag_mode,
              td->tags_count, bner_tag_lvt_string(&bner_tag));

    /*
     * Create the string if does not exist.
     */
    if(st == NULL) {
        st = (ANY_t *)CALLOC(1, sizeof(ANY_t));
        if(st == NULL) RETURN(RC_FAIL);
    }

    st->tag = bner_tag.tag;
    return bner_decode_primitive(opt_codec_ctx, td, sptr, buf_ptr, size,
                                 bner_tag.tag, tag_mode);
}

asn_enc_rval_t
ANY_encode_bner(const asn_TYPE_descriptor_t *td, const void *sptr, int tag_mode,
                ber_tlv_tag_t tag, asn_app_consume_bytes_f *cb, void *app_key) {
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
