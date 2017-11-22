/*
 * Copyright (c) 2017 Jon Ringle <jringle@gridpoint.com>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_codecs_prim.h>
#include <asn_internal.h>
#include <bner_primitive.h>

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

/*
 * Decode an always-primitive type.
 */
asn_dec_rval_t
bner_decode_primitive(const asn_codec_ctx_t *opt_codec_ctx,
                      const asn_TYPE_descriptor_t *td, void **sptr,
                      const void *buf_ptr, size_t size, ber_tlv_tag_t tag,
                      int tag_mode) {
    (void)opt_codec_ctx;
    (void)tag_mode;

    ASN__PRIMITIVE_TYPE_t *st = (ASN__PRIMITIVE_TYPE_t *)*sptr;
    asn_dec_rval_t rval = {RC_OK, 0};
    size_t consumed_myself = 0; /* Consumed bytes from ptr */
    bner_tag_lvt_t bner_tag;

    rval = bner_fetch_tag_lvt(buf_ptr, size, &bner_tag);
    if(rval.code != RC_OK) return rval;

    ASN_DEBUG("Decoding %s as plain primitive %s (tm=%d): %s", td->name,
              ber_tlv_tag_string(tag), tag_mode,
              bner_tag_lvt_string(&bner_tag));

    if(is_bner_opening_tag(bner_tag) && tag != ASN_TAG_AMBIGUOUS
       && !td->tags_count) {
        /* constructed ANY tag */
        size_t tag_len = rval.consumed;
        rval = bner_skip_construct(tag, buf_ptr, size);

        /*
         * If the structure is not there, allocate it.
         */
        if(st == NULL) {
            st = (ASN__PRIMITIVE_TYPE_t *)CALLOC(1, sizeof(*st));
            if(st == NULL) ASN__DECODE_FAILED;
            *sptr = (void *)st;
        }

        st->size = rval.consumed - tag_len * 2;
        st->buf = (uint8_t *)MALLOC(st->size + 1);
        if(!st->buf) {
            st->size = 0;
            ASN__DECODE_FAILED;
        }
        memcpy(st->buf, (const char *)buf_ptr + tag_len, st->size);
        ADVANCE(rval.consumed);
    } else {
        if(tag != ASN_TAG_AMBIGUOUS && !BER_TAGS_EQUAL(bner_tag.tag, tag)) {
            ASN_DEBUG("Expected tag: %s, but got: %s", ber_tlv_tag_string(tag),
                      bner_tag_lvt_string(&bner_tag));
            RETURN(RC_FAIL);
        }

        if(bner_tag.lvt_type == BNER_LVT_TYPE) {
            ASN_DEBUG("Unexpected construct tag: %s",
                      bner_tag_lvt_string(&bner_tag));
            RETURN(RC_FAIL);
        }

        /*
         * If the structure is not there, allocate it.
         */
        if(st == NULL) {
            st = (ASN__PRIMITIVE_TYPE_t *)CALLOC(1, sizeof(*st));
            if(st == NULL) ASN__DECODE_FAILED;
            *sptr = (void *)st;
        }

        st->size =
            (bner_tag.lvt_type == BNER_LVT_LENGTH ? bner_tag.u.length : 1);

        ADVANCE(rval.consumed);

        st->buf = (uint8_t *)MALLOC(st->size + 1);
        if(!st->buf) {
            st->size = 0;
            ASN__DECODE_FAILED;
        }

        if(bner_tag.lvt_type != BNER_LVT_VALUE) {
            memcpy(st->buf, buf_ptr, st->size);
            ADVANCE(st->size);
        } else {
            /* BNER_LVT_VALUE */
            st->buf[0] = bner_tag.u.value;
        }
    }
    st->buf[st->size] = '\0'; /* Just in case */

    ASN_DEBUG("Took %ld bytes to decode %s", (long)consumed_myself, td->name);

    RETURN(RC_OK);
}

/*
 * Encode an always-primitive type using BNER.
 */
asn_enc_rval_t
bner_encode_primitive(const asn_TYPE_descriptor_t *td, const void *sptr,
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
