/*
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info> and contributors.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_SEQUENCE_OF.h>
#include <asn_internal.h>
#include <constr_SEQUENCE_OF.h>

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
SEQUENCE_OF_decode_bner(const asn_codec_ctx_t *opt_codec_ctx,
                        const asn_TYPE_descriptor_t *td, void **struct_ptr,
                        const void *buf_ptr, size_t size, ber_tlv_tag_t tag,
                        int tag_mode) {
    const asn_SET_OF_specifics_t *specs =
        (const asn_SET_OF_specifics_t *)td->specifics;
    asn_TYPE_member_t *elm = td->elements; /* Single one */

    void *st = *struct_ptr;           /* Target structure. */
    asn_struct_ctx_t *ctx;            /* Decoder context */
    asn_dec_rval_t rval = {RC_OK, 0}; /* Return code from subparsers */
    ssize_t consumed_myself = 0;      /* Consumed bytes from ptr */
    bner_tag_lvt_t bner_tag;

    assert(td->tags_count);

    /*
     * Create the target structure if it is not present already.
     */
    if(st == 0) {
        st = *struct_ptr = CALLOC(1, specs->struct_size);
        if(st == 0) {
            RETURN(RC_FAIL);
        }
    }

    ctx = (asn_struct_ctx_t *)((char *)st + specs->ctx_offset);

    ASN_DEBUG("Decoding %s as SEQUENCE OF", td->name);

    if(BER_TAG_CLASS(tag) == ASN_TAG_CLASS_CONTEXT) {
        rval = bner_fetch_tag_lvt(buf_ptr, size, &bner_tag);

        if(is_bner_opening_tag_match(bner_tag, tag)) {
            ADVANCE(rval.consumed);
        } else {
            ASN_DEBUG("Expected Opening tag %s, but got %s",
                      ber_tlv_tag_string(tag), bner_tag_lvt_string(&bner_tag));
            RETURN(RC_FAIL);
        }
    }

    while(size > 0) {
        if(BER_TAG_CLASS(tag) == ASN_TAG_CLASS_CONTEXT) {
            /* Peek to see if we've reached an expected closing tag */
            rval = bner_fetch_tag_lvt(buf_ptr, size, &bner_tag);

            if(is_bner_closing_tag_match(bner_tag, tag)) {
                ADVANCE(rval.consumed);
                RETURN(RC_OK);
            } else if(rval.code != RC_OK) {
                ASN_STRUCT_FREE(*elm->type, ctx->ptr);
                ctx->ptr = 0;
                RETURN(RC_FAIL);
            }
        }

        /*
         * Invoke the member fetch routine according to member's type
         */
        rval = elm->type->op->bner_decoder(opt_codec_ctx, elm->type, &ctx->ptr,
                                           buf_ptr, size, tag, tag_mode);

        ASN_DEBUG("In %s SEQUENCE OF %s code %d consumed %d", td->name,
                  elm->type->name, rval.code, (int)rval.consumed);
        switch(rval.code) {
        case RC_OK: {
            asn_anonymous_set_ *list = _A_SET_FROM_VOID(st);
            if(ASN_SET_ADD(list, ctx->ptr) != 0)
                RETURN(RC_FAIL);
            else
                ctx->ptr = 0;
        } break;
        case RC_WMORE:
            ASN_STRUCT_FREE(*elm->type, ctx->ptr);
            ctx->ptr = 0;
            RETURN(RC_FAIL);
        case RC_FAIL:
            /* This is only a failure if we're expecting a closing tag */
            if(BER_TAG_CLASS(tag) == ASN_TAG_CLASS_CONTEXT) {
                ASN_STRUCT_FREE(*elm->type, ctx->ptr);
                ctx->ptr = 0;
                RETURN(RC_FAIL);
            }
            break;
        }

        ADVANCE(rval.consumed);
    }

    RETURN(RC_OK);
}

asn_enc_rval_t
SEQUENCE_OF_encode_bner(const asn_TYPE_descriptor_t *td, const void *sptr,
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
