/*
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info> and contributors.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_SEQUENCE.h>

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
SEQUENCE_decode_bner(const asn_codec_ctx_t *opt_codec_ctx,
                     const asn_TYPE_descriptor_t *td, void **struct_ptr,
                     const void *buf_ptr, size_t size, ber_tlv_tag_t tag,
                     int tag_mode) {
    const asn_SEQUENCE_specifics_t *specs =
        (const asn_SEQUENCE_specifics_t *)td->specifics;
    asn_dec_rval_t rval = {RC_OK, 0};
    void *st = *struct_ptr; /* Target structure */
    asn_TYPE_member_t *elements = td->elements;
    size_t consumed_myself = 0; /* Consumed bytes from ptr. */
    size_t edx;                 /* SEQUENCE element's index */

    (void)tag;
    (void)tag_mode;

    /*
     * Create the target structure if it is not present already.
     */
    if(st == 0) {
        st = *struct_ptr = CALLOC(1, specs->struct_size);
        if(st == 0) {
            RETURN(RC_FAIL);
        }
    }

    for(edx = 0; edx < td->elements_count; ++edx) {
        void *memb_ptr;   /* Pointer to the member */
        void **memb_ptr2; /* Pointer to that pointer */

        /*
         * Compute the position of the member inside a structure,
         * and also a type of containment (it may be contained
         * as pointer or using inline inclusion).
         */
        if(elements[edx].flags & ATF_POINTER) {
            /* Member is a pointer to another structure */
            memb_ptr2 = (void **)((char *)st + elements[edx].memb_offset);
        } else {
            /*
             * A pointer to a pointer
             * holding the start of the structure
             */
            memb_ptr = (char *)st + elements[edx].memb_offset;
            memb_ptr2 = &memb_ptr;
        }

        rval = elements[edx].type->op->bner_decoder(
            opt_codec_ctx, elements[edx].type, memb_ptr2, buf_ptr, size,
            convert_ber_to_bner_tag(elements[edx].tag), elements[edx].tag_mode);

        ASN_DEBUG(
            "In %s SEQUENCE decoded %zu %s of %d in %d bytes rval.code %d",
            td->name, edx, elements[edx].type->name, (int)size,
            (int)rval.consumed, rval.code);

        if(rval.code != RC_OK) {
            if(elements[edx].optional) continue;

            RETURN(RC_FAIL);
        }

        ADVANCE(rval.consumed);
    }

    RETURN(RC_OK);
}

asn_enc_rval_t
SEQUENCE_encode_bner(const asn_TYPE_descriptor_t *td, const void *sptr,
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
