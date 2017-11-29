/*
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info> and contributors.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_CHOICE.h>

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

static void
_set_present_idx(void *struct_ptr, unsigned pres_offset, unsigned pres_size,
                 unsigned present) {
    void *present_ptr;
    present_ptr = ((char *)struct_ptr) + pres_offset;

    switch(pres_size) {
    case sizeof(int):
        *(unsigned int *)present_ptr = present;
        break;
    case sizeof(short):
        *(unsigned short *)present_ptr = present;
        break;
    case sizeof(char):
        *(unsigned char *)present_ptr = present;
        break;
    default:
        /* ANSI C mandates enum to be equivalent to integer */
        assert(pres_size != sizeof(int));
    }
}

/*
 * Tags are canonically sorted in the tag to member table.
 */
static int
_search4bnertag(const void *ap, const void *bp) {
    const asn_TYPE_tag2member_t *a = (const asn_TYPE_tag2member_t *)ap;
    const asn_TYPE_tag2member_t *b = (const asn_TYPE_tag2member_t *)bp;

    ber_tlv_tag_t a_tag = convert_ber_to_bner_tag(a->el_tag);
    ber_tlv_tag_t b_tag = convert_ber_to_bner_tag(b->el_tag);

    int a_class = BER_TAG_CLASS(a_tag);
    int b_class = BER_TAG_CLASS(b_tag);

    if(a_class == b_class) {
        ber_tlv_tag_t a_value = BER_TAG_VALUE(a_tag);
        ber_tlv_tag_t b_value = BER_TAG_VALUE(b_tag);

        if(a_value == b_value)
            return 0;
        else if(a_value < b_value)
            return -1;
        else
            return 1;
    } else if(a_class < b_class) {
        return -1;
    } else {
        return 1;
    }
}

asn_dec_rval_t
CHOICE_decode_bner(const asn_codec_ctx_t *opt_codec_ctx,
                   const asn_TYPE_descriptor_t *td, void **struct_ptr,
                   const void *buf_ptr, size_t size, ber_tlv_tag_t tag,
                   int tag_mode) {
    (void)opt_codec_ctx;
    (void)tag;
    (void)tag_mode;

    const asn_CHOICE_specifics_t *specs =
        (const asn_CHOICE_specifics_t *)td->specifics;
    asn_TYPE_member_t *elements = td->elements;

    /*
     * Parts of the structure being constructed.
     */
    void *st = *struct_ptr;           /* Target structure. */
    asn_dec_rval_t rval = {RC_OK, 0}; /* Return code from subparsers */
    ssize_t consumed_myself = 0;      /* Consumed bytes from ptr */
    bner_tag_lvt_t bner_tag;
    const asn_TYPE_tag2member_t *t2m;
    asn_TYPE_tag2member_t key;

    ASN_DEBUG("Decoding %s as CHOICE", td->name);

    /*
     * Create the target structure if it is not present already.
     */
    if(st == 0) {
        st = *struct_ptr = CALLOC(1, specs->struct_size);
        if(st == 0) {
            RETURN(RC_FAIL);
        }
    }

    rval = bner_fetch_tag_lvt(buf_ptr, size, &bner_tag);
    ASN_DEBUG("In %s CHOICE tag: %s", td->name, bner_tag_lvt_string(&bner_tag));

    key.el_tag = bner_tag.tag;
    t2m = (const asn_TYPE_tag2member_t *)bsearch(
        &key, specs->tag2el, specs->tag2el_count, sizeof(specs->tag2el[0]),
        _search4bnertag);

    if(t2m) {
        /*
         * Found the element corresponding to the tag.
         */
        asn_TYPE_member_t *elm = &elements[t2m->el_no]; /* CHOICE's element */
        void *memb_ptr;   /* Pointer to the member */
        void **memb_ptr2; /* Pointer to that pointer */

        /*
         * Compute the position of the member inside a structure,
         * and also a type of containment (it may be contained
         * as pointer or using inline inclusion).
         */
        if(elm->flags & ATF_POINTER) {
            /* Member is a pointer to another structure */
            memb_ptr2 = (void **)((char *)st + elm->memb_offset);
        } else {
            /*
             * A pointer to a pointer
             * holding the start of the structure
             */
            memb_ptr = (char *)st + elm->memb_offset;
            memb_ptr2 = &memb_ptr;
        }
        /* Set presence to be able to free it properly at any time */
        _set_present_idx(st, specs->pres_offset, specs->pres_size,
                         t2m->el_no + 1);

        if(is_bner_opening_tag(bner_tag)) {
            ADVANCE(rval.consumed);
        }
        /*
         * Invoke the member fetch routine according to member's type
         */
        rval =
            elm->type->op->bner_decoder(opt_codec_ctx, elm->type, memb_ptr2,
                                        buf_ptr, size, elm->tag, elm->tag_mode);

        if(rval.code != RC_OK) RETURN(RC_FAIL);

        ADVANCE(rval.consumed);

        if(is_bner_opening_tag(bner_tag)) {
            ber_tlv_tag_t expected_closing_tag = bner_tag.tag;
            rval = bner_fetch_tag_lvt(buf_ptr, size, &bner_tag);
            if(rval.code != RC_OK
               && !is_bner_closing_tag_match(bner_tag, expected_closing_tag))
                RETURN(RC_FAIL);
            ADVANCE(rval.consumed);
        }
    } else if(specs->ext_start == -1) {
        ASN_DEBUG("Unexpected tag %s in non-extensible CHOICE %s",
                  bner_tag_lvt_string(&bner_tag), td->name);
        RETURN(RC_FAIL);
    } else {
        /* Skip this tag */
        ASN_DEBUG("Skipping unknown tag %s", bner_tag_lvt_string(&bner_tag));

        if(is_bner_opening_tag(bner_tag)) {
            rval = bner_skip_construct(bner_tag.tag, buf_ptr, size);
            if(rval.code != RC_OK) return rval;
        }

        ADVANCE(rval.consumed + (bner_tag.lvt_type == BNER_LVT_LENGTH
                                     ? bner_tag.u.length
                                     : 0));
    }

    RETURN(RC_OK);
}

asn_enc_rval_t
CHOICE_encode_bner(const asn_TYPE_descriptor_t *td, const void *sptr,
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
