#include <asn_internal.h>
#include <constr_SEQUENCE.h>
#include <OPEN_TYPE.h>
#include <errno.h>

/*
 * Number of bytes left for this structure.
 * (ctx->left) indicates the number of bytes _transferred_ for the structure.
 * (size) contains the number of bytes in the buffer passed.
 */
#define	LEFT	((size>(size_t)ctx->left)?size:(size_t)ctx->left)

/*
 * If the subprocessor function returns with an indication that it wants
 * more data, it may well be a fatal decoding problem, because the
 * size is constrained by the <TLV>'s L, even if the buffer size allows
 * reading more data.
 * For example, consider the buffer containing the following TLVs:
 * <T:5><L:1><V> <T:6>...
 * The TLV length clearly indicates that one byte is expected in V, but
 * if the V processor returns with "want more data" even if the buffer
 * contains way more data than the V processor have seen.
 */
#define	SIZE_VIOLATION	(ctx->left >= 0 && (size_t)ctx->left <= size)

/*
 * This macro "eats" the part of the buffer which is definitely "consumed",
 * i.e. was correctly converted into local representation or rightfully skipped.
 */
#undef  ADVANCE
#define ADVANCE(num_bytes)                   \
    do {                                     \
        size_t num = num_bytes;              \
        ptr = ((const char *)ptr) + num;     \
        size -= num;                         \
        consumed_myself += num;              \
    } while(0)

/*
 * Switch to the next phase of parsing.
 */
#undef  NEXT_PHASE
#undef PHASE_OUT
#define NEXT_PHASE(ctx) \
    do {                \
        ctx->phase++;   \
        ctx->step = 0;  \
    } while(0)

/*
 * Check whether we are inside the extensions group.
 */
#define IN_EXTENSION_GROUP(specs, memb_idx)     \
        ( (((ssize_t)(memb_idx)) > (specs)->ext_after)     \
        &&(((ssize_t)(memb_idx)) < (specs)->ext_before))

/*
 * Return a standardized complex structure.
 */
#undef  RETURN
#define RETURN(_code)   do {                    \
                rval.code = _code;              \
                rval.consumed = consumed_myself;\
                return rval;                    \
        } while(0)

/*
 * Return pointer to a member.
 */
static void **
element_ptrptr(void *struct_ptr, asn_TYPE_member_t *elm, void **tmp_save_ptr) {
    if(elm->flags & ATF_POINTER) {
        /* Member is a pointer to another structure */
        return (void **)((char *)struct_ptr + elm->memb_offset);
    } else {
        assert(tmp_save_ptr);
        *tmp_save_ptr = (void *)((char *)struct_ptr + elm->memb_offset);
        return tmp_save_ptr;
    }
}

static void *element_ptr(void *struct_ptr, asn_TYPE_member_t *elm) {
    if(elm->flags & ATF_POINTER) {
        /* Member is a pointer to another structure */
        return *(void **)((char *)struct_ptr + elm->memb_offset);
    } else {
        return (void *)((char *)struct_ptr + elm->memb_offset);
    }
}

asn_dec_rval_t
SEQUENCE_decode_bner(const asn_codec_ctx_t *opt_codec_ctx,
                     const asn_TYPE_descriptor_t *td,
                     void **struct_ptr, const void *ptr, size_t size,
                     ber_tlv_tag_t tag, int tag_mode)
{
    asn_SEQUENCE_specifics_t *specs = (asn_SEQUENCE_specifics_t *)td->specifics;
    asn_dec_rval_t rval = {RC_OK, 0};
    void *st = *struct_ptr; /* Target structure */
    asn_TYPE_member_t *elements = td->elements;
    asn_struct_ctx_t *ctx; /* Decoder context */
    size_t consumed_myself = 0; /* Consumed bytes from ptr. */
    size_t edx;                 /* SEQUENCE element's index */


    (void)opt_codec_ctx;
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

    /*
     * Restore parsing context.
     */
    ctx = (asn_struct_ctx_t *)((char *)st + specs->ctx_offset);
    if(ctx->ptr == 0) {
        ctx->ptr = CALLOC(1, sizeof(asn_bit_data_t));
        if(!ctx->ptr) {
            RETURN(RC_FAIL);
        }
    }

    for (edx = 0; edx < td->elements_count; edx++) {
	    void *memb_ptr;		/* Pointer to the member */
	    void **memb_ptr2;	/* Pointer to that pointer */

		bner_tag_lvt_t tag_lvt;
		ssize_t tag_len = bner_fetch_tag_lvt(ptr, LEFT, &tag_lvt);
		if (!tag_len
		    || (tag_len > 0
				&& !BER_TAGS_EQUAL(tag_lvt.tag, convert_ber_to_bner_tag(elements[edx].tag))
				&& elements[edx].optional)) {
			continue;
		}

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
	    rval = elements[edx].type->op->bner_decoder(opt_codec_ctx,
	                                                elements[edx].type,
	                                                memb_ptr2, ptr, LEFT,
	                                                elements[edx].tag,
	                                                elements[edx].tag_mode);

	    ASN_DEBUG("In %s SEQUENCE decoded %zu %s of %d "
		    "in %d bytes rval.code %d, size=%d",
		    td->name, edx, elements[edx].type->name,
		    (int)LEFT, (int)rval.consumed, rval.code, (int)size);
	    switch(rval.code) {
	    case RC_OK:
		    break;
	    case RC_WMORE: /* More data expected */
		    //if(!SIZE_VIOLATION) {
			    ADVANCE(rval.consumed);
			    RETURN(RC_WMORE);
		    //}
		    //ASN_DEBUG("Size violation (c->l=%ld <= s=%ld)",
			//    (long)ctx->left, (long)size);
		    /* Fall through */
	    case RC_FAIL: /* Fatal error */
			if (elements[edx].optional) {
				continue;
			}
		    RETURN(RC_FAIL);
	    } /* switch(rval) */

	    ADVANCE(rval.consumed);
    }

    RETURN(RC_OK);
}

/*
 * Encode as BNER.
 */
asn_enc_rval_t
SEQUENCE_encode_bner(const asn_TYPE_descriptor_t *td, const void *sptr,
                     int tag_mode, ber_tlv_tag_t tag,
                     asn_app_consume_bytes_f *cb, void *app_key) {
	bner_tag_lvt_t bner_tag;
	size_t computed_size = 0;
	asn_enc_rval_t erval;
	ssize_t ret;
	size_t edx;

	bner_tag.tag = convert_ber_to_bner_tag(tag);
	bner_tag.lvt_type = BNER_LVT_TYPE;
	bner_tag.tag |= ASN_TAG_CLASS_CONTEXT;

	ASN_DEBUG("%s %s as SEQUENCE",
		cb?"Encoding":"Estimating", td->name);

	/*
	 * Gather the length of the underlying members sequence.
	 */
	if (BER_TAG_VALUE(bner_tag.tag) != 255)	{
		bner_tag.type = BNER_OPENING_TAG;

		ret = bner_write_tags(td, computed_size, tag_mode, 1, bner_tag, 0, 0);
		if(ret == -1)
			ASN__ENCODE_FAILED;
		computed_size += ret;
	}
	for(edx = 0; edx < td->elements_count; edx++) {
		asn_TYPE_member_t *elm = &td->elements[edx];

		void *memb_ptr;		/* Pointer to the member */
		void **memb_ptr2;	/* Pointer to that pointer */

		if(elm->flags & ATF_POINTER) {
			memb_ptr2 = (void **)((char *)sptr + elm->memb_offset);
			if(!*memb_ptr2) {
				ASN_DEBUG("Element %s %zu not present",
					elm->name, edx);
				if(elm->optional)
					continue;
				/* Mandatory element is missing */
				ASN__ENCODE_FAILED;
			}
		} else {
			memb_ptr = (void *)((char *)sptr + elm->memb_offset);
			memb_ptr2 = &memb_ptr;
		}

		/* Eliminate default values */
		if(elm->default_value_cmp && elm->default_value_cmp(*memb_ptr2) == 0)
			continue;

		erval = elm->type->op->bner_encoder(elm->type, *memb_ptr2,
			elm->tag_mode, elm->tag,
			0, 0);
		if(erval.encoded == -1)
			return erval;
		computed_size += erval.encoded;
		ASN_DEBUG("Member %zu %s estimated %ld bytes",
			edx, elm->name, (long)erval.encoded);
	}
	if (BER_TAG_VALUE(bner_tag.tag) != 255)	{
		bner_tag.type = BNER_CLOSING_TAG;

		ret = bner_write_tags(td, computed_size, tag_mode, 1, bner_tag, 0, 0);
		if(ret == -1)
			ASN__ENCODE_FAILED;
		computed_size += ret;
	}

	erval.encoded = computed_size;

	if (!cb) {
		ASN__ENCODED_OK(erval);
	}

	/*
	 * Encode all members.
	 */
	if (BER_TAG_VALUE(bner_tag.tag) != 255)	{
		bner_tag.type = BNER_OPENING_TAG;

		/*
		 * Encode the TLV for the sequence itself.
		 */
		ret = bner_write_tags(td, computed_size, tag_mode, 1, bner_tag, cb, app_key);
		ASN_DEBUG("Wrote tags: %ld (+%ld)", (long)ret, (long)computed_size);
		if(ret == -1)
			ASN__ENCODE_FAILED;
		computed_size -= ret;

		if(!cb) ASN__ENCODED_OK(erval);
	}
	for(edx = 0; edx < td->elements_count; edx++) {
		asn_TYPE_member_t *elm = &td->elements[edx];
		asn_enc_rval_t tmperval;
		void *memb_ptr;		/* Pointer to the member */
		void **memb_ptr2;	/* Pointer to that pointer */

		if(elm->flags & ATF_POINTER) {
			memb_ptr2 = (void **)((char *)sptr + elm->memb_offset);
			if(!*memb_ptr2) continue;
		} else {
			memb_ptr = (void *)((char *)sptr + elm->memb_offset);
			memb_ptr2 = &memb_ptr;
		}

		/* Eliminate default values */
		if(elm->default_value_cmp && elm->default_value_cmp(*memb_ptr2) == 0)
			continue;

		tmperval = elm->type->op->bner_encoder(elm->type, *memb_ptr2,
		                                       elm->tag_mode, elm->tag, cb, app_key);
		if(tmperval.encoded == -1)
			return tmperval;
		computed_size -= tmperval.encoded;
		ASN_DEBUG("Member %zu %s of SEQUENCE %s encoded in %ld bytes",
		          edx, elm->name, td->name, (long)tmperval.encoded);
	}

	if (BER_TAG_VALUE(bner_tag.tag) != 255)	{
		bner_tag.type = BNER_CLOSING_TAG;

		/*
		 * Encode the TLV for the sequence itself.
		 */
		ret = bner_write_tags(td, computed_size, tag_mode, 1, bner_tag, cb, app_key);
		ASN_DEBUG("Wrote tags: %ld (+%ld)", (long)ret, (long)computed_size);
		if(ret == -1)
			ASN__ENCODE_FAILED;
		computed_size -= ret;

		if(!cb) ASN__ENCODED_OK(erval);
	}

	if(computed_size != 0)
		/*
		 * Encoded size is not equal to the computed size.
		 */
		ASN__ENCODE_FAILED;

	ASN__ENCODED_OK(erval);
}
