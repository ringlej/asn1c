/*-
 * Copyright (c) 2003, 2004, 2006 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_SEQUENCE_OF.h>
#include <asn_SEQUENCE_OF.h>

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
#undef	ADVANCE
#define	ADVANCE(num_bytes)	do {		\
		size_t num = num_bytes;		\
		ptr = ((const char *)ptr) + num;\
		size -= num;			\
		if(ctx->left >= 0)		\
			ctx->left -= num;	\
		consumed_myself += num;		\
	} while(0)

/*
 * Switch to the next phase of parsing.
 */
#undef	NEXT_PHASE
#undef	PHASE_OUT
#define	NEXT_PHASE(ctx)	do {			\
		ctx->phase++;			\
		ctx->step = 0;			\
	} while(0)
#define	PHASE_OUT(ctx)	do { ctx->phase = 10; } while(0)

/*
 * Return a standardized complex structure.
 */
#undef	RETURN
#define	RETURN(_code)	do {			\
		rval.code = _code;		\
		rval.consumed = consumed_myself;\
		return rval;			\
	} while(0)

/*
 * The decoder of the SET OF type.
 */
asn_dec_rval_t
SEQUENCE_OF_decode_bner(const asn_codec_ctx_t *opt_codec_ctx,
                        const asn_TYPE_descriptor_t *td,
                        void **struct_ptr, const void *ptr, size_t size,
                        ber_tlv_tag_t tag, int tag_mode)
{
	/*
	 * Bring closer parts of structure description.
	 */
	const asn_SET_OF_specifics_t *specs = (const asn_SET_OF_specifics_t *)td->specifics;
	asn_TYPE_member_t *elm = td->elements;	/* Single one */

	/*
	 * Parts of the structure being constructed.
	 */
	void *st = *struct_ptr;	/* Target structure. */
	asn_struct_ctx_t *ctx;	/* Decoder context */

	bner_tag_lvt_t tag_lvt;
	asn_dec_rval_t rval;	/* Return code from subparsers */

	ssize_t consumed_myself = 0;	/* Consumed bytes from ptr */
	int tags_decoded = 0;

	ASN_DEBUG("Decoding %s as SET OF", td->name);

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

	while(size > 0) {
		rval = bner_check_tags(opt_codec_ctx, td, ctx, ptr, size,
		                       tag, tag_mode, &ctx->left, &tag_lvt, 0);
		ASN_DEBUG("%s", bner_tag_lvt_string(&tag_lvt));

		if(rval.code != RC_OK) {
			if (td->tags_count && BER_TAG_CLASS(td->tags[0]) == ASN_TAG_CLASS_CONTEXT)
			{
				// We should never get here if closing tag is expected
				ASN_DEBUG("%s tagging check failed: %d",
					td->name, rval.code);
				return rval;
			} else {
				// If we are not expecting a closing tag, then an unexpected tag
				// just means that we have reached the end of the sequence of
				ASN_DEBUG("%s non-context end found", td->name);
				RETURN(RC_OK);
			}
		}

		++tags_decoded;

		// We need further validation to see if the tag is really expected...

		if (td->tags_count && BER_TAG_CLASS(td->tags[0]) == ASN_TAG_CLASS_CONTEXT) {
			// Opening/Closing tags expected...
			if (tag_lvt.lvt_type == BNER_LVT_TYPE) {
				// Received an opening or closing tag
				switch (tag_lvt.type) {
				case BNER_OPENING_TAG:
					if (tags_decoded == 1) {
						// Received expected opening tag. Advance past it and continue
						ADVANCE(rval.consumed);
						continue;
					} else {
						// Received unexpected opening tag. Failing...
						RETURN(RC_FAIL);
					}
					break;
				case BNER_CLOSING_TAG:
					if (tags_decoded > 1) {
						// Received expected closing tag. Advance past it and return
						ADVANCE(rval.consumed);
						RETURN(RC_OK);
					} else {
						// Received unexpected closing tag. Failing...
						RETURN(RC_FAIL);
					}
					break;
				}
			} else {
				// Only expecting data after an opening tag
				if (tags_decoded == 1) {
					RETURN(RC_FAIL);
				}
			}
		}

		/*
		 * Invoke the member fetch routine according to member's type
		 */
		rval = elm->type->op->bner_decoder(opt_codec_ctx,
										   elm->type, &ctx->ptr, ptr, LEFT, tag, tag_mode);
		ASN_DEBUG("In %s SET OF %s code %d consumed %d",
				  td->name, elm->type->name,
				  rval.code, (int)rval.consumed);
		switch(rval.code) {
		case RC_OK:
		{
			asn_anonymous_set_ *list = _A_SET_FROM_VOID(st);
			if(ASN_SET_ADD(list, ctx->ptr) != 0)
				RETURN(RC_FAIL);
			else
				ctx->ptr = 0;
		}
			break;
		case RC_WMORE: /* More data expected */
			if(!SIZE_VIOLATION) {
				ADVANCE(rval.consumed);
				RETURN(RC_WMORE);
			}
			/* Fall through */
		case RC_FAIL: /* Fatal error */
			ASN_STRUCT_FREE(*elm->type, ctx->ptr);
			ctx->ptr = 0;
			RETURN(RC_FAIL);
		} /* switch(rval) */

		//if (ctx->left < rval.consumed)
		//	ctx->left = size;
		ADVANCE(rval.consumed);
	}

	RETURN(RC_OK);
}

/*
 * The BNER encoder of the SEQUENCE OF type.
 */
asn_enc_rval_t
SEQUENCE_OF_encode_bner(const asn_TYPE_descriptor_t *td, const void *ptr,
                        int tag_mode, ber_tlv_tag_t tag,
                        asn_app_consume_bytes_f *cb, void *app_key) {
	bner_tag_lvt_t bner_tag;
	asn_TYPE_member_t *elm = td->elements;
	asn_anonymous_sequence_ *list = _A_SEQUENCE_FROM_VOID(ptr);
	size_t computed_size = 0;
	ssize_t encoding_size = 0;
	asn_enc_rval_t erval;
	int edx;

	bner_tag.tag = convert_ber_to_bner_tag(tag);
	bner_tag.lvt_type = BNER_LVT_TYPE;
	bner_tag.tag |= ASN_TAG_CLASS_CONTEXT;

	ASN_DEBUG("Estimating size of SEQUENCE OF %s", td->name);

	/*
	 * Gather the length of the underlying members sequence.
	 */
	if (BER_TAG_VALUE(bner_tag.tag) != 255) {
		bner_tag.type = BNER_OPENING_TAG;
		encoding_size = bner_write_tags(td, computed_size, tag_mode, 1, bner_tag,
		                                0, 0);
		if(encoding_size == -1) {
			erval.encoded = -1;
			erval.failed_type = td;
			erval.structure_ptr = ptr;
			return erval;
		}

		computed_size += encoding_size;
	}
	for(edx = 0; edx < list->count; edx++) {
		void *memb_ptr = list->array[edx];
		if(!memb_ptr) continue;
		erval = elm->type->op->bner_encoder(elm->type, memb_ptr,
			0, elm->tag,
			0, 0);
		if(erval.encoded == -1)
			return erval;
		computed_size += erval.encoded;
	}
	if (BER_TAG_VALUE(bner_tag.tag) != 255) {
		bner_tag.type = BNER_CLOSING_TAG;
		encoding_size = bner_write_tags(td, computed_size, tag_mode, 1, bner_tag,
		                                0, 0);
		if(encoding_size == -1) {
			erval.encoded = -1;
			erval.failed_type = td;
			erval.structure_ptr = ptr;
			return erval;
		}

		computed_size += encoding_size;
	}

	ASN_DEBUG("Encoding members of SEQUENCE OF %s", td->name);

	if (BER_TAG_VALUE(bner_tag.tag) != 255) {
		/*
		 * Encode the Opening tag
		 */
		bner_tag.type = BNER_OPENING_TAG;
		encoding_size = bner_write_tags(td, computed_size, tag_mode, 1, bner_tag,
		                                cb, app_key);
		if(encoding_size == -1) {
			erval.encoded = -1;
			erval.failed_type = td;
			erval.structure_ptr = ptr;
			return erval;
		}
	}

	/*
	 * Encode all members.
	 */
	for(edx = 0; edx < list->count; edx++) {
		void *memb_ptr = list->array[edx];
		if(!memb_ptr) continue;
		erval = elm->type->op->bner_encoder(elm->type, memb_ptr,
			0, elm->tag,
			cb, app_key);
		if(erval.encoded == -1)
			return erval;
		encoding_size += erval.encoded;
	}

	if (BER_TAG_VALUE(bner_tag.tag) != 255) {
		bner_tag.type = BNER_CLOSING_TAG;
		encoding_size += bner_write_tags(td, computed_size, tag_mode, 1, bner_tag,
		                                 cb, app_key);
		if(encoding_size == -1) {
			erval.encoded = -1;
			erval.failed_type = td;
			erval.structure_ptr = ptr;
			return erval;
		}
	}
	if(computed_size != (size_t)encoding_size) {
		/*
		 * Encoded size is not equal to the computed size.
		 */
		erval.encoded = -1;
		erval.failed_type = td;
		erval.structure_ptr = ptr;
	} else {
		erval.encoded = computed_size;
		erval.structure_ptr = 0;
		erval.failed_type = 0;
	}

	return erval;
}
