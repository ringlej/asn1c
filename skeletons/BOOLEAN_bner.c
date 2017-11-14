#ifdef ASN_ENABLE_BNER_SUPPORT

#include <asn_internal.h>
#include <BOOLEAN.h>

#undef	ADVANCE
#define	ADVANCE(num_bytes)	do {					\
		size_t num = num_bytes;					\
		ptr = ((const char *)ptr) + num;			\
		size -= num;						\
		consumed_myself += num;					\
	} while(0)
#undef	RETURN
#define	RETURN(_code)	do {						\
		asn_dec_rval_t rval;					\
		rval.code = _code;					\
		if(opt_ctx) opt_ctx->step = step; /* Save context */	\
		if(_code == RC_OK || opt_ctx)				\
			rval.consumed = consumed_myself;		\
		else							\
			rval.consumed = 0;	/* Context-free */	\
		return rval;						\
	} while(0)

/*
 * Decode BOOLEAN type.
 */
asn_dec_rval_t
BOOLEAN_decode_bner(const asn_codec_ctx_t *opt_codec_ctx,
                    const asn_TYPE_descriptor_t *td,
                    void **bool_value, const void *buf_ptr, size_t size,
                    ber_tlv_tag_t tag, int tag_mode)
{
	BOOLEAN_t *st = (BOOLEAN_t *)*bool_value;
	asn_dec_rval_t rval;
	bner_tag_lvt_t tag_lvt;
	ssize_t length;

	if(st == NULL) {
		st = (BOOLEAN_t *)(*bool_value = CALLOC(1, sizeof(*st)));
		if(st == NULL) {
			rval.code = RC_FAIL;
			rval.consumed = 0;
			return rval;
		}
	}

	ASN_DEBUG("Decoding %s as BOOLEAN (tm=%d)",
		td->name, tag_mode);

	/*
	 * Check tags.
	 */
	rval = bner_check_tags(opt_codec_ctx, td, 0, buf_ptr, size,
	                       tag, tag_mode, &length, &tag_lvt, 0);
	if(rval.code != RC_OK)
		return rval;

	ASN_DEBUG("Boolean length is %d bytes", (int)length);

	buf_ptr = ((const char *)buf_ptr) + rval.consumed;
	size -= rval.consumed;

	switch (tag_lvt.lvt_type) {
	case BNER_LVT_LENGTH:
		if(tag_lvt.length > size) {
			rval.code = RC_WMORE;
			rval.consumed = 0;
			return rval;
		}
		*st = ((const uint8_t *)buf_ptr)[0];
		break;
	case BNER_LVT_VALUE:
		*st = tag_lvt.value;
		rval.consumed = 0;
		break;
	case BNER_LVT_TYPE:
	default:
		rval.code = RC_FAIL;
		if (!opt_codec_ctx)
			rval.consumed = 0;
		return rval;
	}

	rval.code = RC_OK;
	rval.consumed += length;

	ASN_DEBUG("Took %ld/%ld bytes to encode %s, value=%d",
		(long)rval.consumed, (long)length,
		td->name, *st);

	return rval;
}

asn_enc_rval_t
BOOLEAN_encode_bner(const asn_TYPE_descriptor_t *td, const void *sptr,
                    int tag_mode, ber_tlv_tag_t tag,
                    asn_app_consume_bytes_f *cb, void *app_key)
{
	bner_tag_lvt_t bner_tag;
	asn_enc_rval_t erval;
	BOOLEAN_t *st = (BOOLEAN_t *)sptr;

	bner_tag.tag = convert_ber_to_bner_tag(tag);

	if (BER_TAG_CLASS(bner_tag.tag) == ASN_TAG_CLASS_APPLICATION) {
		bner_tag.lvt_type = BNER_LVT_VALUE;
		bner_tag.value = *st ? BNER_TRUE : BNER_FALSE;
	} else {
		bner_tag.lvt_type = BNER_LVT_LENGTH;
		bner_tag.length = 1;
	}

	ASN_DEBUG("%s %s as a BOOLEAN type (tm=%d)",
		cb?"Encoding":"Estimating", td->name, tag_mode);

	erval.encoded = bner_write_tags(td, 1, tag_mode, 0, bner_tag, cb, app_key);
	ASN_DEBUG("%s wrote tags %d", td->name, (int)erval.encoded);
	if(erval.encoded == -1) {
		erval.failed_type = td;
		erval.structure_ptr = sptr;
		return erval;
	}

	if(cb && bner_tag.lvt_type == BNER_LVT_LENGTH) {
		uint8_t bool_value;

		bool_value = *st ? BNER_TRUE : BNER_FALSE;

		if(cb(&bool_value, 1, app_key) < 0) {
			erval.encoded = -1;
			erval.failed_type = td;
			erval.structure_ptr = sptr;
			return erval;
		}
		erval.encoded++;
	}

	ASN__ENCODED_OK(erval);
}

#endif
