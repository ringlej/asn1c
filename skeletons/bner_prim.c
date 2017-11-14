#ifdef ASN_ENABLE_BNER_SUPPORT
#include <asn_internal.h>
#include <bner_prim.h>
#include <errno.h>

#undef	ADVANCE
#define	ADVANCE(num_bytes)	do {					\
		size_t num = num_bytes;					\
		ptr = ((const char *)ptr) + num;			\
		size -= num;						\
		consumed_myself += num;					\
	} while(0)

/*
 * Decode an always-primitive type.
 */
asn_dec_rval_t
bner_decode_primitive(const asn_codec_ctx_t *opt_codec_ctx,
                      const asn_TYPE_descriptor_t *td,
                      void **sptr, const void *buf_ptr, size_t size,
                      ber_tlv_tag_t tag, int tag_mode)
{
	ASN__PRIMITIVE_TYPE_t *st = (ASN__PRIMITIVE_TYPE_t *)*sptr;
	bner_tag_lvt_t tag_lvt;
	asn_dec_rval_t rval;
	ssize_t length = 0; /* =0 to avoid [incorrect] warning. */

	/*
	 * If the structure is not there, allocate it.
	 */
	if(st == NULL) {
		st = (ASN__PRIMITIVE_TYPE_t *)CALLOC(1, sizeof(*st));
		if(st == NULL) ASN__DECODE_FAILED;
		*sptr = (void *)st;
	}

	ASN_DEBUG("Decoding %s as plain primitive (tm=%d)",
		td->name, tag_mode);

	/*
	 * Check tags and extract value length.
	 */
	rval = bner_check_tags(opt_codec_ctx, td, 0, buf_ptr, size,
	                       tag, tag_mode, &length, &tag_lvt, 0);
	if(rval.code != RC_OK)
		return rval;

	if (tag_mode == 1 && is_bner_opening_tag(tag_lvt))
	{
		const void *buf = ((const char *)buf_ptr) + rval.consumed;
		size_t consumed = rval.consumed;
		buf_ptr = ((const char *)buf);
		size -= rval.consumed;

		ber_tlv_tag_t tag_match = tag_lvt.tag;

		do
		{
			buf = ((const char *)buf) + consumed;
			size -= consumed;
			if(length > (ber_tlv_len_t)size) {
				rval.code = RC_WMORE;
				rval.consumed = 0;
				return rval;
			}

			st->size += consumed;

			length = bner_fetch_tag_lvt(buf, size, &tag_lvt);
			switch (length) {
			case -1:
				rval.code = RC_FAIL;
				rval.consumed = 0;
				return rval;
			case 0:
				rval.code = RC_WMORE;
				rval.consumed = 0;
				return rval;
			}

			consumed = length;
			if (tag_lvt.lvt_type == BNER_LVT_LENGTH)
				consumed += tag_lvt.length;


		} while (!is_bner_closing_tag(tag_lvt, tag_match));

		rval.code = RC_OK;
		rval.consumed += st->size
		                + ((tag_lvt.lvt_type == BNER_LVT_LENGTH) ? tag_lvt.length : (int)length);
	}
	else
	{
		/*
		 * Make sure we have this length.
		 */
		buf_ptr = ((const char *)buf_ptr) + rval.consumed;
		size -= rval.consumed;
		if(length > (ber_tlv_len_t)size) {
			rval.code = RC_WMORE;
			rval.consumed = 0;
			return rval;
		}

		st->size += ((tag_lvt.lvt_type == BNER_LVT_LENGTH) ? tag_lvt.length : (int)length);

		rval.code = RC_OK;
		rval.consumed += st->size;
	}

	ASN_DEBUG("%s length is %d bytes", td->name, (int)st->size);

	/* The following better be optimized away. */
	if(sizeof(st->size) != sizeof(length)
			&& (ber_tlv_len_t)st->size != length) {
		st->size = 0;
		ASN__DECODE_FAILED;
	}

	st->buf = (uint8_t *)MALLOC(st->size + 1);
	if(!st->buf) {
		st->size = 0;
		ASN__DECODE_FAILED;
	}

	memcpy(st->buf, buf_ptr, st->size);
	st->buf[st->size] = '\0';		/* Just in case */

	ASN_DEBUG("Took %ld/%ld bytes to encode %s",
		(long)rval.consumed,
		(long)length, td->name);

	return rval;
}

/*
 * Encode an always-primitive type using BNER.
 */
asn_enc_rval_t
bner_encode_primitive(const asn_TYPE_descriptor_t *td, const void *sptr,
                      int tag_mode, ber_tlv_tag_t tag,
                      asn_app_consume_bytes_f *cb, void *app_key)
{
	bner_tag_lvt_t bner_tag;
	asn_enc_rval_t erval;
	ASN__PRIMITIVE_TYPE_t *st = (ASN__PRIMITIVE_TYPE_t *)sptr;

	bner_tag.tag = convert_ber_to_bner_tag(tag);
	bner_tag.lvt_type = BNER_LVT_LENGTH;
	bner_tag.length = st->size;

	ASN_DEBUG("%s %s as a primitive type (tm=%d) %s",
		cb?"Encoding":"Estimating", td->name, tag_mode, bner_tag_lvt_string(&bner_tag));

	erval.encoded = bner_write_tags(td, st->size, tag_mode, 0, bner_tag, cb, app_key);
	ASN_DEBUG("%s wrote tags %d", td->name, (int)erval.encoded);
	if(erval.encoded == -1) {
		erval.failed_type = td;
		erval.structure_ptr = sptr;
		return erval;
	}

	if(cb && st->buf) {
		if(cb(st->buf, st->size, app_key) < 0) {
			erval.encoded = -1;
			erval.failed_type = td;
			erval.structure_ptr = sptr;
			return erval;
		}
	} else {
		assert(st->buf || st->size == 0);
	}

	erval.encoded += st->size;
	ASN__ENCODED_OK(erval);
}
#endif
