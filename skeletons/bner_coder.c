#ifdef ASN_ENABLE_BNER_SUPPORT
#include <asn_internal.h>
#include <errno.h>
#include <regex.h>

static ssize_t bner_write_TL(bner_tag_lvt_t tag,
	asn_app_consume_bytes_f *cb, void *app_key, int constructed);

static int is_bner_pdu_regex_init = 0;
static regex_t bner_pdu_regex;

/*
 * BACnet defines two different encodings:
 * 1) Fixed encoding (Clause 20.1)
 * The fixed encoding is used on the following PDUs:
 *		BACnetPDU
 *		BACnet-Confirmed-Request-PDU
 *		BACnet-Unconfirmed-Request-PDU
 *		BACnet-SimpleACK-PDU
 *		BACnet-ComplexACK-PDU
 *		BACnet-SegmentACK-PDU
 *		BACnet-Error-PDU
 *		BACnet-Reject-PDU
 *		BACnet-Abort-PDU
 * These PDUs can be matched with the regular expression: "BACnet.*PDU"
 * The fixed encoding is outside the scope of the asn1 compiler, and
 * only a weak function that fails encoding/decoding these PDUs is provided here
 *
 * 2) Variable encoding (Clause 20.2)
 * All other BACnet rules are encoded with the BNER variable encoding.
 * This encoding is provided for in the asn1 compiler
 */

int init_bner(void)
{
	int ret = 0;
	if (!is_bner_pdu_regex_init)
	{
		ret = regcomp(&bner_pdu_regex, "BACnet.*PDU", 0);
		if (ret == 0)
			is_bner_pdu_regex_init = 1;
	}

	return ret;
}

void fini_bner(void)
{
	if (is_bner_pdu_regex_init)
		regfree(&bner_pdu_regex);
	is_bner_pdu_regex_init = 0;
}

static int is_bner_fixed_pdu(const char* pdu_type_name)
{
	init_bner();
	return (regexec(&bner_pdu_regex, pdu_type_name, 0, NULL, 0) == 0);
}

 __attribute__ ((weak))
asn_enc_rval_t bner_fixed_encoder(const struct asn_TYPE_descriptor_s *td,
								  const void *sptr,	/* Structure to be encoded */
								  asn_app_consume_bytes_f *consume_bytes_cb,
								  void *app_key		/* Arbitrary callback argument */
								  )
{
	ASN_DEBUG("Failed to decode %s. No bner_fixed_encoder function provided", td->name);
	ASN__ENCODE_FAILED;
}

/*
 * The BNER encoder of any type.
 */
asn_enc_rval_t
bner_encode(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_consume_bytes_f *consume_bytes, void *app_key)
{
	if (!td)
		ASN__ENCODE_FAILED;

	ASN_DEBUG("BNER encoder invoked for %s",
		td->name);

	if (is_bner_fixed_pdu(td->name))
	{
		return bner_fixed_encoder(td, sptr, consume_bytes, app_key);
	} else {
		/*
		 * Invoke type-specific encoder.
		 */
		return td->op->bner_encoder(td, sptr, 0, 0, consume_bytes, app_key);
	}
}

/*
 * Argument type and callback necessary for bner_encode_to_buffer().
 */
typedef struct enc_to_buf_arg {
	void *buffer;
	size_t left;
} enc_to_buf_arg;

static int encode_to_buffer_cb(const void *buffer, size_t size, void *key) {
	enc_to_buf_arg *arg = (enc_to_buf_arg *)key;

	if(arg->left < size)
		return -1;	/* Data exceeds the available buffer size */

	memcpy(arg->buffer, buffer, size);
	arg->buffer = ((char *)arg->buffer) + size;
	arg->left -= size;

	return 0;
}

/*
 * A variant of the bner_encode() which encodes the data into the provided buffer
 */
asn_enc_rval_t
bner_encode_to_buffer(const asn_TYPE_descriptor_t *type_descriptor,
					  const void *struct_ptr,
					  void *buffer, size_t buffer_size) {
	enc_to_buf_arg arg;
	asn_enc_rval_t ec;

	arg.buffer = buffer;
	arg.left = buffer_size;

	if (is_bner_fixed_pdu(type_descriptor->name))
	{
		ec = bner_fixed_encoder(type_descriptor, struct_ptr, encode_to_buffer_cb, &arg);
	} else {
		ec = type_descriptor->op->bner_encoder(type_descriptor,
											   struct_ptr,	/* Pointer to the destination structure */
											   0, 0, encode_to_buffer_cb, &arg);
	}

	if(ec.encoded != -1) {
		assert(ec.encoded == (ssize_t)(buffer_size - arg.left));
		/* Return the encoded contents size */
	}
	return ec;
}


/*
 * Write out leading TL[v] sequence according to the type definition.
 */
ssize_t
bner_write_tags(const asn_TYPE_descriptor_t *sd,
				size_t struct_length,
				int tag_mode, int last_tag_form,
				bner_tag_lvt_t tag_lvt,
				asn_app_consume_bytes_f *cb,
				void *app_key)
{
	const ber_tlv_tag_t *tags;	/* Copy of tags stream */
	int tags_count;			/* Number of tags */
	size_t overall_length;
	ssize_t *lens;
	int i;
	char tagbuf[sizeof("[APPLICATION ] ") + 32];
	ssize_t tmp;
	uint8_t buf[32];
	size_t size = 0;
	int buf_size = cb?sizeof(buf):0;

	bner_tag_lvt_snprint(&tag_lvt, tagbuf, sizeof(tagbuf));

	tmp = bner_tag_lvt_serialize(tag_lvt, buf, buf_size);
	if (tmp == -1) return -1;
	size += tmp;

	if (size > sizeof(buf))
		return -1;

	/*
	 * If callback is specified, invoke it, and check its return value.
	 */
	if(cb) {
		ASN_DEBUG("Writing tags (%s, tm=%d, tc=%d, tag_lvt=%s)",
		          sd->name, tag_mode, sd->tags_count, tagbuf);
		if(cb(buf, size, app_key) < 0)
			return -1;
	}

	return size;
}

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

 __attribute__ ((weak))
 asn_dec_rval_t bner_fixed_decoder(const struct asn_codec_ctx_s *opt_codec_ctx,
								  const struct asn_TYPE_descriptor_s *type_descriptor,
								  void **struct_ptr,	/* Pointer to a target structure's pointer */
								  const void *buffer,	/* Data to be decoded */
								  size_t size		/* Size of that buffer */
								  )
{
	asn_dec_rval_t tmp_error = { RC_FAIL, 0 };
	ASN_DEBUG("Failed to decode %s. No bner_fixed_decoder function provided", type_descriptor->name);
	return tmp_error;
}

/*
 * The BNER decoder of any type.
 */
asn_dec_rval_t
bner_decode(const asn_codec_ctx_t *opt_codec_ctx,
			const asn_TYPE_descriptor_t *type_descriptor, void **struct_ptr,
			const void *ptr, size_t size)
{
	asn_codec_ctx_t s_codec_ctx;

	if (!type_descriptor)
	{
		asn_dec_rval_t tmp_error = { RC_FAIL, 0 };
		ASN_DEBUG("%s: Failed to decode. type_descriptor NULL", __func__);
		return tmp_error;
	}

	/*
	 * Stack checker requires that the codec context
	 * must be allocated on the stack.
	 */
	if(opt_codec_ctx) {
		if(opt_codec_ctx->max_stack_size) {
			s_codec_ctx = *opt_codec_ctx;
			opt_codec_ctx = &s_codec_ctx;
		}
	} else {
		/* If context is not given, be security-conscious anyway */
		memset(&s_codec_ctx, 0, sizeof(s_codec_ctx));
		s_codec_ctx.max_stack_size = ASN__DEFAULT_STACK_MAX;
		opt_codec_ctx = &s_codec_ctx;
	}

	if (is_bner_fixed_pdu(type_descriptor->name))
	{
		return bner_fixed_decoder(opt_codec_ctx, type_descriptor,
		                          struct_ptr,	/* Pointer to the destination structure */
                                  ptr, size	/* Buffer and its size */
                                  );
	} else {
		/*
		 * Invoke type-specific decoder.
		 */
		return type_descriptor->op->bner_decoder(opt_codec_ctx, type_descriptor,
												 struct_ptr,	/* Pointer to the destination structure */
												 ptr, size,	/* Buffer and its size */
												 0, 0		/* Default tag mode is 0 */
												 );
	}
}

/*
 * Check the set of <TL<TL<TL...>>> tags matches the definition.
 */
asn_dec_rval_t
bner_check_tags(const asn_codec_ctx_t *opt_codec_ctx,
                const asn_TYPE_descriptor_t *td, asn_struct_ctx_t *opt_ctx,
                const void *ptr, size_t size,
                ber_tlv_tag_t tag, int tag_mode,
                ssize_t *length, bner_tag_lvt_t *last_tag, int *opt_tlv_form)
{
	ssize_t consumed_myself = 0;
	ssize_t tag_len;
	ssize_t limit_len = -1;
	bner_tag_lvt_t tag_lvt;

	int tlv_constr = -1;	/* If CHOICE, opt_tlv_form is not given */
	int step = opt_ctx ? opt_ctx->step : 0;	/* Where we left previously */
	int tagno;

	/*
	 * Make sure we didn't exceed the maximum stack size.
	 */
	if(ASN__STACK_OVERFLOW_CHECK(opt_codec_ctx))
		RETURN(RC_FAIL);

	tagno = step	/* Continuing where left previously */
		+ (tag_mode==1?-1:0)
		;
	ASN_DEBUG("bner_check_tags(%s, size=%ld, tm=%d, step=%d, tagno=%d)",
		td->name, (long)size, tag_mode, step, tagno);
	/* assert(td->tags_count >= 1) May not be the case for CHOICE or ANY */

	if(tag_mode == 0 && tagno == (int)td->tags_count) {
		/*
		 * This must be the _untagged_ ANY type,
		 * which outermost tag isn't known in advance.
		 * Fetch the tag and length separately.
		 */
		tag_len = bner_fetch_tag_lvt(ptr, size, &tag_lvt);
		switch(tag_len) {
		case -1: RETURN(RC_FAIL);
		case 0: RETURN(RC_WMORE);
		}
		ASN_DEBUG("untagged ANY case: %s", bner_tag_lvt_string(&tag_lvt));

		tlv_constr = (tag_lvt.lvt_type == BNER_LVT_TYPE);

		*length = tlv_constr ? 0 : tag_lvt.length;
		ADVANCE(*length);

		if(opt_tlv_form)
			*opt_tlv_form = tlv_constr;

		*last_tag = tag_lvt;

		RETURN(RC_OK);
	} else {
		assert(tagno < (int)td->tags_count);	/* At least one loop */
	}

	tag_len = bner_fetch_tag_lvt(ptr, size, &tag_lvt);
	ASN_DEBUG("Fetching tag from {%p,%ld}: "
		"len %ld, step %d, tagno %d got %s",
		ptr, (long)size,
		(long)tag_len, step, tagno,
		bner_tag_lvt_string(&tag_lvt));
	switch(tag_len) {
	case -1: RETURN(RC_FAIL);
	case 0: RETURN(RC_WMORE);
	}

	if (tag_mode == 1)
	{
		if (!BER_TAGS_EQUAL(tag_lvt.tag, convert_ber_to_bner_tag(tag)))
		{
			/*
			 * Unexpected tag. Too bad.
			 */
			ASN_DEBUG("Unexpected: %s, "
			          "expectation failed (tn=%d, tm=%d)",
			          bner_tag_lvt_string(&tag_lvt),
			          tagno, tag_mode
			          );
			RETURN(RC_FAIL);
		}
	}
	else if (tag_mode != -1)
	{
		 if (!bner_is_tag_expected(&tag_lvt, td, td->elements, td->elements_count))
		 {
			/*
			 * Unexpected tag. Too bad.
			 */
			 ASN_DEBUG("Unexpected: %s, "
			           "expectation failed (tn=%d, tm=%d)",
			           bner_tag_lvt_string(&tag_lvt),
			           tagno, tag_mode
			           );
			 RETURN(RC_FAIL);
		 }
	}

	ADVANCE(tag_len);

	if(opt_tlv_form)
		*opt_tlv_form = tlv_constr;

	*length = tag_len;
	*last_tag = tag_lvt;

	RETURN(RC_OK);
}

int bner_is_tag_expected(const bner_tag_lvt_t* tag,
						 const struct asn_TYPE_descriptor_s* td,
						 const struct asn_TYPE_member_s* elements,
						 unsigned elements_count)
{
	unsigned int i;

	for (i = 0; i < td->all_tags_count; ++i) {
		if (BER_TAGS_EQUAL(tag->tag, convert_ber_to_bner_tag(td->all_tags[i])))
			return 1;
	}

	for (i = 0; i < elements_count; ++i) {
		if ((BER_TAG_CLASS(elements[i].tag) == ASN_TAG_CLASS_UNIVERSAL)
				&& (BER_TAG_VALUE(elements[i].tag) == 16
					|| BER_TAG_VALUE(elements[i].tag) == 17))
		{
			// We need to look at the child's tags...
			return bner_is_tag_expected(tag, td, elements[i].type->elements,
										elements[i].type->elements_count);
		}

		if (BER_TAGS_EQUAL(tag->tag, convert_ber_to_bner_tag(elements[i].tag)))
			return 1;
		else if (!elements[i].optional)
			break;
	}

	return 0;
}

#endif
