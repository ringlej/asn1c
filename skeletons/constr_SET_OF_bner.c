/*-
 * Copyright (c) 2003, 2004, 2005 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_SET_OF.h>
#include <asn_SET_OF.h>


/*
 * Internally visible buffer holding a single encoded element.
 */
struct _el_buffer {
	uint8_t *buf;
	size_t length;
	size_t size;
};
/* Append bytes to the above structure */
static int _el_addbytes(const void *buffer, size_t size, void *el_buf_ptr) {
	struct _el_buffer *el_buf = (struct _el_buffer *)el_buf_ptr;

	if(el_buf->length + size > el_buf->size)
		return -1;

	memcpy(el_buf->buf + el_buf->length, buffer, size);

	el_buf->length += size;
	return 0;
}
static int _el_buf_cmp(const void *ap, const void *bp) {
	const struct _el_buffer *a = (const struct _el_buffer *)ap;
	const struct _el_buffer *b = (const struct _el_buffer *)bp;
	int ret;
	size_t common_len;

	if(a->length < b->length)
		common_len = a->length;
	else
		common_len = b->length;

	ret = memcmp(a->buf, b->buf, common_len);
	if(ret == 0) {
		if(a->length < b->length)
			ret = -1;
		else if(a->length > b->length)
			ret = 1;
	}

	return ret;
}

/*
 * The DER encoder of the SET OF type.
 */
asn_enc_rval_t
SET_OF_encode_bner(const asn_TYPE_descriptor_t *td, const void *ptr,
                   int tag_mode, ber_tlv_tag_t tag,
                   asn_app_consume_bytes_f *cb, void *app_key) {
	asn_TYPE_member_t *elm = td->elements;
	asn_TYPE_descriptor_t *elm_type = elm->type;
	der_type_encoder_f *der_encoder = elm_type->op->der_encoder;
	asn_anonymous_set_ *list = _A_SET_FROM_VOID(ptr);
	size_t computed_size = 0;
	ssize_t encoding_size = 0;
	struct _el_buffer *encoded_els;
	ssize_t eels_count = 0;
	size_t max_encoded_len = 1;
	asn_enc_rval_t erval;
	int ret;
	int edx;

	ASN_DEBUG("Estimating size for SET OF %s", td->name);

	/*
	 * Gather the length of the underlying members sequence.
	 */
	for(edx = 0; edx < list->count; edx++) {
		void *memb_ptr = list->array[edx];
		if(!memb_ptr) continue;
		erval = der_encoder(elm_type, memb_ptr, 0, elm->tag, 0, 0);
		if(erval.encoded == -1)
			return erval;
		computed_size += erval.encoded;

		/* Compute maximum encoding's size */
		if(max_encoded_len < (size_t)erval.encoded)
			max_encoded_len = erval.encoded;
	}

	/*
	 * Encode the TLV for the sequence itself.
	 */
	encoding_size = der_write_tags(td, computed_size, tag_mode, 1, tag,
		cb, app_key);
	if(encoding_size == -1) {
		erval.encoded = -1;
		erval.failed_type = td;
		erval.structure_ptr = ptr;
		return erval;
	}
	computed_size += encoding_size;

	if(!cb || list->count == 0) {
		erval.encoded = computed_size;
		ASN__ENCODED_OK(erval);
	}

	/*
	 * DER mandates dynamic sorting of the SET OF elements
	 * according to their encodings. Build an array of the
	 * encoded elements.
	 */
	encoded_els = (struct _el_buffer *)MALLOC(
				list->count * sizeof(encoded_els[0]));
	if(encoded_els == NULL) {
		erval.encoded = -1;
		erval.failed_type = td;
		erval.structure_ptr = ptr;
		return erval;
	}

	ASN_DEBUG("Encoding members of %s SET OF", td->name);

	/*
	 * Encode all members.
	 */
	for(edx = 0; edx < list->count; edx++) {
		void *memb_ptr = list->array[edx];
		struct _el_buffer *encoded_el = &encoded_els[eels_count];

		if(!memb_ptr) continue;

		/*
		 * Prepare space for encoding.
		 */
		encoded_el->buf = (uint8_t *)MALLOC(max_encoded_len);
		if(encoded_el->buf) {
			encoded_el->length = 0;
			encoded_el->size = max_encoded_len;
		} else {
			for(edx--; edx >= 0; edx--)
				FREEMEM(encoded_els[edx].buf);
			FREEMEM(encoded_els);
			erval.encoded = -1;
			erval.failed_type = td;
			erval.structure_ptr = ptr;
			return erval;
		}

		/*
		 * Encode the member into the prepared space.
		 */
		erval = der_encoder(elm_type, memb_ptr, 0, elm->tag,
			_el_addbytes, encoded_el);
		if(erval.encoded == -1) {
			for(; edx >= 0; edx--)
				FREEMEM(encoded_els[edx].buf);
			FREEMEM(encoded_els);
			return erval;
		}
		encoding_size += erval.encoded;
		eels_count++;
	}

	/*
	 * Sort the encoded elements according to their encoding.
	 */
	qsort(encoded_els, eels_count, sizeof(encoded_els[0]), _el_buf_cmp);

	/*
	 * Report encoded elements to the application.
	 * Dispose of temporary sorted members table.
	 */
	ret = 0;
	for(edx = 0; edx < eels_count; edx++) {
		struct _el_buffer *encoded_el = &encoded_els[edx];
		/* Report encoded chunks to the application */
		if(ret == 0
		&& cb(encoded_el->buf, encoded_el->length, app_key) < 0)
			ret = -1;
		FREEMEM(encoded_el->buf);
	}
	FREEMEM(encoded_els);

	if(ret || computed_size != (size_t)encoding_size) {
		/*
		 * Standard callback failed, or
		 * encoded size is not equal to the computed size.
		 */
		erval.encoded = -1;
		erval.failed_type = td;
		erval.structure_ptr = ptr;
	} else {
		erval.encoded = computed_size;
	}

	ASN__ENCODED_OK(erval);
}

