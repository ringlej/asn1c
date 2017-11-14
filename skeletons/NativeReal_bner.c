#include <asn_internal.h>
#include <bner_prim.h>
#include <NativeReal.h>
#include <REAL.h>
#include <OCTET_STRING.h>
#include <math.h>

/*
 * Decode REAL type.
 */
asn_dec_rval_t
NativeFloat_decode_bner(const asn_codec_ctx_t *opt_codec_ctx,
                        const asn_TYPE_descriptor_t *td,
                        void **float_ptr, const void *buf_ptr, size_t size,
                        ber_tlv_tag_t tag, int tag_mode)
{
	float *f = (float *)*float_ptr;
	asn_dec_rval_t rval;
	ber_tlv_len_t length;

	/*
	 * If the structure is not there, allocate it.
	 */
	if(f == NULL) {
		*float_ptr = CALLOC(1, sizeof(*f));
		f = (float *)*float_ptr;
		if(f == NULL) {
			rval.code = RC_FAIL;
			rval.consumed = 0;
			return rval;
		}
	}

	ASN_DEBUG("Decoding %s as REAL (tm=%d)",
		td->name, tag_mode);

	/*
	 * Check tags.
	 */
	rval = ber_check_tags(opt_codec_ctx, td, 0, buf_ptr, size,
	                      tag, tag_mode, &length, 0);
	if(rval.code != RC_OK)
		return rval;

	ASN_DEBUG("%s length is %d bytes", td->name, (int)length);

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

	/*
	 * ASN.1 encoded REAL: buf_ptr, length
	 * Fill the Dbl, at the same time checking for overflow.
	 * If overflow occured, return with RC_FAIL.
	 */
	{
		REAL_t tmp;
		union {
			const void *constbuf;
			void *nonconstbuf;
		} unconst_buf;
		double d;

		unconst_buf.constbuf = buf_ptr;
		tmp.buf = (uint8_t *)unconst_buf.nonconstbuf;
		tmp.size = length;

		if(length < (ber_tlv_len_t)size) {
			int ret;
			uint8_t saved_byte = tmp.buf[tmp.size];
			tmp.buf[tmp.size] = '\0';
			ret = asn_REAL2double(&tmp, &d);
			tmp.buf[tmp.size] = saved_byte;
			if(ret) {
				rval.code = RC_FAIL;
				rval.consumed = 0;
				return rval;
			}
		} else if(length < 48 /* Enough for longish %f value. */) {
			tmp.buf = alloca(length + 1);
			tmp.size = length;
			memcpy(tmp.buf, buf_ptr, length);
			tmp.buf[tmp.size] = '\0';
			if(asn_REAL2double(&tmp, &d)) {
				rval.code = RC_FAIL;
				rval.consumed = 0;
				return rval;
			}
		} else {
			/* This should probably never happen: impractically long value */
			tmp.buf = CALLOC(1, length + 1);
			tmp.size = length;
			if(tmp.buf) memcpy(tmp.buf, buf_ptr, length);
			if(!tmp.buf || asn_REAL2double(&tmp, &d)) {
				FREEMEM(tmp.buf);
				rval.code = RC_FAIL;
				rval.consumed = 0;
				return rval;
			}
			FREEMEM(tmp.buf);
		}

		*f = d;
	}

	rval.code = RC_OK;
	rval.consumed += length;

	ASN_DEBUG("Took %ld/%ld bytes to encode %s (%f)",
		(long)rval.consumed, (long)length, td->name, *f);

	return rval;
}

/*
 * Encode the NativeFloat using the standard REAL type BNER encoder.
 */
asn_enc_rval_t
NativeFloat_encode_bner(const asn_TYPE_descriptor_t *td, const void *ptr,
                        int tag_mode, ber_tlv_tag_t tag,
                        asn_app_consume_bytes_f *cb, void *app_key)
{
    double dbl = *(const double *)ptr;
    float flt = dbl;
	asn_enc_rval_t erval;
	REAL_t tmp;
    uint32_t flt_be = htobe32(*(uint32_t*)(char*)&flt);

    tmp.size = sizeof(flt_be);
    tmp.buf = (uint8_t*)&flt_be;

	/* Encode a fake REAL */
	erval = bner_encode_primitive(td, &tmp, tag_mode, tag, cb, app_key);
	if(erval.encoded == -1) {
		assert(erval.structure_ptr == &tmp);
		erval.structure_ptr = ptr;
	}

	return erval;
}

/*
 * Encode the NativeDouble using the standard REAL type BNER encoder.
 */
asn_enc_rval_t
NativeDouble_encode_bner(const asn_TYPE_descriptor_t *td, const void *ptr,
                         int tag_mode, ber_tlv_tag_t tag,
                         asn_app_consume_bytes_f *cb, void *app_key)
{
    double dbl = *(const double *)ptr;
	asn_enc_rval_t erval;
	REAL_t tmp;
    uint64_t dbl_be = htobe64(*(uint64_t*)(char*)&dbl);

    tmp.size = sizeof(dbl_be);
    tmp.buf = (uint8_t*)&dbl_be;

	/* Encode a fake REAL */
	erval = bner_encode_primitive(td, &tmp, tag_mode, tag, cb, app_key);
	if(erval.encoded == -1) {
		assert(erval.structure_ptr == &tmp);
		erval.structure_ptr = ptr;
	}

	return erval;
}
