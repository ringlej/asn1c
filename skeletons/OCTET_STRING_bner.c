/*-
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <bner_prim.h>
#include <NativeReal.h>
#include <OCTET_STRING.h>
#include <errno.h>

/*
 * OCTET STRING basic type description.
 */
static const ber_tlv_tag_t asn_DEF_OCTET_STRING_OCTET_STR_tags[] = {
	(ASN_TAG_CLASS_APPLICATION | (BNER_APPLICATION_TAG_OCTET_STR << 2))
};
static const ber_tlv_tag_t asn_DEF_OCTET_STRING_Double_tags[] = {
	(ASN_TAG_CLASS_APPLICATION | (BNER_APPLICATION_TAG_DOUBLE << 2))
};
static const ber_tlv_tag_t asn_DEF_OCTET_STRING_CHAR_STR_tags[] = {
	(ASN_TAG_CLASS_APPLICATION | (BNER_APPLICATION_TAG_CHAR_STR << 2))
};
static const ber_tlv_tag_t asn_DEF_OCTET_STRING_Date_tags[] = {
	(ASN_TAG_CLASS_APPLICATION | (BNER_APPLICATION_TAG_DATE << 2))
};
static const ber_tlv_tag_t asn_DEF_OCTET_STRING_Time_tags[] = {
	(ASN_TAG_CLASS_APPLICATION | (BNER_APPLICATION_TAG_TIME << 2))
};
static const ber_tlv_tag_t asn_DEF_OCTET_STRING_ObjectId_tags[] = {
	(ASN_TAG_CLASS_APPLICATION | (BNER_APPLICATION_TAG_OBJECT_ID << 2))
};

#if 1
/*
 * Decode OCTET STRING type.
 */
asn_dec_rval_t
OCTET_STRING_decode_bner(const asn_codec_ctx_t *opt_codec_ctx,
                         const asn_TYPE_descriptor_t *td,
                         void **sptr, const void *buf_ptr, size_t size,
                         ber_tlv_tag_t tag, int tag_mode)
{
	OCTET_STRING_t *st = (OCTET_STRING_t *)*sptr;
	/*
	 * If the structure is not there, allocate it.
	 */
	if(st == NULL) {
		st = (OCTET_STRING_t *)CALLOC(1, sizeof(*st));
		if(st == NULL) ASN__DECODE_FAILED;
		*sptr = (void *)st;
	}

	return bner_decode_primitive(opt_codec_ctx, td, sptr, buf_ptr, size, tag, tag_mode);
}
#endif

/*
 * Encode OCTET STRING type using BNER.
 */
asn_enc_rval_t
OCTET_STRING_encode_bner(const asn_TYPE_descriptor_t *td, const void *sptr,
                         int tag_mode, ber_tlv_tag_t tag,
                         asn_app_consume_bytes_f *cb, void *app_key) {
	asn_enc_rval_t er;
	const asn_OCTET_STRING_specifics_t *specs = td->specifics
				? (const asn_OCTET_STRING_specifics_t *)td->specifics
				: &asn_SPC_OCTET_STRING_specs;
	OCTET_STRING_t *st = (OCTET_STRING_t *)sptr;
	enum asn_OS_Subvariant type_variant = specs->subvariant;

	ASN_DEBUG("%s %s as OCTET STRING",
		cb?"Encoding":"Estimating", td->name);

	if (td->tags_count && BER_TAG_CLASS(td->tags[0]) == ASN_TAG_CLASS_APPLICATION) {
		switch (BER_TAG_VALUE(td->tags[0])) {
		case BNER_APPLICATION_TAG_DOUBLE:
			er = NativeDouble_encode_bner(td, st->buf, tag_mode, td->tags[0], cb, app_key);
			break;
		case BNER_APPLICATION_TAG_DATE:
		case BNER_APPLICATION_TAG_TIME:
		case BNER_APPLICATION_TAG_CHAR_STR:
		default:
			er = bner_encode_primitive(td, sptr, tag_mode, td->tags[0], cb, app_key);
			break;
		}
	}

	if(er.encoded == -1) {
		assert(er.structure_ptr == &st);
		er.structure_ptr = sptr;
	}

	return er;
}
