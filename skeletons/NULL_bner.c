#ifdef ASN_ENABLE_BNER_SUPPORT
#include <asn_internal.h>
#include <NULL.h>

asn_enc_rval_t
NULL_encode_bner(const asn_TYPE_descriptor_t *td, const void *ptr,
                 int tag_mode, ber_tlv_tag_t tag,
                 asn_app_consume_bytes_f *cb, void *app_key)
{
	bner_tag_lvt_t bner_tag;
	asn_enc_rval_t erval;

	bner_tag.tag = convert_ber_to_bner_tag(tag);
	bner_tag.lvt_type = BNER_LVT_LENGTH;
	bner_tag.length = 0;

	ASN_DEBUG("%s %s as a NULL type (tm=%d)",
		cb?"Encoding":"Estimating", td->name, tag_mode);

	erval.encoded = bner_write_tags(td, 0, tag_mode, 0, bner_tag, cb, app_key);
	ASN_DEBUG("%s wrote tags %d", td->name, (int)erval.encoded);
	if(erval.encoded == -1) {
		erval.failed_type = td;
		erval.structure_ptr = ptr;
	}

	ASN__ENCODED_OK(erval);
}

asn_dec_rval_t
NULL_decode_bner(const asn_codec_ctx_t *opt_codec_ctx, const asn_TYPE_descriptor_t *td,
                 void **struct_ptr, const void *ptr, size_t size,
                 ber_tlv_tag_t tag, int tag_mode)
{
    asn_dec_rval_t rv = {RC_OK, 0};
    (void)opt_codec_ctx;
    (void)td;
    (void)struct_ptr;
    (void)ptr;
    (void)size;
    (void)tag_mode;
    return rv;
}

#endif
