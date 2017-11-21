/*
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info> and contributors.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <OCTET_STRING.h>
#include <asn_internal.h>
#include <bner_primitive.h>

bner_type_decoder_f BACnetObjectIdentifier_decode_bner;
bner_type_encoder_f BACnetObjectIdentifier_encode_bner;
bner_type_decoder_f CharacterString_decode_bner;
bner_type_encoder_f CharacterString_encode_bner;
bner_type_decoder_f Date_decode_bner;
bner_type_encoder_f Date_encode_bner;
bner_type_decoder_f Double_decode_bner;
bner_type_encoder_f Double_encode_bner;
bner_type_decoder_f Time_decode_bner;
bner_type_encoder_f Time_encode_bner;

asn_dec_rval_t
__OCTET_STRING_decode_bner(const asn_codec_ctx_t *opt_codec_ctx,
                           const asn_TYPE_descriptor_t *td, void **sptr,
                           const void *buf_ptr, size_t size, ber_tlv_tag_t tag,
                           int tag_mode) {
    OCTET_STRING_t *st = (OCTET_STRING_t *)*sptr;

    /*
     * If the structure is not there, allocate it.
     */
    if(st == NULL) {
        st = (OCTET_STRING_t *)CALLOC(1, sizeof(*st));
        if(st == NULL) ASN__DECODE_FAILED;
        *sptr = (void *)st;
    }

    return bner_decode_primitive(opt_codec_ctx, td, sptr, buf_ptr, size, tag,
                                 tag_mode);
}

asn_dec_rval_t
OCTET_STRING_decode_bner(const asn_codec_ctx_t *opt_codec_ctx,
                         const asn_TYPE_descriptor_t *td, void **sptr,
                         const void *buf_ptr, size_t size, ber_tlv_tag_t tag,
                         int tag_mode) {
    ber_tlv_tag_t tag_type = convert_ber_to_bner_tag(td->tags[0]);

    if(BER_TAG_CLASS(tag_type) != ASN_TAG_CLASS_APPLICATION) ASN__DECODE_FAILED;

    switch(BER_TAG_VALUE(tag_type)) {
    case BNER_APPLICATION_TAG_OBJECT_ID:
        return BACnetObjectIdentifier_decode_bner(opt_codec_ctx, td, sptr,
                                                  buf_ptr, size, tag, tag_mode);
    case BNER_APPLICATION_TAG_CHAR_STR:
        return CharacterString_decode_bner(opt_codec_ctx, td, sptr, buf_ptr,
                                           size, tag, tag_mode);
    case BNER_APPLICATION_TAG_DATE:
        return Date_decode_bner(opt_codec_ctx, td, sptr, buf_ptr, size, tag,
                                tag_mode);
    case BNER_APPLICATION_TAG_DOUBLE:
        return Double_decode_bner(opt_codec_ctx, td, sptr, buf_ptr, size, tag,
                                  tag_mode);
    case BNER_APPLICATION_TAG_TIME:
        return Time_decode_bner(opt_codec_ctx, td, sptr, buf_ptr, size, tag,
                                tag_mode);
    case BNER_APPLICATION_TAG_OCTET_STR:
        return __OCTET_STRING_decode_bner(opt_codec_ctx, td, sptr, buf_ptr,
                                          size, tag, tag_mode);
    }

    ASN__DECODE_FAILED;
}

__attribute__((weak)) asn_dec_rval_t
BACnetObjectIdentifier_decode_bner(const asn_codec_ctx_t *opt_codec_ctx,
                                   const asn_TYPE_descriptor_t *td, void **sptr,
                                   const void *buf_ptr, size_t size,
                                   ber_tlv_tag_t tag, int tag_mode) {
    return __OCTET_STRING_decode_bner(opt_codec_ctx, td, sptr, buf_ptr, size,
                                      tag, tag_mode);
}

__attribute__((weak)) asn_dec_rval_t
CharacterString_decode_bner(const asn_codec_ctx_t *opt_codec_ctx,
                            const asn_TYPE_descriptor_t *td, void **sptr,
                            const void *buf_ptr, size_t size, ber_tlv_tag_t tag,
                            int tag_mode) {
    return __OCTET_STRING_decode_bner(opt_codec_ctx, td, sptr, buf_ptr, size,
                                      tag, tag_mode);
}

__attribute__((weak)) asn_dec_rval_t
Date_decode_bner(const asn_codec_ctx_t *opt_codec_ctx,
                 const asn_TYPE_descriptor_t *td, void **sptr,
                 const void *buf_ptr, size_t size, ber_tlv_tag_t tag,
                 int tag_mode) {
    return __OCTET_STRING_decode_bner(opt_codec_ctx, td, sptr, buf_ptr, size,
                                      tag, tag_mode);
}

__attribute__((weak)) asn_dec_rval_t
Double_decode_bner(const asn_codec_ctx_t *opt_codec_ctx,
                   const asn_TYPE_descriptor_t *td, void **sptr,
                   const void *buf_ptr, size_t size, ber_tlv_tag_t tag,
                   int tag_mode) {
    return __OCTET_STRING_decode_bner(opt_codec_ctx, td, sptr, buf_ptr, size,
                                      tag, tag_mode);
}

__attribute__((weak)) asn_dec_rval_t
Time_decode_bner(const asn_codec_ctx_t *opt_codec_ctx,
                 const asn_TYPE_descriptor_t *td, void **sptr,
                 const void *buf_ptr, size_t size, ber_tlv_tag_t tag,
                 int tag_mode) {
    return __OCTET_STRING_decode_bner(opt_codec_ctx, td, sptr, buf_ptr, size,
                                      tag, tag_mode);
}

asn_enc_rval_t
OCTET_STRING_encode_bner(const asn_TYPE_descriptor_t *td, const void *sptr,
                         int tag_mode, ber_tlv_tag_t tag,
                         asn_app_consume_bytes_f *cb, void *app_key) {
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
