/*
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info> and contributors.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <NativeInteger.h>
#include <asn_internal.h>
#include <bner_primitive.h>

asn_dec_rval_t
NativeInteger_decode_bner(const asn_codec_ctx_t *opt_codec_ctx,
                          const asn_TYPE_descriptor_t *td, void **nint_ptr,
                          const void *buf_ptr, size_t size, ber_tlv_tag_t tag,
                          int tag_mode) {
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)td->specifics;
    INTEGER_t *integer_tmp = 0;
    long *native = (long *)*nint_ptr;
    asn_dec_rval_t rval;
    long l;

    ASN_DEBUG("Decoding %s as Native INTEGER (tm=%d)", td->name, tag_mode);
    rval = bner_decode_primitive(opt_codec_ctx, td, (void **)&integer_tmp,
                                 buf_ptr, size, tag, tag_mode);

    if(rval.code != RC_OK) return rval;

    /*
     * If the structure is not there, allocate it.
     */
    if(native == NULL) {
        native = (long *)(*nint_ptr = CALLOC(1, sizeof(*native)));
        if(native == NULL) ASN__DECODE_FAILED;
    }

    if((specs && (specs->field_unsigned || specs->strict_enumeration))
           ? asn_INTEGER2ulong(integer_tmp, (unsigned long *)&l)
           : asn_INTEGER2long(integer_tmp, &l)) {
        rval.code = RC_FAIL;
        rval.consumed = 0;
        return rval;
    }

    *native = l;

    return rval;
}

asn_enc_rval_t
NativeInteger_encode_bner(const asn_TYPE_descriptor_t *td, const void *sptr,
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
