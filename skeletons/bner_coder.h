/*-
 * Copyright (c) 2003, 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_BNER_CODER_H_
#define	_BNER_CODER_H_

#include <asn_application.h>
#include <bner_tag_lvt.h>

#ifdef __cplusplus
extern "C" {
#endif

struct asn_TYPE_descriptor_s;	/* Forward declaration */
struct asn_codec_ctx_s;		/* Forward declaration */

int init_bner(void);
void fini_bner(void);

/*
 * Type of generic function which decodes the byte stream into the structure.
 */
typedef asn_dec_rval_t (bner_type_decoder_f)(const struct asn_codec_ctx_s *opt_codec_ctx,
                                             const struct asn_TYPE_descriptor_s *type_descriptor,
                                             void **struct_ptr, const void *buf_ptr, size_t size,
                                             ber_tlv_tag_t tag, int tag_mode);

/*
 * Type of the generic BNER encoder.
 */
typedef asn_enc_rval_t (bner_type_encoder_f)(
		const struct asn_TYPE_descriptor_s *type_descriptor,
		const void *struct_ptr,	/* Structure to be encoded */
		int tag_mode,		/* {-1,0,1}: IMPLICIT, no, EXPLICIT */
		ber_tlv_tag_t tag,
		asn_app_consume_bytes_f *consume_bytes_cb,	/* Callback */
		void *app_key		/* Arbitrary callback argument */
	);

/*
 * The BNER decoder of any type.
 * This function may be invoked directly from the application.
 * The der_encode() function (der_encoder.h) is an opposite to bner_decode().
 */
asn_dec_rval_t bner_decode(const struct asn_codec_ctx_s *opt_codec_ctx,
                           const struct asn_TYPE_descriptor_s *type_descriptor,
                           void **struct_ptr,	/* Pointer to a target structure's pointer */
                           const void *buffer,	/* Data to be decoded */
                           size_t size		/* Size of that buffer */
                           );

/*
 * The BNER encoder of any type. May be invoked by the application.
 * The ber_decode() function (ber_decoder.h) is an opposite of bner_encode().
 */
asn_enc_rval_t bner_encode(const struct asn_TYPE_descriptor_s *type_descriptor,
						   const void *struct_ptr,	/* Structure to be encoded */
						   asn_app_consume_bytes_f *consume_bytes_cb,
						   void *app_key		/* Arbitrary callback argument */
                           );

/* A variant of bner_encode() which encodes data into the pre-allocated buffer */
asn_enc_rval_t bner_encode_to_buffer(
		const struct asn_TYPE_descriptor_s *type_descriptor,
		const void *struct_ptr,	/* Structure to be encoded */
		void *buffer,		/* Pre-allocated buffer */
		size_t buffer_size	/* Initial buffer size (maximum) */
	);

asn_dec_rval_t bner_fixed_decoder(const struct asn_codec_ctx_s *opt_codec_ctx,
								  const struct asn_TYPE_descriptor_s *type_descriptor,
								  void **struct_ptr,	/* Pointer to a target structure's pointer */
								  const void *buffer,	/* Data to be decoded */
								  size_t size		/* Size of that buffer */
								  );

asn_enc_rval_t bner_fixed_encoder(const struct asn_TYPE_descriptor_s *td,
								  const void *sptr,	/* Structure to be encoded */
								  asn_app_consume_bytes_f *consume_bytes_cb,
								  void *app_key		/* Arbitrary callback argument */
								  );

/*******************************
 * INTERNALLY USEFUL FUNCTIONS *
 *******************************/

/*
 * Write out leading TL[v] sequence according to the type definition.
 */
ssize_t bner_write_tags(const struct asn_TYPE_descriptor_s *type_descriptor,
						size_t struct_length,
						int tag_mode,		/* {-1,0,1}: IMPLICIT, no, EXPLICIT */
						int last_tag_form,	/* {0,!0}: prim, constructed */
						bner_tag_lvt_t tag,
						asn_app_consume_bytes_f *consume_bytes_cb,
						void *app_key);

/*
 * Check that all tags correspond to the type definition (as given in head).
 * On return, last_length would contain either a non-negative length of the
 * value part of the last TLV, or the negative numbner of expected
 * "end of content" sequences. The number may only be negative if the
 * head->last_tag_form is non-zero.
 */
asn_dec_rval_t bner_check_tags(const struct asn_codec_ctx_s *opt_codec_ctx,	/* codec options */
                               const struct asn_TYPE_descriptor_s *td,
                               asn_struct_ctx_t *opt_ctx,	/* saved decoding context */
                               const void *ptr, size_t size,
                               ber_tlv_tag_t tag,
                               int tag_mode,		/* {-1,0,1}: IMPLICIT, no, EXPLICIT */
                               ssize_t *length,
                               bner_tag_lvt_t *last_tag,
                               int *opt_tlv_form	/* optional tag form */
                               );

int bner_is_tag_expected(const bner_tag_lvt_t* tag, const struct asn_TYPE_descriptor_s* td,
						 const struct asn_TYPE_member_s *elements,
						 unsigned elements_count);

#ifdef __cplusplus
}
#endif

#endif	/* _BNER_CODER_H_ */
