/*
 * Copyright (c) 2003, 2004, 2005, 2006, 2007 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_CHOICE.h>
#include <per_opentype.h>

/*
 * Return a standardized complex structure.
 */
#undef	RETURN
#define	RETURN(_code)	do {			\
		rval.code = _code;		\
		rval.consumed = consumed_myself;\
		return rval;			\
	} while(0)

/*
 * The following functions functions offer protection against -fshort-enums,
 * compatible with little- and big-endian machines.
 * If assertion is triggered, either disable -fshort-enums, or add an entry
 * here with the ->pres_size of your target stracture.
 * Unless the target structure is packed, the ".present" member
 * is guaranteed to be aligned properly. ASN.1 compiler itself does not
 * produce packed code.
 */
static unsigned
_fetch_present_idx(const void *struct_ptr, unsigned pres_offset,
                   unsigned pres_size) {
    const void *present_ptr;
	unsigned present;

	present_ptr = ((const char *)struct_ptr) + pres_offset;

	switch(pres_size) {
	case sizeof(int):	present = *(const unsigned int *)present_ptr; break;
	case sizeof(short):	present = *(const unsigned short *)present_ptr; break;
	case sizeof(char):	present = *(const unsigned char *)present_ptr; break;
	default:
		/* ANSI C mandates enum to be equivalent to integer */
		assert(pres_size != sizeof(int));
		return 0;	/* If not aborted, pass back safe value */
	}

	return present;
}

/*
 * The decoder of the CHOICE type.
 */
asn_dec_rval_t
CHOICE_decode_bner(const asn_codec_ctx_t *opt_codec_ctx,
                   const asn_TYPE_descriptor_t *td,
                   void **struct_ptr, const void *ptr, size_t size,
                   ber_tlv_tag_t tag, int tag_mode)
{
	/*
	 * Bring closer parts of structure description.
	 */
	asn_CHOICE_specifics_t *specs = (asn_CHOICE_specifics_t *)td->specifics;
	asn_TYPE_member_t *elements = td->elements;

	/*
	 * Parts of the structure being constructed.
	 */
	void *st = *struct_ptr;	/* Target structure. */
	asn_struct_ctx_t *ctx;	/* Decoder context */

	ber_tlv_tag_t tlv_tag;	/* T from TLV */
	ssize_t tag_len;	/* Length of TLV's T */
	asn_dec_rval_t rval;	/* Return code from subparsers */

	ssize_t consumed_myself = 0;	/* Consumed bytes from ptr */

	ASN_DEBUG("Decoding %s as CHOICE", td->name);

	RETURN(RC_OK);
}

asn_enc_rval_t
CHOICE_encode_bner(const asn_TYPE_descriptor_t *td, const void *sptr,
                   int tag_mode, ber_tlv_tag_t tag,
                   asn_app_consume_bytes_f *cb, void *app_key)
{
	asn_CHOICE_specifics_t *specs = (asn_CHOICE_specifics_t *)td->specifics;
	asn_TYPE_member_t *elm;	/* CHOICE element */
	asn_enc_rval_t erval;
	void *memb_ptr;
	size_t computed_size = 0;
	unsigned present;

	if(!sptr) ASN__ENCODE_FAILED;

	ASN_DEBUG("%s %s as CHOICE",
		cb?"Encoding":"Estimating", td->name);

	present = _fetch_present_idx(sptr,
		specs->pres_offset, specs->pres_size);

	/*
	 * If the structure was not initialized, it cannot be encoded:
	 * can't deduce what to encode in the choice type.
	 */
	if(present == 0 || present > td->elements_count) {
		if(present == 0 && td->elements_count == 0) {
			/* The CHOICE is empty?! */
			erval.encoded = 0;
			ASN__ENCODED_OK(erval);
		}
		ASN__ENCODE_FAILED;
	}

	/*
	 * Seek over the present member of the structure.
	 */
	elm = &td->elements[present-1];
	if(elm->flags & ATF_POINTER) {
		memb_ptr = *(void **)((char *)sptr + elm->memb_offset);
		if(memb_ptr == 0) {
			if(elm->optional) {
				erval.encoded = 0;
				ASN__ENCODED_OK(erval);
			}
			/* Mandatory element absent */
			ASN__ENCODE_FAILED;
		}
	} else {
		memb_ptr = (void *)((char *)sptr + elm->memb_offset);
	}

	/*
	 * Encode the single underlying member.
	 */
	erval = elm->type->op->bner_encoder(elm->type, memb_ptr,
		elm->tag_mode, elm->tag, cb, app_key);
	if(erval.encoded == -1)
		return erval;

	ASN_DEBUG("Encoded CHOICE member in %ld bytes (+%ld)",
		(long)erval.encoded, (long)computed_size);

	erval.encoded += computed_size;

	return erval;
}

