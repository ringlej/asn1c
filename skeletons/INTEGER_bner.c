#ifdef ASN_ENABLE_BNER_SUPPORT
#include <asn_internal.h>
#include <bner_prim.h>
#include <INTEGER.h>
#include <errno.h>

/*
 * Encode as BNER.
 */
asn_enc_rval_t
INTEGER_encode_bner(const asn_TYPE_descriptor_t *td, const void *sptr,
                    int tag_mode, ber_tlv_tag_t tag,
                    asn_app_consume_bytes_f *cb, void *app_key)
{
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)td->specifics;
	INTEGER_t *st = (INTEGER_t *)sptr;

	ASN_DEBUG("%s %s as INTEGER (tm=%d)",
		cb?"Encoding":"Estimating", td->name, tag_mode);

	/*
	 * Canonicalize integer in the buffer.
	 * (Remove too long sign extension, remove some first 0x00 bytes)
	 */
	if(st->buf) {
		uint8_t *buf = st->buf;
		uint8_t *end1 = buf + st->size - 1;
		int shift;

		/* Compute the number of superfluous leading bytes */
		for(; buf < end1; buf++) {
            if(specs && specs->field_unsigned) {
                if(*buf == 0x00)
                    continue;
            } else {
                /*
                 * If the contents octets of an integer value encoding
                 * consist of more than one octet, then the bits of the
                 * first octet and bit 8 of the second octet:
                 * a) shall not all be ones; and
                 * b) shall not all be zero.
                 */
                switch(*buf) {
                case 0x00: if((buf[1] & 0x80) == 0)
                        continue;
                    break;
                case 0xff: if((buf[1] & 0x80))
                        continue;
                    break;
                }
            }
            break;
        }

        /* Remove leading superfluous bytes from the integer */
        shift = buf - st->buf;
        if(shift) {
            uint8_t *nb = st->buf;
            uint8_t *end;

            st->size -= shift;	/* New size, minus bad bytes */
            end = nb + st->size;

            for(; nb < end; nb++, buf++)
                *nb = *buf;
        }

	} /* if(1) */

	return bner_encode_primitive(td, sptr, tag_mode, tag, cb, app_key);
}
#endif
