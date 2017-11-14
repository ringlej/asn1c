#include <asn_internal.h>
#include <bner_tag_lvt.h>
#include <errno.h>

ssize_t
bner_tag_lvt_snprint(const bner_tag_lvt_t* tag_lvt, char *buf, size_t size)
{
	const char *type = "";
	char lvt_info[20];
	int ret;

	switch (tag_lvt->lvt_type)
	{
	case BNER_LVT_LENGTH:
		snprintf(lvt_info, sizeof(lvt_info),
		         "Length:%d", tag_lvt->length);
		break;
	case BNER_LVT_VALUE:
		assert(BER_TAG_CLASS(tag_lvt->tag) == ASN_TAG_CLASS_APPLICATION);
		assert(BER_TAG_VALUE(tag_lvt->tag) == BNER_APPLICATION_TAG_BOOLEAN);
		assert(tag_lvt->value == BNER_FALSE || tag_lvt->value == BNER_TRUE);
		snprintf(lvt_info, sizeof(lvt_info),
		         "Value:%s",
		         (tag_lvt->value == BNER_FALSE) ? "false" : "true");
		break;
	case BNER_LVT_TYPE:
		assert(BER_TAG_CLASS(tag_lvt->tag) == ASN_TAG_CLASS_CONTEXT);
		assert(tag_lvt->type == BNER_OPENING_TAG || tag_lvt->type == BNER_CLOSING_TAG);
		snprintf(lvt_info, sizeof(lvt_info),
		         "Tag:%s",
		         (tag_lvt->type == BNER_OPENING_TAG) ? "opening" : "closing");
	}

	ret = snprintf(buf, size, "[%s%u] %s",
	               (BER_TAG_CLASS(tag_lvt->tag) == ASN_TAG_CLASS_APPLICATION)
	               ? "APPLICATION " : "",
	               BER_TAG_VALUE(tag_lvt->tag), lvt_info);
	if (ret <= 0 && size) buf[0] = '\0';	/* against broken libc's */

	return ret;
}

ssize_t
bner_tag_lvt_fwrite(const bner_tag_lvt_t* tag, FILE *f)
{
	char buf[sizeof("[APPLICATION ] ") + 32];
	ssize_t ret = bner_tag_lvt_snprint(tag, buf, sizeof(buf));
	if (ret >= (ssize_t)sizeof(buf) || ret < 2) {
		errno = EPERM;
		return -1;
	}

	return fwrite(buf, 1, ret, f);
}

char *
bner_tag_lvt_string(const bner_tag_lvt_t* tag)
{
	static char buf[sizeof("[APPLICATION ] ") + 32];

	(void)bner_tag_lvt_snprint(tag, buf, sizeof(buf));

	return buf;
}

ssize_t
bner_fetch_tag_lvt(const void *bufp, size_t size, bner_tag_lvt_t* tag_lvt_r)
{
	const uint8_t* buf = (const uint8_t *)bufp;
	ber_tlv_tag_t tclass;
	uint8_t lvt = buf[0] & 0x7;
	size_t skipped = 1;

	if (size == 0)
		return 0;

	/* 20.2.1.1 */
	tclass = ((buf[0] >> 3) & 0x1) + 1;

	/* 20.2.1.2 */
	if ((buf[0] & 0xF0) != 0xF0)
		tag_lvt_r->tag = (((buf[0] >> 4) & 0xF) << 2) | tclass;
	else {
		if (size < 2)
			return 0;

		if (buf[1] == 0xff)
			/* Reserved by ASHRAE for future use. */
			return -1;

		tag_lvt_r->tag = (buf[1] << 2) | tclass;
		skipped++;
	}

	/* 20.2.1.3 */
	if (BER_TAG_CLASS(tag_lvt_r->tag) == ASN_TAG_CLASS_APPLICATION
	   && BER_TAG_VALUE(tag_lvt_r->tag) == BNER_APPLICATION_TAG_BOOLEAN) {
		tag_lvt_r->lvt_type = BNER_LVT_VALUE;

		/* 20.2.1.3.1 */
		if ((lvt != BNER_FALSE)
		   && (lvt != BNER_TRUE))
			/* Invalid value */
			return -1;

		tag_lvt_r->value = lvt;

	} else if ((lvt == BNER_OPENING_TAG)
	          || (lvt == BNER_CLOSING_TAG)) {

		/* 20.2.1.3.2 */
		tag_lvt_r->lvt_type = BNER_LVT_TYPE;
		tag_lvt_r->type = lvt;

	} else {
		/* 20.2.1.3.1 */
		tag_lvt_r->lvt_type = BNER_LVT_LENGTH;
		if (lvt < 5)
			tag_lvt_r->length = lvt;
		else if (lvt == 5) {
			if (buf[skipped] == 254) {
				if (size < skipped+2)
					return 0;

				tag_lvt_r->length = (buf[++skipped] << 8) +
				                buf[++skipped];

			} else if (buf[skipped] == 255) {
				if (size < skipped+4)
					return 0;

				tag_lvt_r->length = (buf[++skipped] << 24) +
				                (buf[++skipped] << 16) +
				                (buf[++skipped] << 8) +
				                buf[++skipped];

			} else
				tag_lvt_r->length = buf[skipped];

			skipped++;
		}
	}

	return skipped;
}

size_t
bner_tag_lvt_serialize(bner_tag_lvt_t tag_lvt, void *bufp, size_t size)
{
	uint8_t *buf = (uint8_t *)bufp;
	size_t required_size = 1;

	if (BER_TAG_VALUE(tag_lvt.tag) < 15) {
		/* Encoded tag in 1st octet */
		if (size) buf[0] = (BER_TAG_VALUE(tag_lvt.tag) & 0xf) << 4;
	} else {
		if (size > 1) {
			buf[0] = 0xf0;
			buf[1] = BER_TAG_VALUE(tag_lvt.tag);
		}
		required_size++;
	}
	if (size) buf[0] |= (BER_TAG_CLASS(tag_lvt.tag) - 1) << 3;

	switch (tag_lvt.lvt_type)
	{
	case BNER_LVT_LENGTH:
		if (tag_lvt.length < 5) {
			/* 0 to 4 */
			if (size) buf[0] |= (tag_lvt.length & 0x7);
		} else if (tag_lvt.length < 254) {
			/* 5 to 253 */
			required_size++;
			if (size >= required_size) {
				buf[0] |= 5;
				buf[required_size-1] = (uint8_t)tag_lvt.length;
			}
		} else if (tag_lvt.length < 65536) {
			/* 254 to 65535 */
			required_size++;
			if (size >= required_size+2) {
				buf[0] |= 5;
				buf[required_size-1] = 254;
				buf[required_size+0] = (uint8_t)(tag_lvt.length >> 8) & 0xff;
				buf[required_size+1] = (uint8_t)tag_lvt.length & 0xff;
			}
			required_size += 2;
		} else {
			/* 65536 to 2^32-1 */
			required_size++;
			if (size >= required_size+4) {
				buf[0] |= 5;
				buf[required_size-1] = 255;
				buf[required_size+0] = (uint8_t)(tag_lvt.length >> 24) & 0xff;
				buf[required_size+1] = (uint8_t)(tag_lvt.length >> 16) & 0xff;
				buf[required_size+2] = (uint8_t)(tag_lvt.length >> 8) & 0xff;
				buf[required_size+3] = (uint8_t)tag_lvt.length & 0xff;
			}
			required_size += 4;
		}
		break;
	case BNER_LVT_VALUE:
		if (size) buf[0] |= tag_lvt.value;
		break;
	case BNER_LVT_TYPE:
		if (size) buf[0] |= tag_lvt.type;
		break;
	}

	return required_size;
}

ber_tlv_tag_t convert_ber_to_bner_tag(ber_tlv_tag_t ber_tag)
{
	/* The asn1c compiler will produce UNIVERSAL tags for primative types
	 * that need to be translated into APPLICATION tags for BACnet encoding rules
	 */

	/*
	-- ***************************** Application Types ********************************
	-- The following productions are the definitions of the Application datatypes.
	-- See Clause 20.2.1.4.
	-- NULL			[APPLICATION 0], equivalent to [UNIVERSAL 5]
	-- BOOLEAN		[APPLICATION 1], equivalent to [UNIVERSAL 1]
	Unsigned ::=		[APPLICATION 2] INTEGER (0..MAX)
	Unsigned8 ::=		Unsigned (0..255)
	Unsigned16 ::=		Unsigned (0..65535)
	Unsigned32 ::=		Unsigned (0..4294967295)
	-- INTEGER		[APPLICATION 3], equivalent to [UNIVERSAL 2]
	INTEGER16 ::=		INTEGER (-32768..32767)
	-- REAL			[APPLICATION 4], equivalent to [UNIVERSAL 9] ANSI/IEEE-754 single precision floating point
	Double ::=		[APPLICATION 5] OCTET STRING (SIZE(8)) -- ANSI/IEEE-754 double precision floating point
	-- OCTET STRING		[APPLICATION 6], equivalent to [UNIVERSAL 4]
	CharacterString ::=	[APPLICATION 7] OCTET STRING -- see Clause 20.2.9 for supported types
	-- BIT STRING		[APPLICATION 8], equivalent to [UNIVERSAL 3]
	-- ENUMERATED		[APPLICATION 9], equivalent to [UNIVERSAL 10]
	Date ::=		[APPLICATION 10] OCTET STRING (SIZE(4)) -- see Clause 20.2.12
	--	first octet	year minus 1900,		X'FF' = unspecified
	--	second octet	month		(1.. 14),	1 = January
	--							13 = odd months
	--							14 = even months
	--							X'FF' = unspecified
	--	third octet	day of month	(1..34),	32 = last day of month
	--							33 = odd days of month
	--							34 = even days of month
	--							X'FF' = unspecified
	--	fourth octet	day of week	(1..7)		1 = Monday
	--							7 = Sunday
	--							X'FF' = unspecified
	Time ::=		[APPLICATION 11] OCTET STRING (SIZE(4)) -- see Clause 20.2.13
	--	first octet	hour		(0..23),	X'FF' = unspecified
	--	second octet	minute		(0..59),	X'FF' = unspecified
	--	third octet	second		(0..59),	X'FF' = unspecified
	--	fourth octet	hundredths	(0..99)		X'FF' = unspecified
	BACnetObjectIdentifier ::= [APPLICATION 12] OCTET STRING (SIZE(4)) -- see Clause 20.2.14
	 */

	ber_tlv_tag_t bner_tag;

	switch (BER_TAG_CLASS(ber_tag))
	{
	case ASN_TAG_CLASS_UNIVERSAL:
		switch (BER_TAG_VALUE(ber_tag))
		{
		case 5:  bner_tag = (BNER_APPLICATION_TAG_NULL       << 2) | ASN_TAG_CLASS_APPLICATION; break;
		case 1:  bner_tag = (BNER_APPLICATION_TAG_BOOLEAN    << 2) | ASN_TAG_CLASS_APPLICATION; break;
		case 2:  bner_tag = (BNER_APPLICATION_TAG_SIGNED     << 2) | ASN_TAG_CLASS_APPLICATION; break;
		case 9:  bner_tag = (BNER_APPLICATION_TAG_REAL       << 2) | ASN_TAG_CLASS_APPLICATION; break;
		case 4:  bner_tag = (BNER_APPLICATION_TAG_OCTET_STR  << 2) | ASN_TAG_CLASS_APPLICATION; break;
		case 3:  bner_tag = (BNER_APPLICATION_TAG_BIT_STR    << 2) | ASN_TAG_CLASS_APPLICATION; break;
		case 10: bner_tag = (BNER_APPLICATION_TAG_ENUMERATED << 2) | ASN_TAG_CLASS_APPLICATION; break;
		default: bner_tag = (255 << 2) | ASN_TAG_CLASS_APPLICATION; break; /* Invalid */
		}
		break;
	case ASN_TAG_CLASS_APPLICATION:
	case ASN_TAG_CLASS_CONTEXT:
		bner_tag = ber_tag;
		break;
	case ASN_TAG_CLASS_PRIVATE:
	default:
		bner_tag = (255 << 2) | ASN_TAG_CLASS_APPLICATION; /* Invalid */
		break;
	}

	return bner_tag;
}
