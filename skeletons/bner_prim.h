#ifndef	BNER_PRIM_H
#define	BNER_PRIM_H

#include <asn_application.h>
#include <asn_codecs_prim.h>

#ifdef __cplusplus
extern "C" {
#endif

bner_type_decoder_f bner_decode_primitive;
bner_type_encoder_f bner_encode_primitive;

typedef struct bner_date
{
	uint8_t year_;
	uint8_t month_;
	uint8_t dom_;
	uint8_t dow_;
} bner_date_t;

typedef struct bner_time
{
	uint8_t hour_;
	uint8_t minute_;
	uint8_t second_;
	uint8_t hundredths_;
} bner_time_t;

#ifdef __cplusplus
}
#endif

#endif	/* BNER_PRIM_H */
