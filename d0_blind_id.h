#include "d0.h"

typedef struct d0_blind_id_s d0_blind_id_t;

WARN_UNUSED_RESULT d0_blind_id_t *d0_blind_id_new();
void d0_blind_id_free(d0_blind_id_t *a);
void d0_blind_id_clear(d0_blind_id_t *ctx);
void d0_blind_id_copy(d0_blind_id_t *ctx, const d0_blind_id_t *src);
WARN_UNUSED_RESULT BOOL d0_blind_id_generate_private_keys(d0_blind_id_t *ctx, int k);
WARN_UNUSED_RESULT BOOL d0_blind_id_read_private_keys(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen);
WARN_UNUSED_RESULT BOOL d0_blind_id_read_public_keys(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen);
WARN_UNUSED_RESULT BOOL d0_blind_id_write_private_keys(d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen);
WARN_UNUSED_RESULT BOOL d0_blind_id_write_public_keys(d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen);
WARN_UNUSED_RESULT BOOL d0_blind_id_generate_private_id_start(d0_blind_id_t *ctx);
WARN_UNUSED_RESULT BOOL d0_blind_id_generate_private_id_request(d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen);
WARN_UNUSED_RESULT BOOL d0_blind_id_answer_private_id_request(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen, char *outbuf, size_t *outbuflen);
WARN_UNUSED_RESULT BOOL d0_blind_id_finish_private_id_request(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen);
WARN_UNUSED_RESULT BOOL d0_blind_id_read_private_id(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen);
WARN_UNUSED_RESULT BOOL d0_blind_id_read_public_id(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen);
WARN_UNUSED_RESULT BOOL d0_blind_id_write_private_id(d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen);
WARN_UNUSED_RESULT BOOL d0_blind_id_write_public_id(d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen);
WARN_UNUSED_RESULT BOOL d0_blind_id_authenticate_with_private_id_start(d0_blind_id_t *ctx, int is_first, char *message, size_t msglen, char *outbuf, size_t *outbuflen);
WARN_UNUSED_RESULT BOOL d0_blind_id_authenticate_with_private_id_challenge(d0_blind_id_t *ctx, int is_first, const char *inbuf, size_t inbuflen, char *outbuf, size_t *outbuflen);
WARN_UNUSED_RESULT BOOL d0_blind_id_authenticate_with_private_id_response(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen, char *outbuf, size_t *outbuflen);
WARN_UNUSED_RESULT BOOL d0_blind_id_authenticate_with_private_id_verify(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen, char *msg, ssize_t *msglen);
WARN_UNUSED_RESULT BOOL d0_blind_id_fingerprint64_public_id(d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen);

void d0_blind_id_INITIALIZE();
void d0_blind_id_SHUTDOWN();
