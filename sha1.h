#ifndef __SHA1_H__
#define __SHA1_H__

#define SHA_DATASIZE    64
#define SHA_DATALEN     16
#define SHA_DIGESTSIZE  20
#define SHA_DIGESTLEN    5
/* The structure for storing SHA info */

typedef struct sha_ctx {
  unsigned int digest[SHA_DIGESTLEN];  /* Message digest */
  unsigned int count_l, count_h;       /* 64-bit block count */
  unsigned char block[SHA_DATASIZE];     /* SHA data buffer */
  unsigned int index;                  /* index into buffer */
} SHA_CTX;

void sha_init(struct sha_ctx *ctx);
void sha_update(struct sha_ctx *ctx, unsigned char *buffer, unsigned int len);
void sha_final(struct sha_ctx *ctx);
void sha_digest(struct sha_ctx *ctx, unsigned char *s);
void sha_copy(struct sha_ctx *dest, struct sha_ctx *src);

#ifndef EXTRACT_UCHAR
#define EXTRACT_UCHAR(p)  (*(unsigned char *)(p))
#endif

#define STRING2INT(s) ((((((EXTRACT_UCHAR(s) << 8)    \
			 | EXTRACT_UCHAR(s+1)) << 8)  \
			 | EXTRACT_UCHAR(s+2)) << 8)  \
			 | EXTRACT_UCHAR(s+3))

unsigned char *sha(unsigned char *buffer, unsigned int len);

#endif
