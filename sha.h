/* sha.h - Declaration of functions and datatypes for SHA1 sum computing
   library functions.

   Copyright (C) 1999, Scott G. Miller
*/

#ifndef _SHA_H
#define _SHA_H 1

#include <config.h>
#include <stdio.h>
#include "md5.h"

/* Structure to save state of computation between the single steps.  */
struct sha_ctx
{
  md5_uint32 A;
  md5_uint32 B;
  md5_uint32 C;
  md5_uint32 D;
  md5_uint32 E;

  md5_uint32 total[2];
  md5_uint32 buflen;
  char buffer[128];
};


/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is necessary that LEN is a multiple of 64!!! */
extern void sha_process_block __P ((const void *buffer, size_t len,
                            struct sha_ctx *ctx));

/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is NOT required that LEN is a multiple of 64.  */
extern void sha_process_bytes __P((const void *buffer, size_t len,
				    struct sha_ctx *ctx));

/* Initialize structure containing state of computation. */
extern void sha_init_ctx __P ((struct sha_ctx *ctx));

/* Process the remaining bytes in the buffer and put result from CTX
   in first 16 bytes following RESBUF.  The result is always in little
   endian byte order, so that a byte-wise output yields to the wanted
   ASCII representation of the message digest.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
extern void *sha_finish_ctx __P ((struct sha_ctx *ctx, void *resbuf));


/* Put result from CTX in first 16 bytes following RESBUF.  The result is
   always in little endian byte order, so that a byte-wise output yields
   to the wanted ASCII representation of the message digest.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
extern void *sha_read_ctx __P ((const struct sha_ctx *ctx, void *resbuf));


/* Compute MD5 message digest for bytes read from STREAM.  The
   resulting message digest number will be written into the 16 bytes
   beginning at RESBLOCK.  */
extern int sha_stream __P ((FILE *stream, void *resblock));

/* Compute MD5 message digest for LEN bytes beginning at BUFFER.  The
   result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */
extern void *sha_buffer __P ((const char *buffer, size_t len, void *resblock));


/* The following is from gnupg-1.0.2's cipher/bithelp.h.  */
/* Rotate a 32 bit integer by n bytes */
#if defined __GNUC__ && defined __i386__
static inline md5_uint32
rol(md5_uint32 x, int n)
{
  __asm__("roll %%cl,%0"
          :"=r" (x)
          :"0" (x),"c" (n));
  return x;
}
#else
# define rol(x,n) ( ((x) << (n)) | ((x) >> (32-(n))) )
#endif

#endif
