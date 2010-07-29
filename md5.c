/* md5.c - Functions to compute MD5 message digest of files or memory blocks
   according to the definition of MD5 in RFC 1321 from April 1992.
   Copyright (C) 1995, 1996 Free Software Foundation, Inc.
   NOTE: The canonical source of this file is maintained with the GNU C
   Library.  Bugs can be reported to bug-glibc@prep.ai.mit.edu.

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 2, or (at your option) any
   later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

/* Written by Ulrich Drepper <drepper@gnu.ai.mit.edu>, 1995.  */

#include <config.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif

#include "md5.h"
#include "monitor.h"


#ifdef WORDS_BIGENDIAN
# define SWAP(n)							\
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))
#else
# define SWAP(n) (n)
#endif

/* This array contains the bytes used to pad the buffer to the next
   64-byte boundary.  (RFC 1321, 3.1: Step 1)  */
static const unsigned char fillbuf[64] = { 0x80, 0 /* , 0, 0, ...  */ };


/* Initialize structure containing state of computation.
   (RFC 1321, 3.3: Step 3)  */
void
md5_init_ctx (ctx)
     struct md5_ctx *ctx;
{
  ctx->A = 0x67452301;
  ctx->B = 0xefcdab89;
  ctx->C = 0x98badcfe;
  ctx->D = 0x10325476;

  ctx->total[0] = ctx->total[1] = 0;
  ctx->buflen = 0;
}

/* Put result from CTX in first 16 bytes following RESBUF.  The result
   must be in little endian byte order.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
void *
md5_read_ctx (ctx, resbuf)
     const struct md5_ctx *ctx;
     void *resbuf;
{
  ((md5_uint32 *) resbuf)[0] = SWAP (ctx->A);
  ((md5_uint32 *) resbuf)[1] = SWAP (ctx->B);
  ((md5_uint32 *) resbuf)[2] = SWAP (ctx->C);
  ((md5_uint32 *) resbuf)[3] = SWAP (ctx->D);

  return resbuf;
}

/* Process the remaining bytes in the internal buffer and the usual
   prolog according to the standard and write the result to RESBUF.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
void *
md5_finish_ctx (ctx, resbuf)
     struct md5_ctx *ctx;
     void *resbuf;
{
  /* Take yet unprocessed bytes into account.  */
  md5_uint32 bytes = ctx->buflen;
  size_t pad;

  /* Now count remaining bytes.  */
  ctx->total[0] += bytes;
  if (ctx->total[0] < bytes)
    ++ctx->total[1];

  pad = bytes >= 56 ? 64 + 56 - bytes : 56 - bytes;
  memcpy (&ctx->buffer[bytes], fillbuf, pad);

  /* Put the 64-bit file length in *bits* at the end of the buffer.  */
  *(md5_uint32 *) &ctx->buffer[bytes + pad] = SWAP (ctx->total[0] << 3);
  *(md5_uint32 *) &ctx->buffer[bytes + pad + 4] = SWAP ((ctx->total[1] << 3) |
							(ctx->total[0] >> 29));

  /* Process last bytes.  */
  md5_process_block (ctx->buffer, bytes + pad + 8, ctx);

  return md5_read_ctx (ctx, resbuf);
}

/* Compute MD5 message digest for bytes read from STREAM.  The
   resulting message digest number will be written into the 16 bytes
   beginning at RESBLOCK.  */
int
md5_stream (stream, resblock)
     FILE *stream;
     void *resblock;
{
  /* Important: BLOCKSIZE must be a multiple of 64.  */
#define BLOCKSIZE 4096
  struct md5_ctx ctx;
  char buffer[BLOCKSIZE + 72];
  size_t sum;

  /* Initialize the computation context.  */
  md5_init_ctx (&ctx);

  /* Iterate over full file contents.  */
  while (1)
    {
      /* We read the file in blocks of BLOCKSIZE bytes.  One call of the
	 computation function processes the whole buffer so that with the
	 next round of the loop another block can be read.  */
      size_t n;
      sum = 0;

      /* Read block.  Take care for partial reads.  */
      do
	{
	  n = fread (buffer + sum, 1, BLOCKSIZE - sum, stream);

	  sum += n;
	}
      while (sum < BLOCKSIZE && n != 0);
      if (n == 0) {
        int error = ferror(stream);
        if (error) {
          LogError("md5_stream: stream error -- sum=%d, error=0x%x\n", sum, error);
          return error;
        } else
          break; /* If end of file is reached, end the loop.  */
      }

      /* Process buffer with BLOCKSIZE bytes. Note that BLOCKSIZE % 64 == 0
       */
      md5_process_block (buffer, BLOCKSIZE, &ctx);
    }

  /* Add the last bytes if necessary.  */
  if (sum > 0)
    md5_process_bytes (buffer, sum, &ctx);

  /* Construct result in desired memory.  */
  md5_finish_ctx (&ctx, resblock);
  return 0;
}

/* Compute MD5 message digest for LEN bytes beginning at BUFFER.  The
   result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */
void *
md5_buffer (buffer, len, resblock)
     const char *buffer;
     size_t len;
     void *resblock;
{
  struct md5_ctx ctx;

  /* Initialize the computation context.  */
  md5_init_ctx (&ctx);

  /* Process whole buffer but last len % 64 bytes.  */
  md5_process_bytes (buffer, len, &ctx);

  /* Put result in desired memory area.  */
  return md5_finish_ctx (&ctx, resblock);
}


void
md5_process_bytes (buffer, len, ctx)
     const void *buffer;
     size_t len;
     struct md5_ctx *ctx;
{
  /* When we already have some bits in our internal buffer concatenate
     both inputs first.  */
  if (ctx->buflen != 0)
    {
      size_t left_over = ctx->buflen;
      size_t add = 128 - left_over > len ? len : 128 - left_over;

      memcpy (&ctx->buffer[left_over], buffer, add);
      ctx->buflen += add;

      if (left_over + add > 64)
	{
	  md5_process_block (ctx->buffer, (left_over + add) & ~63, ctx);
	  /* The regions in the following copy operation cannot overlap.  */
	  memcpy (ctx->buffer, &ctx->buffer[(left_over + add) & ~63],
		  (left_over + add) & 63);
	  ctx->buflen = (left_over + add) & 63;
	}

      buffer = (const char *) buffer + add;
      len -= add;
    }

  /* Process available complete blocks.  */
  if (len > 64)
    {
      md5_process_block (buffer, len & ~63, ctx);
      buffer = (const char *) buffer + (len & ~63);
      len &= 63;
    }

  /* Move remaining bytes in internal buffer.  */
  if (len > 0)
    {
      memcpy (ctx->buffer, buffer, len);
      ctx->buflen = len;
    }
}


/* These are the four functions used in the four steps of the MD5 algorithm
   and defined in the RFC 1321.  The first function is a little bit optimized
   (as found in Colin Plumbs public domain implementation).  */
/* #define FF(b, c, d) ((b & c) | (~b & d)) */
#define FF(b, c, d) (d ^ (b & (c ^ d)))
#define FG(b, c, d) FF (d, b, c)
#define FH(b, c, d) (b ^ c ^ d)
#define FI(b, c, d) (c ^ (b | ~d))

/* Process LEN bytes of BUFFER, accumulating context into CTX.
   It is assumed that LEN % 64 == 0.  */

void
md5_process_block (buffer, len, ctx)
     const void *buffer;
     size_t len;
     struct md5_ctx *ctx;
{
  md5_uint32 correct_words[16];
  const md5_uint32 *words = buffer;
  size_t nwords = len / sizeof (md5_uint32);
  const md5_uint32 *endp = words + nwords;
  md5_uint32 A = ctx->A;
  md5_uint32 B = ctx->B;
  md5_uint32 C = ctx->C;
  md5_uint32 D = ctx->D;

  /* First increment the byte count.  RFC 1321 specifies the possible
     length of the file up to 2^64 bits.  Here we only compute the
     number of bytes.  Do a double word increment.  */
  ctx->total[0] += len;
  if (ctx->total[0] < len)
    ++ctx->total[1];

  /* Process all bytes in the buffer with 64 bytes in each round of
     the loop.  */
  while (words < endp)
    {
      md5_uint32 *cwp = correct_words;
      md5_uint32 A_save = A;
      md5_uint32 B_save = B;
      md5_uint32 C_save = C;
      md5_uint32 D_save = D;

      /* First round: using the given function, the context and a constant
	 the next context is computed.  Because the algorithms processing
	 unit is a 32-bit word and it is determined to work on words in
	 little endian byte order we perhaps have to change the byte order
	 before the computation.  To reduce the work for the next steps
	 we store the swapped words in the array CORRECT_WORDS.  */

#define OP(a, b, c, d, s, T)						\
      do								\
        {								\
	  a += FF (b, c, d) + (*cwp++ = SWAP (*words)) + T;		\
	  ++words;							\
	  CYCLIC (a, s);						\
	  a += b;							\
        }								\
      while (0)

      /* It is unfortunate that C does not provide an operator for
	 cyclic rotation.  Hope the C compiler is smart enough.  */
#define CYCLIC(w, s) (w = (w << s) | (w >> (32 - s)))

      /* Before we start, one word to the strange constants.
	 They are defined in RFC 1321 as

	 T[i] = (int) (4294967296.0 * fabs (sin (i))), i=1..64
       */

      /* Round 1.  */
      OP (A, B, C, D,  7, 0xd76aa478);
      OP (D, A, B, C, 12, 0xe8c7b756);
      OP (C, D, A, B, 17, 0x242070db);
      OP (B, C, D, A, 22, 0xc1bdceee);
      OP (A, B, C, D,  7, 0xf57c0faf);
      OP (D, A, B, C, 12, 0x4787c62a);
      OP (C, D, A, B, 17, 0xa8304613);
      OP (B, C, D, A, 22, 0xfd469501);
      OP (A, B, C, D,  7, 0x698098d8);
      OP (D, A, B, C, 12, 0x8b44f7af);
      OP (C, D, A, B, 17, 0xffff5bb1);
      OP (B, C, D, A, 22, 0x895cd7be);
      OP (A, B, C, D,  7, 0x6b901122);
      OP (D, A, B, C, 12, 0xfd987193);
      OP (C, D, A, B, 17, 0xa679438e);
      OP (B, C, D, A, 22, 0x49b40821);

      /* For the second to fourth round we have the possibly swapped words
	 in CORRECT_WORDS.  Redefine the macro to take an additional first
	 argument specifying the function to use.  */
#undef OP
#define OP(f, a, b, c, d, k, s, T)					\
      do 								\
	{								\
	  a += f (b, c, d) + correct_words[k] + T;			\
	  CYCLIC (a, s);						\
	  a += b;							\
	}								\
      while (0)

      /* Round 2.  */
      OP (FG, A, B, C, D,  1,  5, 0xf61e2562);
      OP (FG, D, A, B, C,  6,  9, 0xc040b340);
      OP (FG, C, D, A, B, 11, 14, 0x265e5a51);
      OP (FG, B, C, D, A,  0, 20, 0xe9b6c7aa);
      OP (FG, A, B, C, D,  5,  5, 0xd62f105d);
      OP (FG, D, A, B, C, 10,  9, 0x02441453);
      OP (FG, C, D, A, B, 15, 14, 0xd8a1e681);
      OP (FG, B, C, D, A,  4, 20, 0xe7d3fbc8);
      OP (FG, A, B, C, D,  9,  5, 0x21e1cde6);
      OP (FG, D, A, B, C, 14,  9, 0xc33707d6);
      OP (FG, C, D, A, B,  3, 14, 0xf4d50d87);
      OP (FG, B, C, D, A,  8, 20, 0x455a14ed);
      OP (FG, A, B, C, D, 13,  5, 0xa9e3e905);
      OP (FG, D, A, B, C,  2,  9, 0xfcefa3f8);
      OP (FG, C, D, A, B,  7, 14, 0x676f02d9);
      OP (FG, B, C, D, A, 12, 20, 0x8d2a4c8a);

      /* Round 3.  */
      OP (FH, A, B, C, D,  5,  4, 0xfffa3942);
      OP (FH, D, A, B, C,  8, 11, 0x8771f681);
      OP (FH, C, D, A, B, 11, 16, 0x6d9d6122);
      OP (FH, B, C, D, A, 14, 23, 0xfde5380c);
      OP (FH, A, B, C, D,  1,  4, 0xa4beea44);
      OP (FH, D, A, B, C,  4, 11, 0x4bdecfa9);
      OP (FH, C, D, A, B,  7, 16, 0xf6bb4b60);
      OP (FH, B, C, D, A, 10, 23, 0xbebfbc70);
      OP (FH, A, B, C, D, 13,  4, 0x289b7ec6);
      OP (FH, D, A, B, C,  0, 11, 0xeaa127fa);
      OP (FH, C, D, A, B,  3, 16, 0xd4ef3085);
      OP (FH, B, C, D, A,  6, 23, 0x04881d05);
      OP (FH, A, B, C, D,  9,  4, 0xd9d4d039);
      OP (FH, D, A, B, C, 12, 11, 0xe6db99e5);
      OP (FH, C, D, A, B, 15, 16, 0x1fa27cf8);
      OP (FH, B, C, D, A,  2, 23, 0xc4ac5665);

      /* Round 4.  */
      OP (FI, A, B, C, D,  0,  6, 0xf4292244);
      OP (FI, D, A, B, C,  7, 10, 0x432aff97);
      OP (FI, C, D, A, B, 14, 15, 0xab9423a7);
      OP (FI, B, C, D, A,  5, 21, 0xfc93a039);
      OP (FI, A, B, C, D, 12,  6, 0x655b59c3);
      OP (FI, D, A, B, C,  3, 10, 0x8f0ccc92);
      OP (FI, C, D, A, B, 10, 15, 0xffeff47d);
      OP (FI, B, C, D, A,  1, 21, 0x85845dd1);
      OP (FI, A, B, C, D,  8,  6, 0x6fa87e4f);
      OP (FI, D, A, B, C, 15, 10, 0xfe2ce6e0);
      OP (FI, C, D, A, B,  6, 15, 0xa3014314);
      OP (FI, B, C, D, A, 13, 21, 0x4e0811a1);
      OP (FI, A, B, C, D,  4,  6, 0xf7537e82);
      OP (FI, D, A, B, C, 11, 10, 0xbd3af235);
      OP (FI, C, D, A, B,  2, 15, 0x2ad7d2bb);
      OP (FI, B, C, D, A,  9, 21, 0xeb86d391);

      /* Add the starting values of the context.  */
      A += A_save;
      B += B_save;
      C += C_save;
      D += D_save;
    }

  /* Put checksum in context given as argument.  */
  ctx->A = A;
  ctx->B = B;
  ctx->C = C;
  ctx->D = D;
}



/* This md5crypt implementation is taken from glibc-2.3.2.  It
   accepts additionally a variable md5_salt_prefixes.*/

static const char b64t[64] =
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

char *
md5_crypt (key, md5_salt_prefix, salt, buffer, buflen)
     const char *key;
     const char *md5_salt_prefix;
     const char *salt;
     char *buffer;
     int buflen;
{
#ifdef __SUNPRO_C
  /* Suns Forte Developer C Compiler does not support __aligned__ etc. */
  unsigned char alt_result[16];
#else
  unsigned char alt_result[16]
    __attribute__ ((__aligned__ (__alignof__ (md5_uint32))));
#endif
  
  struct md5_ctx ctx;
  struct md5_ctx alt_ctx;
  size_t salt_len;
  size_t key_len;
  size_t cnt;
  char *cp;
  char *copied_key = NULL;
  char *copied_salt = NULL;

  /* Find beginning of salt string.  The prefix should normally always
     be present.  Just in case it is not.  */
  if (strncmp (md5_salt_prefix, salt, strlen (md5_salt_prefix)) == 0)
    /* Skip salt prefix.  */
    salt += strlen(md5_salt_prefix);

  salt_len = MIN (strcspn (salt, "$"), 8);
  key_len = strlen (key);

#ifndef __SUNPRO_C
  /* Suns Forte Developer C Compiler doesn`t support this below,
     so lets hope 32 bit integers are well aligned.
  */

  if ((key - (char *) 0) % __alignof__ (md5_uint32) != 0)
    {
      char *tmp = (char *) alloca (key_len + __alignof__ (md5_uint32));
      key = copied_key =
	memcpy (tmp + __alignof__ (md5_uint32)
		- (tmp - (char *) 0) % __alignof__ (md5_uint32),
		key, key_len);
      ASSERT ((key - (char *) 0) % __alignof__ (md5_uint32) == 0);
    }

  if ((salt - (char *) 0) % __alignof__ (md5_uint32) != 0)
    {
      char *tmp = (char *) alloca (salt_len + __alignof__ (md5_uint32));
      salt = copied_salt =
	memcpy (tmp + __alignof__ (md5_uint32)
		- (tmp - (char *) 0) % __alignof__ (md5_uint32),
		salt, salt_len);
      ASSERT ((salt - (char *) 0) % __alignof__ (md5_uint32) == 0);
    }
#endif

  /* Prepare for the real work.  */
  md5_init_ctx (&ctx);

  /* Add the key string.  */
  md5_process_bytes (key, key_len, &ctx);

  /* Because the SALT argument need not always have the salt prefix we
     add it separately.  */
  md5_process_bytes (md5_salt_prefix, strlen (md5_salt_prefix), &ctx);

  /* The last part is the salt string.  This must be at most 8
     characters and it ends at the first `$' character (for
     compatibility which existing solutions).  */
  md5_process_bytes (salt, salt_len, &ctx);


  /* Compute alternate MD5 sum with input KEY, SALT, and KEY.  The
     final result will be added to the first context.  */
  md5_init_ctx (&alt_ctx);

  /* Add key.  */
  md5_process_bytes (key, key_len, &alt_ctx);

  /* Add salt.  */
  md5_process_bytes (salt, salt_len, &alt_ctx);

  /* Add key again.  */
  md5_process_bytes (key, key_len, &alt_ctx);

  /* Now get result of this (16 bytes) and add it to the other
     context.  */
  md5_finish_ctx (&alt_ctx, alt_result);

  /* Add for any character in the key one byte of the alternate sum.  */
  for (cnt = key_len; cnt > 16; cnt -= 16)
    md5_process_bytes (alt_result, 16, &ctx);
  md5_process_bytes (alt_result, cnt, &ctx);
  
  /* For the following code we need a NUL byte.  */
  *alt_result = '\0';

  /* The original implementation now does something weird: for every 1
     bit in the key the first 0 is added to the buffer, for every 0
     bit the first character of the key.  This does not seem to be
     what was intended but we have to follow this to be compatible.  */
  for (cnt = key_len; cnt > 0; cnt >>= 1)
    md5_process_bytes ((cnt & 1) != 0 ? (const char *) alt_result : key, 1,
			 &ctx);

  /* Create intermediate result.  */
  md5_finish_ctx (&ctx, alt_result);

  /* Now comes another weirdness.  In fear of password crackers here
     comes a quite long loop which just processes the output of the
     previous round again.  We cannot ignore this here.  */
  for (cnt = 0; cnt < 1000; ++cnt)
    {
      /* New context.  */
      md5_init_ctx (&ctx);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
	md5_process_bytes (key, key_len, &ctx);
      else
	md5_process_bytes (alt_result, 16, &ctx);

      /* Add salt for numbers not divisible by 3.  */
      if (cnt % 3 != 0)
	md5_process_bytes (salt, salt_len, &ctx);

      /* Add key for numbers not divisible by 7.  */
      if (cnt % 7 != 0)
	md5_process_bytes (key, key_len, &ctx);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
	md5_process_bytes (alt_result, 16, &ctx);
      else
	md5_process_bytes (key, key_len, &ctx);

      /* Create intermediate result.  */
      md5_finish_ctx (&ctx, alt_result);
    }

  /* Now we can construct the result string.  It consists of three
     parts.  */
  cp = strncpy (buffer, md5_salt_prefix, MAX (0, buflen));
  buflen -= strlen (md5_salt_prefix);
  cp = strchr (cp, '\0');

  cp = strncpy (cp, salt, MIN ((size_t) MAX (0, buflen), salt_len));
  buflen -= MIN ((size_t) MAX (0, buflen), salt_len);
  cp = strchr (cp, '\0');

  if (buflen > 0)
    {
      *cp++ = '$';
      --buflen;
    }

#define b64_from_24bit(B2, B1, B0, N)					      \
  do {									      \
    unsigned int w = ((B2) << 16) | ((B1) << 8) | (B0);			      \
    int n = (N);							      \
    while (n-- > 0 && buflen > 0)					      \
      {									      \
	*cp++ = b64t[w & 0x3f];						      \
	--buflen;							      \
	w >>= 6;							      \
      }									      \
  } while (0)


  b64_from_24bit (alt_result[0], alt_result[6], alt_result[12], 4);
  b64_from_24bit (alt_result[1], alt_result[7], alt_result[13], 4);
  b64_from_24bit (alt_result[2], alt_result[8], alt_result[14], 4);
  b64_from_24bit (alt_result[3], alt_result[9], alt_result[15], 4);
  b64_from_24bit (alt_result[4], alt_result[10], alt_result[5], 4);
  b64_from_24bit (0, 0, alt_result[11], 2);
  if (buflen <= 0)
    {
      buffer = NULL;
    }
  else
    *cp = '\0';		/* Terminate the string.  */

  /* Clear the buffer for the intermediate result so that people
     attaching to processes or reading core dumps cannot get any
     information.  We do it in this way to clear correct_words[]
     inside the MD5 implementation as well.  */
  md5_init_ctx (&ctx);
  md5_finish_ctx (&ctx, alt_result);
  memset (&ctx, '\0', sizeof (ctx));
  memset (&alt_ctx, '\0', sizeof (alt_ctx));
  if (copied_key != NULL)
    memset (copied_key, '\0', key_len);
  if (copied_salt != NULL)
    memset (copied_salt, '\0', salt_len);

  return buffer;
}
