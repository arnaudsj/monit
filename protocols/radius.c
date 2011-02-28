/*
 * Copyright (C) 2011 Tildeslash Ltd. All rights reserved.
 * Copyright (C) 2009 Alan DeKok <aland@freeradius.org> All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

#include <config.h>

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "md5.h"
#include "protocol.h"

static void hmac_md5(const unsigned char *data, int data_len, const unsigned char *key, int key_len, unsigned char *digest) {
  struct md5_ctx ctx;
  unsigned char k_ipad[65];
  unsigned char k_opad[65];
  unsigned char tk[16];
  int i;

  if (key_len > 64) {
    struct md5_ctx tctx;

    md5_init_ctx(&tctx);
    md5_process_bytes(key, key_len, &tctx);
    md5_finish_ctx(&tctx, tk);

    key = tk;
    key_len = 16;
  }

  memset(k_ipad, 0, sizeof(k_ipad));
  memset(k_opad, 0, sizeof(k_opad));
  memcpy(k_ipad, key, key_len);
  memcpy(k_opad, key, key_len);

  for (i = 0; i < 64; i++) {
    k_ipad[i] ^= 0x36;
    k_opad[i] ^= 0x5c;
  }

  md5_init_ctx(&ctx);
  md5_process_bytes(k_ipad, 64, &ctx);
  md5_process_bytes(data, data_len, &ctx);
  md5_finish_ctx(&ctx, digest);

  md5_init_ctx(&ctx);
  md5_process_bytes(k_opad, 64, &ctx);
  md5_process_bytes(digest, 16, &ctx);
  md5_finish_ctx(&ctx, digest);
}


/**
 *  Simple RADIUS test.
 *
 *  We send a Status-Server packet, and expect an Access-Accept or Accounting-Response packet.
 *
 *  @author Alan deKok, <alan@freeradius.org>
 *
 */
int check_radius(Socket_T s) {
  int i, length, left;
  int secret_len;
  Port_T P;
  struct md5_ctx ctx;
  char *secret;
  unsigned char *attr;
  unsigned char  digest[16];
  unsigned char  response[STRLEN];
  unsigned char  request[38] =
  {
    0x0c,                                /** Status-Server */

    0x00,                    /* code.  We always use zero. */

    0x00,                                 /** packet length */
    0x26,

    0x00,                         /** Request Authenticator */
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,

    0x50,                        /** Message-Authenticator */

    0x12,                                       /** length */

    0x00,            /** contents of Message-Authenticator */
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00
  };

  ASSERT(s);

  switch (socket_get_type(s)) {
    case SOCK_DGRAM:
      break;
    default:
      LogError("RADIUS: unsupported socket type -- protocol test skipped\n");
      return TRUE;
  }

  P = socket_get_Port(s);

  ASSERT(P);
  
  secret = (P->request ? P->request : "testing123");
  secret_len = strlen(secret);

  /* Get 16 bytes of (very bad) random data */
  for (i = 0; i < 16; i++)
    request[i + 4] = ((unsigned int)random()) & 0xff;

  /* sign the packet */
  hmac_md5(request, sizeof(request), (unsigned char *)secret, secret_len, request + 22);

  if (socket_write(s, (unsigned char *)request, sizeof(request)) < 0) {
    LogError("RADIUS: error sending query -- %s\n", STRERROR);
    return FALSE;
  }

  /* Response should have at least 20 bytes */
  length = socket_read(s, (unsigned char *)response, sizeof(response));
  if (length < 20) {
    LogError("RADIUS: error receiving response -- %s\n", STRERROR);
    return FALSE;
  }

  /* Compare response code (should be Access-Accept or Accounting-Response) */
  if ((response[0] != 2) && (response[0] != 5)) {
    LogError("RADIUS: Invalid reply code -- error occured\n");
    return FALSE;
  }

  /* Compare packet ID (it should be the same as in our request): */
  if (response[1] != 0x00) {
    LogError("RADIUS: ID mismatch\n");
    return FALSE;
  }

  /* check length */
  if (response[2] != 0) {
    LogError("RADIUS: message is too long\n");
    return FALSE;
  }

  /* check length against packet data*/
  if (response[3] != length) {
    LogError("RADIUS: message has invalid length\n");
    return FALSE;
  }

  /* validate that it is a well-formed packet */
  attr = response + 20;
  left = length - 20;
  while (left > 0) {
    if (left < 2) {
      LogError("RADIUS: message is malformed\n");
      return FALSE;
    }

    if (attr[1] < 2) {
      LogError("RADIUS: message has invalid attribute length\n");
      return FALSE;
    }

    if (attr[1] > left) {
      LogError("RADIUS: message has attribute that is too long\n");
      return FALSE;
    }

    /* validate Message-Authenticator, if found */
    if (attr[0] == 0x50) {
      /* FIXME: validate it */
    }
    left -= attr[1];
  }

  /* save the reply authenticator, and copy the request authenticator over */
  memcpy(digest, response + 4, 16);
  memcpy(response + 4, request + 4, 16);

  md5_init_ctx(&ctx);
  md5_process_bytes(response, length, &ctx);
  md5_process_bytes(secret, secret_len, &ctx);
  md5_finish_ctx(&ctx, response + 4);

  if (memcmp(digest, response + 4, 16) != 0)
    LogError("RADIUS: message fails authentication\n");

  return TRUE;
}

