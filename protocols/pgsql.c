/*
 * Copyright (C) 2011 Tildeslash Ltd. All rights reserved.
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

#include "protocol.h"

/**
 *  PostgreSQL test.
 *
 *  @author Tatsuya Nonogaki, <http://www.asahi-net.or.jp/~aa4t-nngk/>
 *
 *  @file
 */
int check_pgsql(Socket_T s) {

  unsigned char buf[STRLEN];

  unsigned char requestLogin[33] = {
    0x00,                              /** Length */
    0x00,
    0x00,
    0x21,

    0x00,                              /** ProtoVer 3.0 */
    0x03,
    0x00,
    0x00,

    0x75, 0x73, 0x65, 0x72, 0x00,      /** user */
    0x72, 0x6f, 0x6f, 0x74, 0x00,      /** root */

    0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00,  /** database */
    0x72, 0x6f, 0x6f, 0x74, 0x00,                          /** root */

    0x00
  };

  /** Doing this is too suspicious maybe.
   * Type Q, Length 19 and QUERY select 1 as a; */
  /**
  unsigned char requestQuery[20] = {
    0x51,

    0x00,
    0x00,
    0x00,
    0x13,

    0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20,
    0x31, 0x20, 0x61, 0x73, 0x20, 0x61, 0x3b,

    0x00
  };
  */

  unsigned char requestTerm[5] = {
    0x58,                              /** Type X */

    0x00,                              /** Length */
    0x00,
    0x00,
    0x04
  };

  unsigned char responseAuthOk[9] = {
    0x52,                              /** Type R */

    0x00,                              /** Length */
    0x00,
    0x00,
    0x08,

    0x00,                              /** OK code 0 */
    0x00,
    0x00,
    0x00
  };

  ASSERT(s);

  if(socket_write(s, (unsigned char *)requestLogin, sizeof(requestLogin)) <= 0) {
    LogError("PGSQL: error sending data -- %s\n", STRERROR);
    return FALSE;
  }

  /** Nine-byte is enough to hold Auth-Ok */
  if(socket_read(s, buf, 9) <= 0) {
    LogError("PGSQL: error receiving data -- %s\n", STRERROR);
    return FALSE;
  }

  /** If server insists on auth error it is working anyway */
  if(*buf=='E') {
    return TRUE;
  }

  /** Successful connection */
  if(!memcmp((unsigned char *)buf, (unsigned char *)responseAuthOk, 9)) {
    /** This is where suspicious people can do SELECT query that I dont */
    socket_write(s, (unsigned char *)requestTerm, sizeof(requestTerm));
    return TRUE;
  }

  /** The last possibility must be that server is demanding password */
  if(*buf=='R') {
    return TRUE;
  }

  LogError("PGSQL: unknown error\n");
  
  return FALSE;
}

