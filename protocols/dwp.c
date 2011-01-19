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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif


#include "protocol.h"

/**
 *  A simple DWP (database wire protocol) test.
 *
 *  We send the following request to the server:
 *  'HEAD / HTTP/1.1'
 *  and check the server's status code.
 *
 *  If the status code is >= 400, an error has occurred.
 *  Return TRUE if the status code is 200, otherwise FALSE.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Martin Pala, <martinp@tildeslash.com>
 *
 *  @file
 */
int check_dwp(Socket_T s) {

#define REQ_LENGTH  1024

  int n;
  int status;
  char buf[STRLEN];
  char proto[STRLEN];

  ASSERT(s);

  if(socket_print(s, "HEAD / HTTP/1.1\r\n"
		  "Connection: close\r\n\r\n") < 0) {
    LogError("DWP: error sending data -- %s\n", STRERROR);
    return FALSE;
  }
  
  if(! socket_readln(s, buf, sizeof(buf))) {
    LogError("DWP: error receiving data -- %s\n", STRERROR);
    return FALSE;
  }

  Util_chomp(buf);

  n= sscanf(buf, "%255s %d", proto, &status);
  if(n!=2 || (status >= 400)) {
    LogError("DWP error: %s\n", buf);
    return FALSE;
  }
  
  return TRUE;
  
}

