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

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
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

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "net.h"
#include "socket.h"
#include "monitor.h"
#include "process.h"
#include "device.h"


/**
 *  Obtain status from the monit daemon
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Christian Hopp, <chopp@iei.tu-clausthal.de>
 *
 *  @file
 */


/* ------------------------------------------------------------------ Public */


/**
 * Show all services in the service list.
 */
int status(char *level) {

#define LINE 1024

  int status= FALSE;
  Socket_T sock = NULL;
  char buf[LINE];
  char *auth= NULL;

  if(!exist_daemon()) {
    LogError("%s: no status available -- the monit daemon is not running\n",
      prog);
    return status;
  }

  if(!(sock= socket_new(Run.bind_addr?Run.bind_addr:"localhost", Run.httpdport,
                        SOCKET_TCP, Run.httpdssl, NET_TIMEOUT))) {
    LogError("%s: error connecting to the monit daemon\n", prog);
    return status;
  }

  auth= Util_getBasicAuthHeaderMonit();
  socket_print(sock, 
	       "GET /_status?format=text&level=%s HTTP/1.0\r\n%s\r\n",
	       level, auth?auth:"");
  FREE(auth);

  /* Read past HTTP headers and check status */
  while(socket_readln(sock, buf, LINE)) {
    if(*buf == '\n' || *buf == '\r')
      break;
    if(Util_startsWith(buf, "HTTP/1.0 200"))
      status= TRUE;
  }

  if(!status) {
    LogError("%s: cannot read status from the monit daemon\n", prog);
  } else {
    while(socket_readln(sock, buf, LINE)) {
      printf("%s", buf);
    }
  }
  socket_free(&sock);

  return status;
}
