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

#ifdef HAVE_STRING_H
#include <string.h>
#endif 

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif 

#include "monitor.h"
#include "socket.h"
#include "event.h"


/**
 *  Connect to a data collector servlet and send event or status message.
 *
 *  @author Martin Pala, <martinp@tildeslash.com>
 *
 *
 *  @file
 */


/* -------------------------------------------------------------- Prototypes */


static int data_send(Socket_T, Mmonit_T, char *);
static int data_check(Socket_T, Mmonit_T);


/* ------------------------------------------------------------------ Public */


/**
 * Post event or status data message to mmonit
 * @param E An event object or NULL for status data
 * @return If failed, return HANDLER_MMONIT flag or HANDLER_SUCCEEDED flag if succeeded
 */
int handle_mmonit(Event_T E) {
  char     *D = NULL;
  Mmonit_T  C = Run.mmonits;
  int       rv = HANDLER_SUCCEEDED;
  Socket_T  socket;

  /* The event is sent to mmonit just once - only in the case that the state changed */
  if(!C || (E && !E->state_changed))
    return rv;

  while(!(socket = socket_create_t(C->url->hostname, C->url->port, SOCKET_TCP, C->ssl, C->timeout))) {
    LogError("M/Monit: cannot open a connection to %s -- %s\n", C->url->url, STRERROR);

    if((C = C->next)) {
      LogInfo("M/Monit: trying next server %s\n", C->url->url);
      continue;
    } else {
      LogError("M/Monit: no server available\n");
      rv = HANDLER_MMONIT;
      goto exit2;
    }
  }

  D = status_xml(E, E ? LEVEL_SUMMARY : LEVEL_FULL, 2, socket_get_local_host(socket));

  if(!data_send(socket, C, D)) {
    LogError("M/Monit: communication failed\n");
    rv = HANDLER_MMONIT;
    goto exit1;
  }
  
  /* Close write part of socket to indicate to M/Monit that message was sent
  and stop M/Monit XML parser from waiting for more data */
  socket_shutdown_write(socket);
  
  if(!data_check(socket, C)) {
    LogError("M/Monit: communication failed (%s message)\n", E ? "event" : "status");
    rv = HANDLER_MMONIT;
    goto exit1;
  }
  DEBUG("M/Monit: %s message sent to %s\n", E ? "event" : "status", C->url->url);

exit1:
  FREE(D);
  if(socket)
    socket_free(&socket);
exit2:
  return rv;
}


/* ----------------------------------------------------------------- Private */


/**
 * Send message to the server
 * @param C An mmonit object
 * @param D Data to send
 * @return TRUE if the message sending succeeded otherwise FALSE
 */
static int data_send(Socket_T socket, Mmonit_T C, char *D) {
  int   rv;
  char *auth;

  auth = Util_getBasicAuthHeader(C->url->user, C->url->password);
  rv = socket_print(socket,
         "POST %s HTTP/1.1\r\n"
         "Host: %s:%d\r\n"
         "Content-Type: text/xml\r\n"
         "Content-Length: %d\r\n"
         "Pragma: no-cache\r\n"
         "Accept: */*\r\n"
         "User-Agent: %s/%s\r\n"
         "Connection: close\r\n"
         "%s"
         "\r\n"
         "%s",
         C->url->path,
         C->url->hostname, C->url->port,
         strlen(D),
         prog, VERSION,
         auth?auth:"",
         D);
  FREE(auth);
  if(rv <0) {
    LogError("M/Monit: error sending data to %s -- %s\n", C->url->url, STRERROR);
    return FALSE;
  }
  return TRUE;
}


/**
 * Check that the server returns a valid HTTP response
 * @param C An mmonit object
 * @return TRUE if the response is valid otherwise FALSE
 */
static int data_check(Socket_T socket, Mmonit_T C) {
  int  n;
  int  status;
  char buf[STRLEN];

  if(!socket_readln(socket, buf, sizeof(buf))) {
    LogError("M/Monit: error receiving data from %s -- %s\n", C->url->url, STRERROR);
    return FALSE;
  }
  Util_chomp(buf);
  n = sscanf(buf, "%*s %d", &status);
  if(n != 1 || (status >= 400)) {
    LogError("M/Monit: message sending failed to %s -- %s\n", C->url->url, buf);
    return FALSE;
  }
  return TRUE;
}

