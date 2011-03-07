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


/* Private prototypes */
static int say(Socket_T s, char *msg);
static int expect(Socket_T s, int expect, int log);


/**
 * Check the server for greeting code 220 and send EHLO. If that failed
 * try HELO and test for return code 250 and finally send QUIT and check
 * for return code 221. If alive return TRUE else return FALSE.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Michael Amster, <mamster@webeasy.com>
 *  @author Martin Pala, <martinp@tildeslash.com>
 *
 *  @file
 */
int check_smtp(Socket_T s) {
  ASSERT(s);
  
  /* Try HELO also before giving up as of rfc2821 4.1.1.1 */
  if (expect(s, 220, TRUE) && ((say(s, "EHLO localhost\r\n") && expect(s, 250, FALSE)) || (say(s, "HELO localhost\r\n") && expect(s, 250, TRUE))) && (say(s, "QUIT\r\n") && expect(s, 221, TRUE)))
    return TRUE;

  return FALSE;
}


/* --------------------------------------------------------------- Private */


static int say(Socket_T s, char *msg) {
  if (socket_write(s, msg, strlen(msg)) < 0) {
    LogError("SMTP: error sending data -- %s\n", STRERROR);
    return FALSE;
  }
  return TRUE;
}


static int expect(Socket_T s, int expect, int log) {
  int status;
  char buf[STRLEN];

  do {
    if (! socket_readln(s, buf, STRLEN)) {
      LogError("SMTP: error receiving data -- %s\n", STRERROR);
      return FALSE;
    }
    Util_chomp(buf);
  } while (buf[3] == '-'); // Discard multi-line response
  if (sscanf(buf, "%d", &status) != 1) {
    if(log) 
      LogError("SMTP error: %s\n", buf);
    return FALSE;
  }
  return TRUE;
}

