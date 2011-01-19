/*
 * Copyright (C) 2011 Tildeslash Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
static int do_send(Socket_T s, char *msg);
static int expect(Socket_T s, int expect, int log);


/**
 * Check the server for greeting code 220 and send LHLO and test
 * for return code 250 and finally send QUIT and check
 * for return code 221. If alive return TRUE else return FALSE.
 * See rfc2033
 *
 *  @author Fco.Javier Felix, <ffelix@inode64.com>
 *
 *  @file
 */
int check_lmtp(Socket_T s) {
    
  ASSERT(s);
  
  if(!expect(s, 220, TRUE))
    return FALSE;
  
  if (!(do_send(s, "LHLO localhost\r\n") && expect(s, 250, TRUE)))
      return FALSE;

  if(!(do_send(s, "QUIT\r\n") && expect(s, 221, TRUE)))
    return FALSE;
    
  return TRUE;
  
}


/* --------------------------------------------------------------- Private */


static int do_send(Socket_T s, char *msg) {
  
  if(socket_write(s, msg, strlen(msg)) < 0) {
    LogError("LMTP: error sending data -- %s\n", STRERROR);
    return FALSE;
  }
  
  return TRUE;
  
}


static int expect(Socket_T s, int expect, int log) {
  
  int status;
  char buf[STRLEN];

  if(!socket_readln(s, buf, STRLEN)) {
    LogError("LMTP: error receiving data -- %s\n", STRERROR);
    return FALSE;
  }
  
  Util_chomp(buf);
  
  sscanf(buf, "%d%*s", &status);
  if(status != expect) {
    if(log) 
      LogError("LMTP error: %s\n", buf);
    return FALSE;
  }
  
  return TRUE;
  
}

