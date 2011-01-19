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
 *  Check the server for greeting code 200 and then send a QUIT and
 *  check for code 205. If alive return TRUE, else, return FALSE.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *
 *  @file
 */
int check_nntp(Socket_T s) {

  int status= 0;
  char buf[STRLEN];

  ASSERT(s);

  if(!socket_readln(s, buf, sizeof(buf))) {
    LogError("NNTP: error receiving data -- %s\n", STRERROR);
    return FALSE;
  }

  Util_chomp(buf);
  
  sscanf(buf, "%d %*s", &status);
  if(status != 200) {
    LogError("NNTP error: %s\n", buf);
    return FALSE;
  }
  
  if(socket_print(s, "QUIT\r\n") < 0) {
    LogError("NNTP: error sending data -- %s\n", STRERROR);
    return FALSE;
  }

  if(!socket_readln(s, buf, sizeof(buf))) {
    LogError("NNTP: error receiving data -- %s\n", STRERROR);
    return FALSE;
  }

  Util_chomp(buf);

  sscanf(buf, "%d %*s", &status);
  if(status != 205) {
    LogError("NNTP error: %s\n", buf);
    return FALSE;
  }

  return TRUE;
  
}

