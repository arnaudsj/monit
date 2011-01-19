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

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_PCRE
#include <pcre.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#include "protocol.h"

/**
 *  Generic service test.
 *
 *  @author Christian Hopp, <chopp@iei.tu-clausthal.de>
 *
 *  @file
 */
int check_generic(Socket_T s) {
  Generic_T g= NULL;
  char *buf;
#ifdef HAVE_REGEX_H
  int regex_return;
#endif
  
  ASSERT(s);

  if(socket_get_Port(s))
    g= ((Port_T)(socket_get_Port(s)))->generic;
    
  buf = xcalloc(sizeof(char), Run.expectbuffer + 1);

  while (g != NULL) {
    
    if (g->send != NULL) {
      
      /* Unescape any \0x00 escaped chars in g's send string 
      to allow sending a string containing \0 bytes also */
      char *X = xstrdup(g->send);
      int l = Util_handle0Escapes(X);
      
      if(socket_write(s, X, l) < 0) {
        LogError("GENERIC: error sending data -- %s\n", STRERROR);
        FREE(X);
        FREE(buf);
        return FALSE;
      } else
        DEBUG("GENERIC: successfully sent: '%s'\n", g->send); 

      FREE(X);          

    } else if (g->expect != NULL) {
      int n; 

      /* Need read, not readln here */
      if((n= socket_read(s, buf, Run.expectbuffer))<0) {
        LogError("GENERIC: error receiving data -- %s\n", STRERROR);
        FREE(buf);
        return FALSE;
      }
      buf[n]= 0;
      
#ifdef HAVE_REGEX_H
      regex_return= regexec(g->expect, buf, 0, NULL, 0);
      if (regex_return != 0) {
        char e[STRLEN];
        regerror(regex_return, g->expect, e, STRLEN);
        LogError("GENERIC: receiving unexpected data [%s] -- %s\n", Util_trunc(buf, STRLEN - 4), e);
        FREE(buf);
        return FALSE;
      } else
        DEBUG("GENERIC: successfully received: '%s'\n", Util_trunc(buf, STRLEN - 4)); 
      
#else
      /* w/o regex support */

      if (strncmp(buf, g->expect, strlen(g->expect)) != 0) {
        LogError("GENERIC: receiving unexpected data [%s]\n", Util_trunc(buf, STRLEN - 4));
        FREE(buf);
        return FALSE;
      } else
        DEBUG("GENERIC: successfully received: '%s'\n", Util_trunc(buf, STRLEN - 4)); 
      
#endif
      
    } else {
      /* This should not happen */
      LogError("GENERIC: unexpected strageness\n");
      FREE(buf);
      return FALSE;
    }
    g= g->next;
  }
  
  FREE(buf);
  return TRUE;
    
}

