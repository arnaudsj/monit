/*
 * Copyright (C) 2010 Tildeslash Ltd. All rights reserved.
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
#include <ctype.h>

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "protocol.h"

/**
 *  Check the server for greeting "@RSYNCD: XX, then send this greeting back
 *  to server, send command '#list' to get a listing of modules.
 * 
 *  @author Igor Homyakov <homyakov@altlinux.ru>
 *
 *  @file
 */
int check_rsync(Socket_T s) {

  char  buf[STRLEN];
  char  msg[STRLEN];
  int   rc, version;
  char  *rsyncd = "@RSYNCD:";
  
  ASSERT(s);
    
  if(!socket_readln(s, buf, sizeof(buf))) {
    LogError("RSYNC: did not see server greeting  -- %s\n", STRERROR);
    return FALSE;
  }

  Util_chomp(buf);
  
  rc = sscanf(buf, "%255s %d", msg, &version);
  if ((rc == EOF) || (rc == 0)) {
     LogError("RSYNC: server greeting parse error %s\n", buf);
    return FALSE;
  }
   
  if(strncasecmp(msg, rsyncd, strlen(rsyncd)) != 0) {
    LogError("RSYNC: server sent \"%s\" rather than greeting\n", buf);
    return FALSE;
  }

  if(snprintf(buf, sizeof(buf), "%s %d\n", rsyncd, version) < 0) {
    LogError("RSYNC: string copy error -- %s\n", STRERROR);
    return FALSE;
  } 
	
  if(socket_write(s, buf, strlen(buf)) <= 0) {
    LogError("RSYNC: error sending identification string -- %s\n", STRERROR);
     return FALSE;
  }

  if(socket_print(s, "#list\n") < 0) {
    LogError("RSYNC: error sending writing #list command  -- %s\n", STRERROR);
    return FALSE;
  }

  if(!socket_readln(s, buf, sizeof(buf))) {
    LogError("RSYNC: did not see server answer  -- %s\n", STRERROR);
    return FALSE;
  }
  
  return TRUE;
  
}
