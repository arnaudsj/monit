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

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <netinet/in.h>
#include <time.h>

#include "protocol.h"

/**
 *  Check the server response, check the time it returns and accept a 
 *  TIME_TOLERANCE sec delta with the current system time.
 *
 *  This test is based on RFC868. Rdate returns number of seconds since
 *  00:00:00 UTC, January 1, 1900.
 *
 *  @author Francois Isabelle <Francois.Isabelle@ca.kontron.com>
 *
 *  @file
 */
int check_rdate(Socket_T s) {
 
/* Offset of 00:00:00 UTC, January 1, 1970 from 00:00:00 UTC, January 1, 1900 */
#define  TIME_OFFSET    2208988800UL
#define  TIME_TOLERANCE (time_t)3

  time_t delta;
  time_t rdatet;
  time_t systemt;
	  
  ASSERT(s);
  
  if(socket_read(s,(char*) &rdatet, sizeof(time_t)) <= 0) {
    LogError("RDATE: error receiving data -- %s\n", STRERROR);
    return FALSE;
  }
  
  /* Get remote time and substract offset to allow unix time comparision */
  rdatet = ntohl(rdatet) - TIME_OFFSET;
  
  if((systemt = time(NULL)) == -1) {
    LogError("RDATE error: cannot get system time -- %s\n", STRERROR);
    return FALSE;
  }
   
  if(rdatet >= systemt)
    delta = (rdatet-systemt);
  else
    delta= (systemt-rdatet);
 
  if(delta > TIME_TOLERANCE) {
    LogError("RDATE error: time does not match system time -- %s\n", STRERROR);
    return FALSE;
  }
  
  return TRUE;
  
}

