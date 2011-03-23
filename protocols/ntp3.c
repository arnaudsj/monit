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

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "protocol.h"


/**
 *  NTP (Network time procol) version 3 test
 *
 *  Synchronization request based on RFC1305.
 *
 *  @author Michel Marti, <michel.marti@objectxp.com>
 *
 */


/* ------------------------------------------------------------- Definitions */


#define NTPLEN           48
#define NTP_LEAP_NOWARN   0 /** Leap Indicator: No warning             */
#define NTP_LEAP_NOTSYNC  3 /** Leap Indicator: Clock not synchronized */
#define NTP_VERSION       3 /** Version Number: 3                      */
#define NTP_MODE_CLIENT   3 /** Mode:           Client                 */
#define NTP_MODE_SERVER   4 /** Mode:           Server                 */


/* ------------------------------------------------------------------ Public */


int check_ntp3(Socket_T s) 
{
  int  br;
  char ntpRequest[NTPLEN];
  char ntpResponse[NTPLEN];

  ASSERT(s);

  memset(ntpRequest, 0, NTPLEN);
  memset(ntpResponse, 0, NTPLEN);

  /*
    Prepare NTP request. The first octet consists of:
       bits 0-1 ... Leap Indicator
       bits 2-4 ... Version Number
       bits 5-7 ... Mode
   */
  ntpRequest[0]=
    (NTP_LEAP_NOTSYNC << 6)
    |
    (NTP_VERSION << 3)
    |
    (NTP_MODE_CLIENT);

  /* Send request to NTP server */
  if(socket_write(s, ntpRequest, NTPLEN) <= 0 ) {
    LogError("NTP: error sending NTP request -- %s\n", STRERROR);
    return FALSE;
  }

  /* Receive and validate response */
  if( (br= socket_read(s, ntpResponse, NTPLEN)) <= 0) {
    LogError("NTP: did not receive answer from server -- %s\n", STRERROR);
    return FALSE;
  }

  if( br != NTPLEN ) {
    LogError("NTP: Received %d bytes from server, expected %d bytes\n",
      br, NTPLEN);
    return FALSE;
  }

  /*
    Compare NTP response. The first octet consists of:
       bits 0-1 ... Leap Indicator
       bits 2-4 ... Version Number
       bits 5-7 ... Mode
   */
  if( (ntpResponse[0] & 0x07) != NTP_MODE_SERVER )
  {
    LogError("NTP: Server mode error\n");
    return FALSE;
  }
  if( (ntpResponse[0] & 0x38) != NTP_VERSION<<3 )
  {
    LogError("NTP: Server protocol version error\n");
    return FALSE;
  }
  if( (ntpResponse[0] & 0xc0) == NTP_LEAP_NOTSYNC<<6 )
  {
    LogError("NTP: Server not synchronized\n");
    return FALSE;
  }

  return TRUE;
}

