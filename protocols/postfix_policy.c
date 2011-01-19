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
 *  A simple Postfix SMTP access policy delegation protocol test
 *
 *  To not affect real traffic, we send the following request with
 *  fixed virtual triplet values to the server:
 *   request=smtpd_access_policy
 *   protocol_state=RCPT
 *   protocol_name=SMTP
 *   sender=monit@foo.tld
 *   recipient=monit@foo.tld
 *   client_address=1.2.3.4
 *   client_name=mx.foo.tld
 *  and check that the server replies with some action.
 *
 *  @author Martin Pala, <martinp@tildeslash.com>
 *
 *  @file
 */
int check_postfix_policy(Socket_T s) {

  char buf[STRLEN];

  ASSERT(s);

  if(socket_print(s,
    "request=smtpd_access_policy\n"
    "protocol_state=RCPT\n"
    "protocol_name=SMTP\n"
    "sender=monit@foo.tld\n"
    "recipient=monit@foo.tld\n"
    "client_address=1.2.3.4\n"
    "client_name=mx.foo.tld\n"
    "\n") < 0) {
    LogError("POSTFIX-POLICY: error sending data -- %s\n", STRERROR);
    return FALSE;
  }
  
  if(! socket_readln(s, buf, sizeof(buf))) {
    LogError("POSTFIX-POLICY: error receiving data -- %s\n", STRERROR);
    return FALSE;
  }

  Util_chomp(buf);

  if( (strlen(buf) <= 7) || strncasecmp(buf, "action=", 7) ) {
    LogError("POSTFIX-POLICY error: %s\n",
      *buf?buf:"no action returned");
    return FALSE;
  }
  
  return TRUE;
  
}

