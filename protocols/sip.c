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

#ifdef HAVE_TIME_H
#include <time.h>
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "protocol.h"


/**
 *
 *  A SIP test. 
 *
 *  This test has been created in order to construct valid SIP message, 
 *  even with a low poll cycle. (In case of low poll cycle, chance are 
 *  high for a  misinterpretation of the generic test by the SIP AS. It 
 *  will considered it for  a retransmission, not for a new message)
 *
 *  The test sends an OPTIONS request and check the server's status code.
 *
 *  The status code must be between 200 and 300
 *  Return TRUE if the status code is OK, otherwise FALSE
 * 
 *  In this current version, redirection is not supported. 
 *
 *  @author Pierrick Grasland <pierrick.grasland@nexcom.fr>
 *  @author Bret McDanel, <trixter AT 0xdecafbad.com>
 *
 *  @file
 */


 /* -------------------------------------------------------------- Public*/ 

int check_sip(Socket_T s) {
  int status;
  char buf[STRLEN];
  int port;
  char *transport;
  Port_T P;
  const char *request;
  const char *myip;
  char *rport= "";
  char *proto;

  ASSERT(s);

  P= socket_get_Port(s);
  ASSERT(P);
  request= P->request?P->request:"monit@foo.bar";

  port = socket_get_local_port(s);
  proto = socket_is_secure(s) ? "sips" : "sip";  

  switch(socket_get_type(s)) {
    case SOCK_DGRAM:
    {
      transport="UDP";
      rport=";rport";
      break;
    }
    case SOCK_STREAM:
    {
      transport="TCP";
      break;
    }
    default:
    {
      LogError("Unsupported socket type, only TCP and UDP are supported\n");
      return TRUE;
    }
  }

  myip= socket_get_local_host(s);

  if(socket_print(s,
    "OPTIONS %s:%s SIP/2.0\r\n"
    "Via: SIP/2.0/%s %s:%d;branch=z9hG4bKh%u%s\r\n"
    "Max-Forwards: %d\r\n"
    "To: <%s:%s>\r\n"
    "From: monit <%s:monit@%s>;tag=%d\r\n"
    "Call-ID: %u\r\n"
    "CSeq: 63104 OPTIONS\r\n"
    "Contact: <%s:%s:%d>\r\n"
    "Accept: application/sdp\r\n"
    "Content-Length: 0\r\n"
    "User-Agent: %s/%s\r\n\r\n",
    proto,            // protocol
    request,          // to
    transport,        // via transport udp|tcp
    myip,             // who its from
    port,             // our port
    random(),         // branch
    rport,            // rport option
    P->maxforward,    // maximum forwards
    proto,            // protocol
    request,          // to
    proto,            // protocol
    myip,             // from host
    random(),         // tag
    random(),         // call id
    proto,            // protocol
    myip,             // contact host
    port,             // contact port
    prog, VERSION     // user agent
    ) < 0) {
    LogError("SIP: error sending data -- %s\n", STRERROR);
    return FALSE;
  }

  if(! socket_readln(s, buf, sizeof(buf))) {
    LogError("SIP: error receiving data -- %s\n", STRERROR);
    return FALSE;
  }

  Util_chomp(buf);

  DEBUG("Response from SIP server: %s\n", buf);

  if(! sscanf(buf, "%*s %d", &status)) { 
    LogError("SIP error: cannot parse SIP status in response: %s\n", buf);
    return FALSE;
  }

  if(status >= 400) {
    LogError("SIP error: Server returned status %d\n", status);
    return FALSE;
  }

  if(status >= 300 && status < 400) {
    LogError("SIP info: Server redirection. Returned status %d\n", status); 
    return FALSE;
  }

  if(status > 100 && status < 200) {
    LogError("SIP error: Provisional response . Returned status %d\n", status);
    return FALSE;
  }

  return TRUE;

}
