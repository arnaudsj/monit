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
 *  Simple LDAPv2 protocol test.
 *
 *  Try anonymous bind to the server.
 *
 *  BindRequest based on RFC1777. Request and response are ASN.1
 *  BER encoded strings. To make the test as simple as possible
 *  we work with BER encoded data.
 *
 *  The test checks only if the bind was successfull - in the
 *  case of failure it don't provide any erroneous message
 *  analysis.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Martin Pala, <martinp@tildeslash.com>
 *
 *  @file
 */
int check_ldap2(Socket_T s) {

  unsigned char buf[STRLEN];

  unsigned char request[14] = {
    0x30,	                 /** Universal Sequence TAG */
    0x0c,	       /** Length of the packet's data part */

    0x02,	                  /** Universal Integer TAG */
    0x01,			   	 /** Integer length */
    0x00,		   	              /** MessageID */

    0x60,		    /** Application BindRequest TAG */
    0x07,		        /** Length of the data part */

    0x02,                         /** Universal Integer TAG */
    0x01,			         /** Integer length */
    0x02,			       /** Protocol version */	

    0x04,                    /** Universal Octet string TAG */
    0x00,      			    /** Octet string length */
    /* NULL */     	     	       /** Anonymous BindDN */

    0x80,	        /** Context specific SimpleAuth TAG */
    0x00     	       /** SimpleAuth (octet string) length */
    /* NULL */     	     	  /** Anonymous Credentials */
  };
    
  unsigned char response[14] = {
    0x30,	                 /** Universal Sequence TAG */
    0x0c,	       /** Length of the packet's data part */

    0x02,	                  /** Universal Integer TAG */
    0x01,			   	 /** Integer length */
    0x00,		   	              /** MessageID */

    0x61,		   /** Application BindResponse TAG */
    0x07,		        /** Length of the data part */

    0x0a,                      /** Universal Enumerated TAG */
    0x01,			      /** Enumerated length */
    0x00,			                /** Success */	

    0x04,                    /** Universal Octet string TAG */
    0x00,      			    /** Octet string length */
    /* NULL */     	     	              /** MatchedDN */

    0x04,                    /** Universal Octet string TAG */
    0x00      			    /** Octet string length */
    /* NULL */     	     	           /** ErrorMessage */
  };

  unsigned char unbind[7] = {
    0x30,                        /** Universal Sequence TAG */
    0x05,              /** Length of the packet's data part */

    0x02,                         /** Universal Integer TAG */
    0x01,                                /** Integer length */
    0x01,                                     /** MessageID */

    0x42,                 /** Application UnbindRequest TAG */
    0x00                        /** Length of the data part */
    /* NULL */

  };

  ASSERT(s);


  if(socket_write(s, (unsigned char *)request, sizeof(request)) < 0) {
    LogError("LDAP: error sending data -- %s\n", STRERROR);
    return FALSE;
  }

  if(socket_read(s, (unsigned char *)buf, sizeof(response)) <= 0) {
    LogError("LDAP: error receiving data -- %s\n", STRERROR);
    return FALSE;
  }

  if(memcmp((unsigned char *)buf,
	    (unsigned char *)response,
	    sizeof(response))) {
    LogError("LDAP: anonymous bind failed\n");
    return FALSE;
  }

  if(socket_write(s, (unsigned char *)unbind, sizeof(unbind)) < 0) {
    LogError("LDAP: error sending data -- %s\n", STRERROR);
    return FALSE;
  }

  return TRUE;
    
}

