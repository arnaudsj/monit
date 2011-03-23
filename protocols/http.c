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

#ifdef HAVE_REGEX_H
#include <regex.h>
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

#include "md5.h"
#include "sha.h"
#include "base64.h"
#include "protocol.h"
#include "httpstatus.h"


/**
 *  A HTTP test.
 *
 *  We send the following request to the server:
 *  'GET / HTTP/1.1'             ... if request statement isn't defined
 *  'GET /custom/page  HTTP/1.1' ... if request statement is defined
 *  and check the server's status code.
 *
 *  If the statement defines hostname, it's used in the 'Host:' header
 * otherwise a default (empty) Host header is set.
 *
 *  If the status code is >= 400, an error has occurred.
 *  Return TRUE if the status code is OK, otherwise FALSE.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Martin Pala, <martinp@tildeslash.com>
 *  @file
 */



/* ------------------------------------------------------------- Definitions */


#undef   READ_SIZE
#define  READ_SIZE  8192
#define  LINE_SIZE  512


/* -------------------------------------------------------------- Prototypes */


static int check_request(Socket_T s, Port_T P);
static char *get_auth_header(Port_T P, char *auth, int l);
static int do_regex(Socket_T s, long content_length, Request_T R);
static int check_request_checksum(Socket_T s, long content_length, char *checksum, int hashtype);


/* ------------------------------------------------------------------ Public */


int check_http(Socket_T s) {

  Port_T P;
  char host[STRLEN];
  char auth[STRLEN]= {0};
  const char *request= NULL;
  const char *hostheader= NULL;
  
  ASSERT(s);

  P= socket_get_Port(s);

  ASSERT(P);
  
  request= P->request?P->request:"/";
        
  Util_getHTTPHostHeader(s, host, STRLEN);
  hostheader= P->request_hostheader?P->request_hostheader:host;
 
  if(socket_print(s, 
		  "GET %s HTTP/1.1\r\n"
		  "Host: %s\r\n"
		  "Accept: */*\r\n"
		  "Connection: close\r\n"
		  "User-Agent: %s/%s\r\n"
		  "%s\r\n",
		  request, hostheader, prog, VERSION,
                  get_auth_header(P, auth, STRLEN)) < 0) {
    LogError("HTTP: error sending data -- %s\n", STRERROR);
    return FALSE;
  }

  return check_request(s, P);
  
}


/* ----------------------------------------------------------------- Private */


/**
 * Check that the server returns a valid HTTP response as well as checksum
 * or content regex if required
 * @param s A socket
 * @return TRUE if the response is valid otherwise FALSE
 */
static int check_request(Socket_T s, Port_T P) {

  int status;
  char buf[LINE_SIZE];
  long content_length= -1;

    if(! socket_readln(s, buf, LINE_SIZE)) {
      LogError("HTTP: error receiving data -- %s\n", STRERROR);
      return FALSE;
    }

    Util_chomp(buf);

    if(! sscanf(buf, "%*s %d", &status)) {
      LogError("HTTP error: cannot parse HTTP status in response: %s\n", buf);
      return FALSE;
    }
         
    if(status >= 400) {
      LogError("HTTP error: Server returned status %d\n", status);
      return FALSE;
    }
        
    /* Get Content-Length header value */
    while(NULL != socket_readln(s, buf, LINE_SIZE)) {

      if((buf[0] == '\r' && buf[1] == '\n') || (buf[0] == '\n'))
        break;

      Util_chomp(buf);

      if(Util_startsWith(buf, "Content-Length")) {
        if(! sscanf(buf, "%*s%*[: ]%ld", &content_length)) {
          LogError("HTTP error: parsing Content-Length response header '%s'\n",
            buf);
          return FALSE;
        }
        if(content_length < 0) {
          LogError("HTTP error: Illegal Content-Length response header '%s'\n",
            buf);
          return FALSE;
        }
      }

    }
  
    if(P->url_request && P->url_request->regex) {
      if(! do_regex(s, content_length, P->url_request)) {
        LogError("HTTP error: Failed regular expression test on content"
          " returned from server\n");
        return FALSE;
      }
    }

    if(P->request_checksum) {  
      return check_request_checksum(s, content_length, P->request_checksum, 
        P->request_hashtype); 
    }

    return TRUE;

}


static int check_request_checksum(Socket_T s, long content_length, char *checksum, int hashtype) {

  int n;
  long size;
  MD_T result;
  char buf[READ_SIZE];
  unsigned char hash[STRLEN];
  int  keylength=0;
  
  if(content_length <= 0) {
    DEBUG("HTTP warning: Response does not contain a valid Content-Length\n"
      "Cannot compute checksum\n");
    return TRUE;
  }
  
  switch (hashtype) {
    case HASH_MD5:
    {
      struct md5_ctx ctx;
      md5_init_ctx(&ctx);
      while(content_length > 0) {
        size= content_length>READ_SIZE?READ_SIZE:content_length;
        n= socket_read(s, buf, size);
        if(n<0) break;
        md5_process_bytes(buf, n, &ctx);
        content_length -= n; 
      }
      md5_finish_ctx(&ctx, hash);
      keylength=16; /* Raw key bytes not string chars! */
      break;
    }
    case HASH_SHA1: 
    {
      struct sha_ctx ctx;
      sha_init_ctx(&ctx);
      while(content_length > 0) {
        size= content_length>READ_SIZE?READ_SIZE:content_length;
        n= socket_read(s, buf, size);
        if(n<0) break;
        sha_process_bytes(buf, n, &ctx);
        content_length -= n; 
      }
      sha_finish_ctx(&ctx, hash);
      keylength=20; /* Raw key bytes not string chars! */
      break;
    }
    default:
    DEBUG("HTTP warning: Unknown hash type\n");
    return FALSE;
  }          

  if(strncasecmp(Util_digest2Bytes(hash, keylength, result), checksum, keylength*2) != 0) {
    DEBUG("HTTP warning: Document checksum mismatch\n");
    return FALSE;
  } else {
    DEBUG("HTTP: Succeeded testing document checksum\n");
  }

  return TRUE;

}


static int do_regex(Socket_T s, long content_length, Request_T R) {

  int n;
  int size= 0;
  int rv= TRUE;
  int length= 0;
  char *buf= NULL;
#ifdef HAVE_REGEX_H
  int regex_return;
#else
  char *regex_return;
#endif

  if(R->regex == NULL) {
    return TRUE;
  }

  if(content_length == 0) {
    LogError("HTTP error: Cannot test regex -- No content returned "
      "from server\n");
    return FALSE;
  }
 
  if(content_length < 0) /* Not defined in response */
    content_length= HTTP_CONTENT_MAX;
  else if(content_length > HTTP_CONTENT_MAX)
    content_length= HTTP_CONTENT_MAX;
  
  size= 0;
  length= content_length;
  buf= xmalloc(content_length + 1);
  
  do {
      n= socket_read(s, &buf[size], length);
      if(n<=0)
        break;
      size+= n;
      length-= n;
  } while(length>0);
  
  if(size==0) {
    rv= FALSE;
    LogError("HTTP: error receiving data -- %s\n", STRERROR);
    goto error;
  }
  buf[size]= 0;

#ifdef HAVE_REGEX_H

      regex_return=regexec(R->regex,
			   buf,
			   0,
			   NULL,
			   0);
      switch(R->operator) {

      case OPERATOR_EQUAL:
	if(regex_return!=0) {
	  rv= FALSE;
	} else {
	  DEBUG("HTTP: Regular expression test succeeded\n");
	  
	}
	break;

      case OPERATOR_NOTEQUAL:
	if(regex_return == 0) {
	  rv= FALSE;
	} else {
	  DEBUG("HTTP: Regular expression test succeeded\n");
	  
	}
	break;

      default:
	LogError("HTTP error: Invalid content operator\n");
      }
	
#else
      /* w/o regex support */

      regex_return= strstr(buf, R->regex);
      switch(R->operator) {

      case OPERATOR_EQUAL:
	if(!regex_return) {
	  rv= FALSE;
	  DEBUG("HTTP: Regular expression does not match\n");
	}
	break;

      case OPERATOR_NOTEQUAL:
	if(regex_return) {
	  rv= FALSE;
	  DEBUG("HTTP: Regular expression match\n");
	}
	break;

      default:
	LogError("HTTP error: Invalid content operator\n");
      }
      
#endif
  
error:
  FREE(buf);
  return rv;
  
}


static char *get_auth_header(Port_T P, char *auth, int l) {
  
  char *b64;
  char buf[STRLEN];
  char *username= NULL;
  char *password= NULL;
  
  if(P->url_request) {
    URL_T U=  P->url_request->url;
    if(U) {
      username= U->user;
      password= U->password;
    }
  }
      
  if(! (username && password)) {
    return auth;
  } 

  snprintf(buf, STRLEN, "%s:%s", username, password);
  if(! (b64= encode_base64(strlen(buf), (unsigned char *)buf)) ) {
    return auth;
  }

  snprintf(auth, l, "Authorization: Basic %s\r\n", b64);
  FREE(b64);
  
  return auth;

}
