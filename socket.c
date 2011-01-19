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

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif 

#ifdef HAVE_STRINGS_H
#include <strings.h>
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

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif


#include "net.h"
#include "ssl.h"
#include "monitor.h"
#include "socket.h"



/**
 * Implementation of the socket interface.
 * 
 * @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 * @file
 */


/* ------------------------------------------------------------- Definitions */

#define TYPE_LOCAL   0
#define TYPE_ACCEPT  1
#define RBUFFER_SIZE 1024

struct Socket_T {
  int port;
  int type;
  int socket;
  char *host;
  Port_T Port;
  int timeout;
  int connection_type;
  ssl_connection *ssl;
  ssl_server_connection *sslserver;
  int length;
  int offset;
  unsigned char buffer[RBUFFER_SIZE+1];
};


/* -------------------------------------------------------------- Prototypes */


static int fill(Socket_T S, int timeout);


/* ------------------------------------------------------------------ Public */


Socket_T socket_new(const char *host, int port, int type, int use_ssl,
                    int timeout) {
  
  Ssl_T ssl;    
  
  ssl.use_ssl= use_ssl;
  ssl.version= SSL_VERSION_AUTO;
  ssl.certmd5= NULL;
  
  return socket_create_t(host, port, type, ssl, timeout);
  
}


Socket_T socket_create(void *port) {
  
  int s;
  Port_T p= port;
  
  ASSERT(port);
  
  if((s= create_generic_socket(p)) != -1) {
    
    Socket_T S= NULL;
    
    NEW(S);
    S->socket= s;
    S->length= 0;
    S->offset= 0;
    S->type= p->type;
    S->port= p->port;
    S->timeout= p->timeout;
    S->connection_type= TYPE_LOCAL;
    
    if(p->family==AF_UNIX) {
      S->host= xstrdup(LOCALHOST);
    } else {
      S->host= xstrdup(p->hostname);
    }
    
    if(p->SSL.use_ssl && !socket_switch2ssl(S, p->SSL)) {
      socket_free(&S);
      return NULL;
    }
    
    S->Port= port;
    return S;
  }
  
  return NULL;
}


Socket_T socket_create_t(const char *host, int port, int type, Ssl_T ssl,
                         int timeout) {
  
  int s;
  int proto= type==SOCKET_UDP?SOCK_DGRAM:SOCK_STREAM;
  
  ASSERT(host);
  ASSERT((type==SOCKET_UDP)||(type==SOCKET_TCP));
  if(ssl.use_ssl) {
    ASSERT(type==SOCKET_TCP);
  }
  ASSERT(timeout>0);
  
  if((s= create_socket(host, port, proto, timeout)) != -1) {
    
    Socket_T S= NULL;
    
    NEW(S);
    S->socket= s;
    S->length= 0;
    S->offset= 0;
    S->port= port;
    S->type= proto;
    S->timeout= timeout;
    S->host= xstrdup(host);
    S->connection_type= TYPE_LOCAL;
    
    if(ssl.use_ssl && !socket_switch2ssl(S, ssl)) {
      socket_free(&S);
      return NULL;
    }
    
    return S;
  }
  
  return NULL;
}


Socket_T socket_create_a(int socket, const char *remote_host,
                         int port, void *sslserver) {
  
  Socket_T S;
  
  ASSERT(socket>=0);
  ASSERT(remote_host);
  
  NEW(S);
  S->length= 0;
  S->offset= 0;
  S->port= port;
  S->socket= socket;
  S->type= SOCK_STREAM;
  S->timeout= NET_TIMEOUT;
  S->host= xstrdup(remote_host);
  S->connection_type= TYPE_ACCEPT;
  
  if(sslserver) {
    S->sslserver= sslserver;
    if(! (S->ssl= insert_accepted_ssl_socket(S->sslserver))) {
      goto ssl_error;
    }
    if(! embed_accepted_ssl_socket(S->ssl, S->socket)) {
      goto ssl_error;
    }
  }
  
  return S;
  
ssl_error:
    socket_free(&S);
  return NULL;
  
}


void socket_free(Socket_T *S) {
  
  ASSERT(S && *S);
  
#ifdef HAVE_OPENSSL
  if((*S)->ssl && (*S)->ssl->handler) {
    if((*S)->connection_type==TYPE_LOCAL) {
      close_ssl_socket((*S)->ssl);
      delete_ssl_socket((*S)->ssl);
    } else if((*S)->connection_type==TYPE_ACCEPT && (*S)->sslserver) {
      close_accepted_ssl_socket((*S)->sslserver, (*S)->ssl);
    }
  } else
#endif
  
  close_socket((*S)->socket);
  FREE((*S)->host);
  FREE(*S);
  
}


/* ------------------------------------------------------------ Properties */


int socket_is_ready(Socket_T S) {
  
  ASSERT(S);
  
  switch(S->type) {
    
    case SOCK_STREAM:
      return check_socket(S->socket);
      
    case SOCK_DGRAM:
      return check_udp_socket(S->socket);
      
    default:
      break;
  }
  
  return FALSE;
  
}


int socket_is_secure(Socket_T S) {
  
  ASSERT(S);
  
  return (S->ssl != NULL);
  
}


int socket_get_socket(Socket_T S) {
  
  ASSERT(S);
  
  return S->socket;
  
}


int socket_get_type(Socket_T S) {
  
  ASSERT(S);
  
  return S->type;
  
}


void *socket_get_Port(Socket_T S) {
  
  ASSERT(S);
  
  return S->Port;
  
}


int socket_get_remote_port(Socket_T S) {
  
  ASSERT(S);
  
  return S->port;
  
}


const char *socket_get_remote_host(Socket_T S) {
  
  ASSERT(S);
  
  return S->host;
  
}


int socket_get_local_port(Socket_T S) {
  struct sockaddr sock;
  socklen_t len = sizeof(sock);

  ASSERT(S);

  if(getsockname (S->socket, &sock, &len ) == 0)
    return ntohs (((struct sockaddr_in *)&sock)->sin_port);
  return -1;
  
}


const char *socket_get_local_host(Socket_T S) {
  struct sockaddr sock;
  socklen_t len = sizeof(sock);

  ASSERT(S);

  if(getsockname(S->socket, &sock, &len) == 0) 
    return inet_ntoa(((struct sockaddr_in *)&sock)->sin_addr);
  return NULL;
  
}


/* ---------------------------------------------------------------- Public */


int socket_switch2ssl(Socket_T S, Ssl_T ssl)  {

  if(! (S->ssl= new_ssl_connection(NULL, ssl.version)))
    return FALSE;

  if(! embed_ssl_socket(S->ssl, S->socket))
    return FALSE;

  if(ssl.certmd5 && !check_ssl_md5sum(S->ssl, ssl.certmd5)) {
    LogError("md5sum of certificate does not match!");
    return FALSE;
  }
  
  return TRUE;
}


int socket_print(Socket_T S, const char *m, ...) {
  
  int n;
  long l;
  va_list ap;
  char *buf= NULL;
  
  ASSERT(S);
  ASSERT(m);
  
  va_start(ap, m);
  buf= Util_formatString(m, ap, &l);
  va_end(ap);
  
  n= socket_write(S, buf, l);
  FREE(buf);
  
  return n;
  
}


int socket_write(Socket_T S, void *b, int size) {
  
  int n= 0;
  void *p= b;
  
  ASSERT(S);
  
  /* Clear any extra data read from the server */
  socket_reset(S);

  while(size > 0) {
    
    if(S->ssl) {
      n= send_ssl_socket(S->ssl, p, size, S->timeout);
    } else {
      if(S->type==SOCK_DGRAM)
        n= udp_write(S->socket,  p, size, S->timeout);
      else
        n= sock_write(S->socket,  p, size, S->timeout);
    }
    
    if(n <= 0) break;
    p+= n;
    size-= n;
    
  }
  
  if(n < 0) {
    /* No write or a partial write is an error */
    return -1;
  }
  
  return  (int)(p - b);
  
}


int socket_read_byte(Socket_T S) {
  
  ASSERT(S);
  
  if(S->offset >= S->length) {
    if(fill(S, S->timeout) <= 0)
      return -1;
  }
  
  return S->buffer[S->offset++];
  
}


int socket_read(Socket_T S, void *b, int size) {
  
  int c;
  unsigned char *p= b;
  
  ASSERT(S);
  
  while((size-- > 0) && ((c= socket_read_byte(S)) >= 0)) { 
    *p++= c;
  }
  
  return  (long)p - (long)b;
  
}


char *socket_readln(Socket_T S, char *s, int size) {
  
  int c;
  unsigned char *p= (unsigned char *)s;
  
  ASSERT(S);
  
  while(--size && ((c= socket_read_byte(S)) > 0)) { // Stop when \0 is read
    *p++= c;
    if(c == '\n')
      break;
  }
  
  *p= 0;
  
  if(*s)
    return s;
  
  return NULL;
  
}


void socket_reset(Socket_T S) {

  ASSERT(S);
  
  /* Throw away any pending incomming data */
  while(fill(S, 0) > 0);
  S->offset= 0;
  S->length= 0;
  
}


int socket_shutdown_write(Socket_T S) {
        ASSERT(S);
        return (shutdown(S->socket, 1) == 0);
}


/* --------------------------------------------------------------- Private */


/*
 * Fill the internal buffer. If an error occurs or if the read
 * operation timed out -1 is returned.
 * @param S A Socket object
 * @param timeout The number of seconds to wait for data to be read
 * @return TRUE (the length of data read) or -1 if an error occured
 */
static int fill(Socket_T S, int timeout) {
  
  int n;
  
  S->offset= 0;
  S->length= 0;
  /* Optimizing, assuming a request/response pattern and that a udp_write
     was issued before we are called, we don't have to wait for data */
  if(S->type==SOCK_DGRAM) timeout= 0; 
  
  /* Read as much as we can, but only block on the first read */
  while(RBUFFER_SIZE > S->length) {
    
    if(S->ssl) {
      n= recv_ssl_socket(S->ssl, S->buffer + S->length, 
                         RBUFFER_SIZE-S->length, timeout);
    } else {
      n= sock_read(S->socket, S->buffer + S->length, 
                   RBUFFER_SIZE-S->length, timeout);
    }
    
    timeout= 0;
    
    if(n > 0) {
      S->length+= n;
      continue;
    }  else if(n < 0) {
      if(errno == EAGAIN || errno == EWOULDBLOCK || S->type==SOCK_DGRAM) break;
      return -1;
    } else
      break;

  }
  
  return S->length;
  
}
