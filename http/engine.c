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

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
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

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "engine.h"
#include "socket.h"


/**
 *  A naive http 1.0 server. The server delegates handling of a HTTP
 *  request and response to the processor module.
 *
 *  NOTE
 *    This server does not use threads or forks; Requests are
 *    serialized and pending requests will be popped from the
 *    connection queue when the current request finish.
 *
 *    Since this server is written for monit, low traffic is expected.
 *    Connect from not-authenicated clients will be closed down
 *    promptly. The authentication schema or access control is based
 *    on client name/address and only requests from known clients are
 *    accepted. Hosts allowed to connect to this server should be
 *    added to the access control list by calling add_host_allow().
 *
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Christian Hopp, <chopp@iei.tu-clausthal.de>
 *  @author Martin Pala <martinp@tildeslash.com>
 *
 *  @file 
 */


/* ------------------------------------------------------------- Definitions */


static int myServerSocket= 0;
static HostsAllow hostlist= NULL;
static volatile int stopped= FALSE;
ssl_server_connection *mySSLServerConnection= NULL;
static pthread_mutex_t hostlist_mutex= PTHREAD_MUTEX_INITIALIZER;
struct ulong_net {
  unsigned long network;
  unsigned long mask;
};


/* -------------------------------------------------------------- Prototypes */


static void check_Impl();
static void initialize_service();
static int  authenticate(const struct in_addr);
static int  is_host_allow(const struct in_addr);
static void destroy_host_allow(HostsAllow);
static Socket_T socket_producer(int, int, void*);
static int  parse_network(char *, struct ulong_net *);

/* ------------------------------------------------------------------ Public */


/**
 * Start the HTTPD server
 * @param port The Port number to start the server at
 * @param backlog The maximum length of the incomming connection queue 
 * @param bindAddr the local address the server will bind to
 */
void start_httpd(int port, int backlog, char *bindAddr) {

  Socket_T S= NULL;

  stopped= Run.stopped;

  if((myServerSocket= create_server_socket(port, backlog, bindAddr)) < 0) {
    
    LogError("http server: Could not create a server socket at port %d -- %s\n",
	port, STRERROR);
    
    LogError("monit HTTP server not available\n");
    
    if(Run.init) {
      
      sleep(1);
      kill_daemon(SIGTERM);
      
    }
    
  } else {
    
    initialize_service();
    
    if(Run.httpdssl) {
      
      mySSLServerConnection= init_ssl_server( Run.httpsslpem,
					      Run.httpsslclientpem);
      
      if(mySSLServerConnection == NULL) {
	
	LogError("http server: Could not initialize SSL engine\n");
	
	LogError("monit HTTP server not available\n");
	
	return;
      }
      
#ifdef HAVE_OPENSSL
      mySSLServerConnection->server_socket= myServerSocket;
#endif
    }
    
    while(! stopped) {
      
      if(!(S= socket_producer(myServerSocket, port, mySSLServerConnection))) {
	continue;
      }

      http_processor(S);
      
    }

    delete_ssl_server_socket(mySSLServerConnection);  
    close_socket(myServerSocket);

  }

}


/**
 * Stop the HTTPD server. 
 */
void stop_httpd() {

  stopped= TRUE;

}


/* -------------------------------------------------------------- Properties */


/**
 * Add hosts allowed to connect to this server.
 * @param name A hostname (A-Record) or IP address to be added to the
 * hosts allow list
 * @return FALSE if the given host does not resolve, otherwise TRUE
 */
int add_host_allow(char *name) {

  struct addrinfo hints;
  struct addrinfo *res;
  struct addrinfo *_res;

  ASSERT(name);

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = PF_INET; /* we support just IPv4 currently */

  if(getaddrinfo(name, NULL, &hints, &res) != 0)
    return FALSE;

  for(_res = res; _res; _res = _res->ai_next) {
    if(_res->ai_family == AF_INET) {
       HostsAllow h;
       struct sockaddr_in *sin = (struct sockaddr_in *)_res->ai_addr;

       NEW(h);      
       memcpy(&h->network, &sin->sin_addr, 4);
       h->mask=    0xffffffff;
       LOCK(hostlist_mutex)
       if(hostlist) {
         HostsAllow p, n;
         for(n= p= hostlist; p; n= p, p= p->next) {
           if((p->network == h->network) && ((p->mask == h->mask))) {
             DEBUG("%s: Debug: Skipping redundant host '%s'\n", prog, name); 
             destroy_host_allow(h);
             goto done;
           }
         }
         DEBUG("%s: Debug: Adding host allow '%s'\n", prog, name); 
         n->next= h;
       } else {
         DEBUG("%s: Debug: Adding host allow '%s'\n", prog, name);
        
         hostlist= h;
       }
       done:
       END_LOCK;
    }
  }

  freeaddrinfo(res);
  return TRUE;
}

/**
 * Add network allowed to connect to this server.
 * @param s_network A network identifier in IP/mask format to be added
 * to the hosts allow list
 * @return FALSE if no correct network identifier is provided,
 * otherwise TRUE
 */

int add_net_allow(char *s_network) {

  struct ulong_net net={0, 0};
  HostsAllow h;

  ASSERT(s_network);

  /* Add the network */

  if (!parse_network(s_network, &net)) {

    return FALSE;
    
  }

  NEW(h);

  h->network=net.network;
  h->mask=net.mask;
  
  LOCK(hostlist_mutex)
          
  if(hostlist) {
      
    HostsAllow p, n;
    
    for(n= p= hostlist; p; n= p, p= p->next) {
      
      if((p->network == net.network) && ((p->mask == net.mask))) {
	
        DEBUG("%s: Debug: Skipping redundant net '%s'.\n",
              prog, s_network); 
        destroy_host_allow(h);
        goto done;
	
      }
      
    }

    DEBUG("%s: Debug: Adding net allow '%s'.\n",
          prog, s_network); 
    
    n->next= h;
    
  } else {
    
    DEBUG("%s: Debug: Adding net allow '%s'.\n",
          prog, s_network); 

    hostlist= h;
    
  }

  done:
  END_LOCK;

  return TRUE;
}


/**
 * Are any hosts present in the host allow list?
 * @return TRUE if the host allow list is non-empty, otherwise FALSE
 */
int has_hosts_allow() {

  int rv;

  LOCK(hostlist_mutex)
      rv= (hostlist != NULL);
  END_LOCK;

  return rv;

}


/** 
 * Free the host allow list
 */
void destroy_hosts_allow() {

  if(has_hosts_allow()) {
    
    LOCK(hostlist_mutex)
	destroy_host_allow(hostlist);
        hostlist= NULL;
    END_LOCK;
    
  }

}

/* ----------------------------------------------------------------- Private */


/**
 * Setup the cervlet service and verify that a cervlet implementation
 * exist. Only one cervlet is supported in this version. In a standalone
 * versions this function will load cervlets from a repository and
 * initialize each cervlet.
 */
static void initialize_service() {

  init_service();
  check_Impl();

}


/**
 * Abort if no Service implementors are found
 */
static void check_Impl() {

  if((Impl.doGet == 0) || (Impl.doPost == 0)) {
    
    LogError("http server: Service Methods not implemented\n");
    _exit(1);
    
  }
  
}


/**
 * Returns TRUE if remote host is allowed to connect, otherwise return
 * FALSE. If allow Basic Authentication is defined in the Run.Auth
 * object, authentication is delegated to the processor module.
 */
static int authenticate(const struct in_addr addr) {

  if(is_host_allow(addr)) {

    return TRUE;
    
  }

  if(! has_hosts_allow() && (Run.credentials!=NULL)) {

    return TRUE;

  }

  LogError("%s: Denied connection from non-authorized client [%s]\n", prog,
      inet_ntoa(addr));
  
  return FALSE;

}


/**
 * Returns TRUE if host is allowed to connect to
 * this server
 */
static int is_host_allow(const struct in_addr addr) { 

  HostsAllow p;
  int rv= FALSE;

  LOCK(hostlist_mutex)
  
  for(p= hostlist; p; p= p->next) {

    if((p->network & p->mask) == (addr.s_addr & p->mask)) {

      rv= TRUE;
      break;
      
    }
    
  }

  END_LOCK;

  if (rv)
      return rv;
  
  return rv;

}


/**
 * Parse network string and return numeric IP and netmask
 * @param s_network A network identifier in IP/mask format to be parsed
 * @param net A structure holding IP and mask of the network
 * @return FALSE if parsing fails otherwise TRUE
 */
static int parse_network(char *s_network, struct ulong_net *net) {

  char *temp=NULL;
  char *copy=NULL;
  char *longmask=NULL;
  int   shortmask=0;
  int   slashcount=0;
  int   dotcount=0;
  int   count=0;
  int   rv=FALSE;
  struct in_addr inp;

  ASSERT(s_network);
  ASSERT(net);

  temp= copy= xstrdup(s_network);

  /* decide if we have xxx.xxx.xxx.xxx/yyy or
                       xxx.xxx.xxx.xxx/yyy.yyy.yyy.yyy */
  while (*temp!=0) {
    if (*temp=='/') {

      /* We have found a "/" -> we are preceeding to the netmask */
      
      if ((slashcount==1) || (dotcount !=3)) {

        /* We have already found a "/" or we haven't had enough dots
           before finding the slash -> Error! */
        
        goto done;
        
      }
      
      *temp=0;
      longmask= *(temp+1)?temp+1:NULL;
      count=0;
      slashcount=1;
      dotcount=0;

    } else if (*temp=='.') {

      /* We have found the next dot! */
      
      dotcount++;
      
    } else if (!isdigit((int)*temp)) {

      /* No number, "." or "/" -> Error! */
      
      goto done;
      
    }
    
    count++;
    temp++;
  }

  if (slashcount == 0) {

    /* We have just host portion */

    shortmask= 32;

  } else if ((dotcount==0) && (count > 1) && (count < 4)) {

    /* We have no dots but 1 or 2 numbers after the slash -> short netmask */

    if (longmask!=NULL) {
      
      shortmask=atoi(longmask);
      longmask=NULL;
      
    }
    
  } else if (dotcount != 3) {

    /* A long netmask requires three dots */
    
    goto done;
    
  }

  /* Parse the network */
  
  if (inet_aton(copy, &inp) == 0) {

    /* Failed! */
    goto done;

  }
  net->network=inp.s_addr;

  /* Convert short netmasks to integer */
  if (longmask==NULL) {
    
    if ((shortmask > 32) || (shortmask < 0)) {
      
      goto done;
      
    } else if ( shortmask == 32 ) {

      net->mask=-1;

    } else {
      
      net->mask= (1<<shortmask)-1;
      net->mask= htonl(net->mask<<(32-shortmask));

    }

  } else { 	 
  	 
    /* Parse long netmasks */ 	 
    if (inet_aton(longmask, &inp) == 0) { 	 

      goto done; 	 

    }

    net->mask=inp.s_addr;

  }

  /* Remove bogus network components */
  net->network&=net->mask;

  /* Everything went fine, so we return TRUE! */
  rv=TRUE;
  
  done:

  FREE(copy);
  return rv;
  
}

/* --------------------------------------------------------------- Factories */


/**
 * Accept connections from Clients and create a Socket_T object for
 * each successful accept. If accept fails, return a NULL object
 */
static Socket_T socket_producer(int server, int port, void *sslserver) {
  
  int client;
  struct sockaddr_in in;
  socklen_t len= sizeof(struct sockaddr_in);
  
  if(can_read(server, 1)) {
    
    if( (client= accept(server, (struct sockaddr*)&in, &len)) < 0) {

      if(stopped) {
        LogError("http server: service stopped\n");
      }  else {
        LogError("http server: cannot accept connection -- %s\n", STRERROR);
      }

      return NULL;

    }

  } else {

    /* If timeout or error occured, return NULL to allow the caller to
     * handle various states (such as stopped) which can occure in the
     * meantime */
    return NULL;

  }

  if(set_noblock(client) < 0) {
    goto error;
  }
  
  if(!check_socket(client)) {
    goto error;
  }
  
  if(! authenticate(in.sin_addr)) {
    goto error;
  }


  return socket_create_a(client, inet_ntoa(in.sin_addr), port, sslserver);

  error:
  close_socket(client);
  return NULL;

}


/* ----------------------------------------------------------------- Cleanup */


/**
 * Free a (linked list of) host_allow ojbect(s). 
 */
static void destroy_host_allow(HostsAllow p) {
  
  HostsAllow a= p; 
  
  if(a->next) {
    destroy_host_allow(a->next);
  }

  FREE(a);
 
}

