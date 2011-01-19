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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include "monitor.h"
#include "net.h"
#include "engine.h"

/* Private prototypes */
static void *thread_wrapper(void *arg);

/* The HTTP Thread */
static pthread_t thread;

static volatile int running = FALSE;


/**
 *  Facade functions for the cervlet sub-system. Start/Stop the monit
 *  http server and check if monit http can start.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *
 *  @file
 */


/* ------------------------------------------------------------------ Public */


/**
 * @return TRUE if the monit http can start and is specified in the
 * controlfile to start, otherwise return FALSE. Print an error
 * message if monit httpd _should_ start but can't.
 */
int can_http() {

  if(Run.dohttpd && Run.isdaemon) {
    
    if(! has_hosts_allow() && ! Run.credentials) {
      
      LogError("%s: monit httpd not started since no connect allowed\n",
	  prog);
      
      return FALSE;
      
    }
    
    return TRUE;
    
  }
  
  return FALSE;
  
}


/**
 * Start and stop the monit http server
 * @param action START_HTTP or STOP_HTTP
 */
void monit_http(int action) {

  int status;

  switch(action) {
    
  case STOP_HTTP:
    if(!running) break;
    LogInfo("Shutting down %s HTTP server\n", prog);
    stop_httpd();
    if( (status= pthread_join(thread, NULL)) != 0) {
      LogError("%s: Failed to stop the http server. Thread error -- %s.\n",
          prog, strerror(status));
    } else {
      LogInfo("%s HTTP server stopped\n", prog);
      running = FALSE;
    }
    break;

  case START_HTTP:
    LogInfo("Starting %s HTTP server at [%s:%d]\n",
        prog, Run.bind_addr?Run.bind_addr:"*", Run.httpdport);
    if( (status= pthread_create(&thread, NULL, thread_wrapper, NULL)) != 0) {
      LogError("%s: Failed to create the http server. Thread error -- %s.\n",
          prog, strerror(status));
    } else {
      LogInfo("%s HTTP server started\n", prog);
      running = TRUE;
    }
    break;

  default:
    LogError("%s: Unknown http server action\n", prog);
    break;
      
  }

  return;

}


/* ----------------------------------------------------------------- Private */


static void *thread_wrapper(void *arg) {

  sigset_t ns;

  /* Block collective signals in the http thread. The http server is
   * taken down gracefully by signaling the main monit thread */
  set_signal_block(&ns, NULL);
  start_httpd(Run.httpdport, 1024, Run.bind_addr);

  return NULL;

}

  
