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

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "monitor.h"
#include "net.h"
#include "socket.h"
#include "event.h"


/**
 *  Methods for controlling services managed by monit.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Rory Toma, <rory@digeo.com>
 *  @author Martin Pala, <martinp@tildeslash.com>
 *
 *  @file
 */


/* -------------------------------------------------------------- Prototypes */


static void do_start(Service_T);
static int  do_stop(Service_T);
static void do_monitor(Service_T);
static void do_unmonitor(Service_T);
static void wait_start(Service_T);
static int  wait_stop(Service_T);
static void do_depend(Service_T, int);


/* ------------------------------------------------------------------ Public */


/**
 * Pass on to methods in http/cervlet.c to start/stop services
 * @param S A service name as stated in the config file
 * @param action A string describing the action to execute
 * @return FALSE for error, otherwise TRUE
 */
int control_service_daemon(const char *S, const char *action) {
  int rv = FALSE;
  int status, content_length = 0;
  Socket_T s;
  char *auth;
  char buf[STRLEN];
  
  ASSERT(S);
  ASSERT(action);
  
  if (Util_getAction(action) == ACTION_IGNORE) {
    LogError("%s: Cannot %s service '%s' -- invalid action %s\n", prog, action, S, action);
    return FALSE;
  }
  
  s = socket_new(Run.bind_addr ? Run.bind_addr : "localhost", Run.httpdport, SOCKET_TCP, Run.httpdssl, NET_TIMEOUT);
  if (!s) {
    LogError("%s: Cannot connect to the monit daemon. Did you start it with http support?\n", prog);
    return FALSE;
  }

  /* Send request */
  auth = Util_getBasicAuthHeaderMonit();
  if (socket_print(s,
        "POST /%s HTTP/1.0\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: %d\r\n"
        "%s"
        "\r\n"
        "action=%s",
        S,
        strlen("action=") + strlen(action),
        auth ? auth : "",
        action) < 0) {
    LogError("%s: Cannot send the command '%s' to the monit daemon -- %s", prog, action ? action : "null", STRERROR);
    goto err1;
  }

  /* Process response */
  if (! socket_readln(s, buf, STRLEN)) {
    LogError("%s: error receiving data -- %s\n", prog, STRERROR);
    goto err1;
  }
  Util_chomp(buf);
  if (! sscanf(buf, "%*s %d", &status)) {
    LogError("%s: cannot parse status in response: %s\n", prog, buf);
    goto err1;
  }
  if (status >= 300) {
    char *message = NULL;

    /* Skip headers */
    while (socket_readln(s, buf, STRLEN)) {
      if (! strncmp(buf, "\r\n", sizeof(buf)))
        break;
      if(Util_startsWith(buf, "Content-Length") && ! sscanf(buf, "%*s%*[: ]%d", &content_length))
        goto err1;
    }
    if (content_length > 0 && content_length < 1024 && socket_readln(s, buf, STRLEN)) {
      char token[] = "</h2>";
      char *p = strstr(buf, token);

      if (strlen(p) <= strlen(token))
        goto err2;
      p += strlen(token);
      message = xcalloc(sizeof(unsigned char), content_length + 1);
      snprintf(message, content_length + 1, "%s", p);
      p = strstr(message, "<p>");
      if (p)
        *p = 0;
    }
err2:
    LogError("%s: action failed -- %s\n", prog, message ? message : "unable to parse response");
    FREE(message);
  } else
    rv = TRUE;
err1:
  FREE(auth);
  socket_free(&s);

  return rv;
}


/**
 * Check to see if we should try to start/stop service
 * @param S A service name as stated in the config file
 * @param A A string describing the action to execute
 * @return FALSE for error, otherwise TRUE
 */
int control_service_string(const char *S, const char *A) {
  int a;

  ASSERT(S);
  ASSERT(A);

  if ((a = Util_getAction(A)) == ACTION_IGNORE) {
    LogError("%s: service '%s' -- invalid action %s\n", prog, S, A);
    return FALSE;
  }
  return control_service(S, a);
}


/**
 * Check to see if we should try to start/stop service
 * @param S A service name as stated in the config file
 * @param A An action id describing the action to execute
 * @return FALSE for error, otherwise TRUE
 */
int control_service(const char *S, int A) {
  Service_T s = NULL;

  ASSERT(S);

  if (! (s = Util_getService(S))) {
    LogError("%s: service '%s' -- doesn't exist\n", prog, S);
    return FALSE;
  }

  switch(A) {

    case ACTION_START:
      if (s->type == TYPE_PROCESS) {
        if (Util_isProcessRunning(s, FALSE)) {
          DEBUG("%s: Process already running -- process %s\n", prog, S);
          Util_monitorSet(s);
          return TRUE;
        }
        if (!s->start) {
          LogError("%s: Start method not defined -- process %s\n", prog, S);
          Util_monitorSet(s);
          return FALSE;
        }
      }
      do_depend(s, ACTION_STOP);
      do_start(s);
      do_depend(s, ACTION_START);
      break;

    case ACTION_STOP:
      if (s->type == TYPE_PROCESS && !s->stop) {
        LogError("%s: Stop method not defined -- process %s\n", prog, S);
        Util_monitorUnset(s);
        return FALSE;
      }
      /* soft unmonitor and stop: */
      do_depend(s, ACTION_STOP);
      do_stop(s);
      /* hard unmonitor - will reset all counters and flags: */
      do_depend(s, ACTION_UNMONITOR);
      do_unmonitor(s);
      break;

    case ACTION_RESTART:
      if (s->type == TYPE_PROCESS && (!s->start || !s->stop)) {
        LogError("%s: Start or stop method not defined -- process %s\n", prog, S);
        Util_monitorSet(s);
        return FALSE;
      }
      LogInfo("'%s' trying to restart\n", s->name);
      do_depend(s, ACTION_STOP);
      if (do_stop(s)) {
        /* Only start if stop succeeded */
        do_start(s);
        do_depend(s, ACTION_START);
      } else {
        /* enable monitoring of this service again to allow the restart retry
         * in the next cycle up to timeout limit */
        Util_monitorSet(s);
      }
      break;

    case ACTION_MONITOR:
      /* We only enable monitoring of this service and all prerequisite
       * services. Chain of services which depends on this service keep
       * its state */
      do_monitor(s);
      break;

    case ACTION_UNMONITOR:
      /* We disable monitoring of this service and all services which
       * depends on it */
      do_depend(s, ACTION_UNMONITOR);
      do_unmonitor(s);
      break;

    default:
      LogError("%s: service '%s' -- invalid action %s\n", prog, S, A);
      return FALSE;
  }
  return TRUE;
}


/*
 * Reset the visited flags used when handling dependencies
 */
void reset_depend() {
  Service_T s;
  
  for (s = servicelist; s; s = s->next) {
    s->visited = FALSE;
    s->depend_visited = FALSE;
  }
}


/* ----------------------------------------------------------------- Private */


/*
 * This is a post- fix recursive function for starting every service
 * that s depends on before starting s.
 * @param s A Service_T object
 */
static void do_start(Service_T s) {
  ASSERT(s);

  if (s->visited)
    return;
  
  s->visited = TRUE;
  
  if (s->dependantlist) {
    Dependant_T d;
    
    for (d = s->dependantlist; d; d = d->next ) {
      Service_T parent = Util_getService(d->dependant);
      ASSERT(parent);
      do_start(parent);
    }
  }
  
  if (s->start && (s->type!=TYPE_PROCESS || !Util_isProcessRunning(s, FALSE))) {
    LogInfo("'%s' start: %s\n", s->name, s->start->arg[0]);
    spawn(s, s->start, NULL);
    /* We only wait for a process type, other service types does not have a pid file to watch */
    if (s->type == TYPE_PROCESS)
      wait_start(s);
  }
  Util_monitorSet(s);
}


/*
 * This function simply stops the service p.
 * @param s A Service_T object
 * @return TRUE if the service was stopped otherwise FALSE
 */
static int do_stop(Service_T s) {
  ASSERT(s);

  if (s->depend_visited)
    return TRUE;
 
  s->depend_visited = TRUE;

  /* do soft unmonitor - start counter and error state is kept */
  if (s->monitor != MONITOR_NOT) {
    s->monitor = MONITOR_NOT;
    DEBUG("Monitoring disabled -- service %s\n", s->name);
  } 

  if (s->stop && (s->type!=TYPE_PROCESS || Util_isProcessRunning(s, FALSE))) {
    LogInfo("'%s' stop: %s\n", s->name, s->stop->arg[0]);
    spawn(s, s->stop, NULL);
    if (s->type == TYPE_PROCESS) {
      /* Only wait for process service types */
      if (!wait_stop(s))
        return FALSE;
    }
  }
  Util_resetInfo(s);

  return TRUE;
}


/*
 * This is a post- fix recursive function for enabling monitoring every service
 * that s depends on before monitor s.
 * @param s A Service_T object
 */
static void do_monitor(Service_T s) {
  ASSERT(s);

  if (s->visited)
    return;
  
  s->visited = TRUE;
  
  if (s->dependantlist) {
    Dependant_T d;
    
    for (d = s->dependantlist; d; d = d->next ) {
      Service_T parent = Util_getService(d->dependant);
      ASSERT(parent);
      do_monitor(parent);
    }
  }
  Util_monitorSet(s);
}


/*
 * This is a function for disabling monitoring
 * @param s A Service_T object
 */
static void do_unmonitor(Service_T s) {
  ASSERT(s);

  if (s->depend_visited)
    return;
 
  s->depend_visited = TRUE;
  Util_monitorUnset(s);
}


/*
 * This is an in-fix recursive function called before s is started to
 * stop every service that depends on s, in reverse order *or* after s
 * was started to start again every service that depends on s. The
 * action parametere controls if this function should start or stop
 * the procceses that depends on s.
 * @param s A Service_T object
 * @param action An action to do on the dependant services
 */
static void do_depend(Service_T s, int action) {
  Service_T child;
  
  ASSERT(s);

  for (child = servicelist; child; child = child->next) {
    if (child->dependantlist) {
      Dependant_T d;
    
      for (d = child->dependantlist; d; d = d->next) {
	if (IS(d->dependant, s->name)) {
	  if (action == ACTION_START)
	    do_start(child);
          else if (action == ACTION_MONITOR)
	    do_monitor(child);
	  do_depend(child, action);
	  if (action == ACTION_STOP)
	    do_stop(child);
          else if (action == ACTION_UNMONITOR)
	    do_unmonitor(child);
	  break;
	}
      }
    }
  }
}
    

/*
 * This function runs in its own thread and waits for the service to
 * start running. If the service did not start a failed event is
 * posted to notify the user.
 * @param service A Service to wait for
 */
static void wait_start(Service_T s) {
  int            isrunning = FALSE;
  time_t         timeout = time(NULL) + s->start->timeout;
  
  ASSERT(s);

  while ((time(NULL) < timeout) && !Run.stopped) {
    if ((isrunning = Util_isProcessRunning(s, TRUE)))
      break;
    sleep(1);
  }
  
  if (! isrunning)
    Event_post(s, Event_Exec, STATE_FAILED, s->action_EXEC, "failed to start");
  else
    Event_post(s, Event_Exec, STATE_SUCCEEDED, s->action_EXEC, "started");
}


/*
 * This function waits for the service to stop running. If the service
 * did not stop a failed event is posted to notify the user. This
 * function does purposefully not run in its own thread because, if we
 * did a restart we need to know if we successfully managed to stop
 * the service first before we can do a start.
 * @param service A Service to wait for
 * @return TRUE if the service was stopped otherwise FALSE
 */
static int wait_stop(Service_T s) {
  int            isrunning = TRUE;
  time_t         timeout = time(NULL) + s->stop->timeout;
  
  ASSERT(s);

  while ((time(NULL) < timeout) && !Run.stopped) {
    if (! (isrunning = Util_isProcessRunning(s, TRUE)))
      break;
    sleep(1);
  }

  if (isrunning) {
    Event_post(s, Event_Exec, STATE_FAILED, s->action_EXEC, "failed to stop");
    return FALSE;
  } else {
    Event_post(s, Event_Exec, STATE_SUCCEEDED, s->action_EXEC, "stopped");
  }

  return TRUE;
}

