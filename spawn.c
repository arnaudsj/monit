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

#ifdef HAVE_SIGNAL_H
#include <signal.h>
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

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include "event.h"
#include "alert.h"
#include "monitor.h"
#include "engine.h"


/**
 *  Function for spawning of a process. This function fork's twice to
 *  avoid creating any zombie processes. Inspired by code from
 *  W. Richard Stevens book, APUE.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Peter Holdaway <pholdaway@technocom-wireless.com>
 *
 *  @file
 */


/* ------------------------------------------------------------- Definitions */


/* Do not exceed 8 bits here */
enum ExitStatus_E {
  setgid_ERROR   = 0x1,
  setuid_ERROR   = 0x2,
  redirect_ERROR = 0x4,
  fork_ERROR     = 0x8
};

typedef struct En {
  char env[STRLEN];
  struct En *next;
} *Environment_T;


/* -------------------------------------------------------------- Prototypes */


static void put_monit_environment(Environment_T e);
static void free_monit_environment(Environment_T *e);
static void push_monit_environment(const char *env, Environment_T *list);
static void set_monit_environment(Service_T s, Command_T C, Event_T event, Environment_T *e);


/* ------------------------------------------------------------------ Public */


/**
 * Execute the given command. If the execution fails, the wait_start()
 * thread in control.c should notice this and send an alert message.
 * @param P A Service object
 * @param C A Command object
 * @param E An optional event object. May be NULL.
 */
void spawn(Service_T S, Command_T C, Event_T E) {
  pid_t pid;
  sigset_t mask;
  sigset_t save;
  int stat_loc= 0;
  int exit_status;
  Environment_T environment= NULL;

  ASSERT(S);
  ASSERT(C);

  if(access(C->arg[0], X_OK) != 0) {
    LogError("Error: Could not execute %s\n", C->arg[0]);
    return;
  }

  /*
   * Block SIGCHLD
   */
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  pthread_sigmask(SIG_BLOCK, &mask, &save);

  set_monit_environment(S, C, E, &environment);

  pid= fork();
  if(pid < 0) {
    LogError("Cannot fork a new process\n");  
    exit(1); 
  }

  if(pid == 0) {
    /*
     * Reset to the original umask so programs will inherit the
     * same file creation mask monit was started with
     */
    umask(Run.umask);

    /*
     * Switch uid/gid if requested
     */
    if(C->has_gid) {
        if(0 != setgid(C->gid)) {
          stat_loc |= setgid_ERROR;
      }
    }
    if(C->has_uid) {
      if(0 != setuid(C->uid)) {
         stat_loc |= setuid_ERROR;
      }
    }

    put_monit_environment(environment);

    if(! Run.isdaemon) {
      int i;
      for(i= 0; i < 3; i++)
        if(close(i) == -1 || open("/dev/null", O_RDWR) != i)
          stat_loc |= redirect_ERROR;
    }

    Util_closeFds();

    setsid();

    pid = fork();
    if(pid < 0) {
      stat_loc |= fork_ERROR;
      _exit(stat_loc);
    }

    if(pid == 0) {
        /*
         * Reset all signals, so the spawned process is *not* created
         * with any inherited SIG_BLOCKs
         */
      sigemptyset(&mask);
      pthread_sigmask(SIG_SETMASK, &mask, NULL);
      signal(SIGINT, SIG_DFL);
      signal(SIGHUP, SIG_DFL);
      signal(SIGTERM, SIG_DFL);
      signal(SIGUSR1, SIG_DFL);
      signal(SIGPIPE, SIG_DFL);
      
      (void) execv(C->arg[0], C->arg);
      _exit(1);
    }

    /* Exit first child and return errors to parent */
    _exit(stat_loc);
  }

  /* Wait for first child - aka second parent, to exit */
  if(waitpid(pid, &stat_loc, 0) != pid) {
      LogError("Waitpid error\n");
  }

  exit_status= WEXITSTATUS(stat_loc);
  if (exit_status & setgid_ERROR)
    LogError("Failed to change gid to '%d' for '%s'\n", C->gid, C->arg[0]);
  if (exit_status & setuid_ERROR)
    LogError("Failed to change uid to '%d' for '%s'\n", C->uid, C->arg[0]);
  if (exit_status & fork_ERROR)
    LogError("Cannot fork a new process for '%s'\n", C->arg[0]);
  if (exit_status & redirect_ERROR)
    LogError("Cannot redirect IO to /dev/null for '%s'\n", C->arg[0]);

  free_monit_environment(&environment);
  ASSERT(environment == NULL);

  /*
   * Restore the signal mask
   */
  pthread_sigmask(SIG_SETMASK, &save, NULL);

  /*
   * We do not need to wait for the second child since we forked twice,
   * the init system-process will wait for it. So we just return
   */

} 


/* ----------------------------------------------------------------- Private */


/*
 * Setup the environment with special MONIT_xxx variables. The program
 * executed may use such variable for various purposes.
 */
static void set_monit_environment(Service_T s, Command_T C, Event_T event, Environment_T *e) {
  char buf[STRLEN];
  char date[STRLEN];
  
  Util_getRFC822Date(NULL, date, STRLEN);
  
  snprintf(buf, STRLEN, "MONIT_DATE=%s", date);
  push_monit_environment(buf, e);

  snprintf(buf, STRLEN, "MONIT_SERVICE=%s", s->name);
  push_monit_environment(buf, e);

  snprintf(buf, STRLEN, "MONIT_HOST=%s", Run.localhostname);
  push_monit_environment(buf, e);

  snprintf(buf, STRLEN, "MONIT_EVENT=%s", event ? Event_get_description(event) : C == s->start ? "Started" : C == s->stop ? "Stopped" : "No Event");
  push_monit_environment(buf, e);
  
  snprintf(buf, STRLEN, "MONIT_DESCRIPTION=%s", event ? Event_get_message(event) : C == s->start ? "Started" : C == s->stop ? "Stopped" : "No Event");
  push_monit_environment(buf, e);

  if (s->type == TYPE_PROCESS) {
    snprintf(buf, STRLEN, "MONIT_PROCESS_PID=%d", Util_isProcessRunning(s, FALSE));
    push_monit_environment(buf, e);

    snprintf(buf, STRLEN, "MONIT_PROCESS_MEMORY=%ld", s->inf->priv.process.mem_kbyte);
    push_monit_environment(buf, e);

    snprintf(buf, STRLEN, "MONIT_PROCESS_CHILDREN=%d", s->inf->priv.process.children);
    push_monit_environment(buf, e);

    snprintf(buf, STRLEN, "MONIT_PROCESS_CPU_PERCENT=%d", s->inf->priv.process.cpu_percent);
    push_monit_environment(buf, e);
  }

}


static void push_monit_environment(char const *env, Environment_T *list) {
  Environment_T e= NULL;
  NEW(e);
  strncpy(e->env, env, sizeof(e->env) - 1);
  e->env[sizeof(e->env) - 1] = 0;
  e->next= *list;
  *list= e;
}


static void put_monit_environment(Environment_T e) {
  while(e != NULL) {
    putenv(e->env);
    e= e->next;
  }
}


static void free_monit_environment(Environment_T *e) {
  if(e&&*e) {
    free_monit_environment(&(*e)->next);
    FREE((*e));
  }
}

