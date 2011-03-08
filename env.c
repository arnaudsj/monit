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

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_CRT_EXTERNS_H
#include <crt_externs.h>
#endif

#include "monitor.h"

#ifndef MAXPATHLEN
#define MAXPATHLEN STRLEN
#endif

#ifdef DARWIN
#define environ (*_NSGetEnviron())
#endif

/* Private prototypes */
static void set_sandbox(void);
static void set_environment(void);

/**
 *  Setup this program for safer exec, and set required runtime
 *  "environment" variables.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *
 *  @file
 */


/* ------------------------------------------------------------------ Public */


/**
 * Initialize the program environment
 */
void init_env() {
  
  /* Setup for safe(r) exec */
  set_sandbox();

  /* Setup program environment */
  set_environment();

}


/* ----------------------------------------------------------------- Private */


/**
 *  DESCRIPTION
 *    This code was originally posted by Wietse Venema, years ago, in
 *    a discussion on news on how to create safe suid wrappers. For
 *    those interested in NNTP archeology, here's the post:
 *    
 *  Article 5648 of comp.security.unix:
 *  From: wietse@wzv.win.tue.nl (Wietse Venema)
 *  Newsgroups: comp.security.unix
 *  Subject: Re: [8lgm]-Advisory-7.UNIX.passwd.11-May-1994
 *  Date: 18 May 1994 07:52:05 +0200
 *  Organization: Eindhoven University of Technology, The Netherlands
 *  Lines: 68
 *  
 *  milton@picard.med.miami.edu (H. Milton Johnson) writes:
 *  >OK, I admit it, I'm a totally incompetent sysadmin because I am not
 *  >sure I could write a bullet-proof setuid wrapper.  However, if one of
 *  >the competent sysadmins subscribing to this group could post or point
 *  >the way to an example of a bullet- proof setuid wrapper, I'm sure that
 *  >I could use it as a template to address this/future/other problems.
 *  
 *  Ok, here is a first stab. Perhaps we can make this into a combined
 *  effort and get rid of the problem once and for all.
 *  
 *           Wietse
 *
 *  [code - see the function below, only marginally changed to suit monit]    
 *
 *  @author Wietse Venema <wietse@wzv.win.tue.nl>
 *
 */
static void set_sandbox(void) {

  int    i = 0;
  struct stat st;
  extern char **environ;
  char   *path = "PATH=/bin:/usr/bin:/sbin:/usr/sbin";
  char   *tz;

  /*
   * Purge the environment, but keep the TZ variable as the time.h family depends on it at least on AIX
   */
  for (tz = environ[0]; tz; tz = environ[++i]) {
    if (! strncasecmp(tz, "TZ=", 3)) {
      environ[0] = tz;
      environ[1] = 0;
      break;
    }
  }
  if (! tz)
    environ[0] = 0;
  
  if (putenv(path)) {
    LogError("%s: cannot set the PATH variable -- %s\n", prog, STRERROR);
    exit(1);
  }

  /*
   * Require that file descriptors 0,1,2 are open. Mysterious things
   * can happen if that is not the case.
   */
  for(i= 0; i < 3; i++) {
    
    if(fstat(i, &st) == -1 && open("/dev/null", O_RDWR) != i) {
      
      LogError("Cannot open /dev/null -- %s\n", STRERROR);
      exit(1);
      
    }
    
  }

  Util_closeFds();

}


/**
 * Get and set required runtime "environment" variables.
 */
static void set_environment(void) {

  struct passwd *pw;
  
  /* Get password struct */
  if ( ! (pw= getpwuid(geteuid())) ) {
    LogError("%s: You don't exist. Go away.\n", prog);
    exit(1);
  }
  Run.Env.home= xstrdup(pw->pw_dir);
  Run.Env.user= xstrdup(pw->pw_name);
  
  /* Get CWD */
  Run.Env.cwd= xcalloc(sizeof(char), MAXPATHLEN+1);
  if ( ! (getcwd(Run.Env.cwd, MAXPATHLEN)) ) {
    LogError("%s: Cannot read current directory -- %s\n", prog, STRERROR);
    exit(1);
  }
  
  /*
   * Save and clear the file creation mask
   */
  Run.umask= umask(0);

}

