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

#ifdef HAVE_STDARG_H
#include <stdarg.h>
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

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
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

#ifdef HAVE_EXECINFO_H
#include <execinfo.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include "monitor.h"


/**
  *  Implementation of a logger that appends log messages to a file
  *  with a preceding timestamp. Methods support both syslog or own
  *  logfile.
  *
  *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
  *  @author Martin Pala, <martinp@tildeslash.com>
  *
  *  @file
 */


/* ------------------------------------------------------------- Definitions */


static FILE *LOG= NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;


static struct mylogpriority {
  int  priority;
  char *description;
} logPriority[]= {
  {LOG_EMERG,   "emergency"},
    {LOG_ALERT,   "alert"},
    {LOG_CRIT,    "critical"},
    {LOG_ERR,     "error"},
    {LOG_WARNING, "warning"},
    {LOG_NOTICE,  "notice"},
    {LOG_INFO,    "info"},
    {LOG_DEBUG,   "debug"},
    {-1,          NULL}
};


/* -------------------------------------------------------------- Prototypes */


static int  open_log();
static char *timefmt(char *t, int size);
static const char *logPriorityDescription(int p);
static void log_log(int priority, const char *s, va_list ap);
static void log_backtrace();


/* ------------------------------------------------------------------ Public */


/**
 * Initialize the log system and 'log' function
 * @return TRUE if the log system was successfully initialized
 */
int log_init() {

  if (!Run.dolog) {
    return TRUE;
  }

  if (!open_log()) {
    return FALSE;
  }

  /* Register log_close to be
  called at program termination */
    atexit(log_close);

  return TRUE;

}


/**
 * Logging interface with priority support
 * @param s A formated (printf-style) string to log
 */
void LogEmergency(const char *s, ...) {
  va_list ap;

  ASSERT(s);

  va_start(ap, s);
  log_log(LOG_EMERG, s, ap);
  va_end(ap);
  log_backtrace();
}


/**
 * Logging interface with priority support
 * @param s A formated (printf-style) string to log
 */
void LogAlert(const char *s, ...) {
  va_list ap;

  ASSERT(s);

  va_start(ap, s);
  log_log(LOG_ALERT, s, ap);
  va_end(ap);
  log_backtrace();
}


/**
 * Logging interface with priority support
 * @param s A formated (printf-style) string to log
 */
void LogCritical(const char *s, ...) {
  va_list ap;

  ASSERT(s);

  va_start(ap, s);
  log_log(LOG_CRIT, s, ap);
  va_end(ap);
  log_backtrace();
}


/**
 * Logging interface with priority support
 * @param s A formated (printf-style) string to log
 */
void LogError(const char *s, ...) {
  va_list ap;

  ASSERT(s);

  va_start(ap, s);
  log_log(LOG_ERR, s, ap);
  va_end(ap);
  log_backtrace();
}


/**
 * Logging interface with priority support
 * @param s A formated (printf-style) string to log
 */
void LogWarning(const char *s, ...) {
  va_list ap;

  ASSERT(s);

  va_start(ap, s);
  log_log(LOG_WARNING, s, ap);
  va_end(ap);
}


/**
 * Logging interface with priority support
 * @param s A formated (printf-style) string to log
 */
void LogNotice(const char *s, ...) {
  va_list ap;

  ASSERT(s);

  va_start(ap, s);
  log_log(LOG_NOTICE, s, ap);
  va_end(ap);
}


/**
 * Logging interface with priority support
 * @param s A formated (printf-style) string to log
 */
void LogInfo(const char *s, ...) {
  va_list ap;

  ASSERT(s);

  va_start(ap, s);
  log_log(LOG_INFO, s, ap);
  va_end(ap);
}


/**
 * Logging interface with priority support
 * @param s A formated (printf-style) string to log
 */
void LogDebug(const char *s, ...) {
  va_list ap;

  ASSERT(s);

  va_start(ap, s);
  log_log(LOG_DEBUG, s, ap);
  va_end(ap);
}


/**
 * Close the log file or syslog
 */
void log_close() {

  if (Run.use_syslog) {
    closelog(); 
  }

  if (LOG  && (0 != fclose(LOG))) {
    LogError("%s: Error closing the log file -- %s\n",	prog, STRERROR);
  }

  LOG= NULL;

}


#ifndef HAVE_VSYSLOG
#ifdef HAVE_SYSLOG
void vsyslog (int facility_priority, const char *format, va_list arglist) {
  char msg[STRLEN+1];

  vsnprintf(msg, STRLEN, format, arglist);
  syslog(facility_priority, "%s", msg);
}
#endif /* HAVE_SYSLOG */
#endif /* HAVE_VSYSLOG */


/* ----------------------------------------------------------------- Private */


/**
 * Open a log file or syslog
 */
static int open_log() {

  if (Run.use_syslog) {
    openlog(prog, LOG_PID, Run.facility); 
  } else {
    umask(LOGMASK);
    if ((LOG= fopen(Run.logfile,"a+")) == (FILE *)NULL) {
      LogError("%s: Error opening the log file '%s' for writing -- %s\n", prog, Run.logfile, STRERROR);
      return(FALSE);
    }
    /* Set logger in unbuffered mode */
    setvbuf(LOG, NULL, _IONBF, 0);
  }

  return TRUE;

}


/**
 * Returns the current time as a formated string, see the TIMEFORMAT
 * macro in monitor.h
 */
static char *timefmt(char *t, int size) {
  time_t now;
  struct tm tm;

  time(&now);
  localtime_r(&now, &tm);
  if ( !strftime(t, size, TIMEFORMAT, &tm))
    *t = 0;
  return t;
}


/**
 * Get a textual description of the actual log priority.
 * @param p The log priority
 * @return A string describing the log priority in clear text. If the
 * priority is not found NULL is returned.
 */
static const char *logPriorityDescription(int p) {

  struct mylogpriority *lp= logPriority;

  while ((*lp).description)
  {
    if (p == (*lp).priority)
    {
      return (*lp).description;
    }
    lp++;
  }

  return "unknown";

}


/**
 * Log a message to monits logfile or syslog. 
 * @param priority A message priority
 * @param s A formated (printf-style) string to log
 */
static void log_log(int priority, const char *s, va_list ap) {

#ifdef HAVE_VA_COPY
  va_list ap_copy;
#endif

  ASSERT(s);

  LOCK(log_mutex)

#ifdef HAVE_VA_COPY
    va_copy(ap_copy, ap);
  vfprintf(stderr, s, ap_copy);
  va_end(ap_copy);
#else
  vfprintf(stderr, s, ap);
#endif
  fflush(stderr);

  if (Run.dolog) {
    if (Run.use_syslog) {
#ifdef HAVE_VA_COPY
      va_copy(ap_copy, ap);
      vsyslog(priority, s, ap_copy);
      va_end(ap_copy);
#else
      vsyslog(priority, s, ap);
#endif
    } else if (LOG) {
      char datetime[STRLEN];
      fprintf(LOG, "[%s] %-8s : ", timefmt(datetime, STRLEN), logPriorityDescription(priority));
#ifdef HAVE_VA_COPY
      va_copy(ap_copy, ap);
      vfprintf(LOG, s, ap_copy);
      va_end(ap_copy);
#else
      vfprintf(LOG, s, ap);
#endif

    }
  }
  END_LOCK;
}


static void log_backtrace() {
#ifdef HAVE_BACKTRACE
  int i, frames;
  void *callstack[128];
  char **strs;

  if (Run.debug) {
    frames = backtrace(callstack, 128);
    strs = backtrace_symbols(callstack, frames);
    LogDebug("-------------------------------------------------------------------------------\n");
    for (i = 0; i < frames; ++i)
      LogDebug("    %s\n", strs[i]);
    LogDebug("-------------------------------------------------------------------------------\n");
    FREE(strs);
  }
#endif
}

