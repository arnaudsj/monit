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

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#include "monitor.h"

/**
 *  Signal handeling routines.
 *
 *  @author W. Richard Stevens
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *     
 *  @file
 */


/* ------------------------------------------------------------------ Public */


/**
 * Replace the standard signal() function, with a more reliable
 * using sigaction. From W. Richard Stevens' "Advanced Programming
 * in the UNIX Environment"
 */
Sigfunc *signal(int signo, Sigfunc *func) {
  
  struct sigaction act, oact;

  act.sa_handler = func;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;
  if (signo == SIGALRM) {
#ifdef  SA_INTERRUPT
    act.sa_flags |= SA_INTERRUPT;   /* SunOS */
#endif
  } else {
#ifdef  SA_RESTART
    act.sa_flags |= SA_RESTART;             /* SVR4, 44BSD */
#endif
  }
  if (sigaction(signo, &act, &oact) < 0)
      return(SIG_ERR);
  
  return(oact.sa_handler);
  
}


/**
 * Set a collective thread signal block for signals honored by monit
 * @param new The signal mask to use for the block
 * @param old The signal mask used to save the previous mask
 */
void set_signal_block(sigset_t *new, sigset_t *old) {

  sigemptyset(new);
  sigaddset(new, SIGHUP);
  sigaddset(new, SIGINT);
  sigaddset(new, SIGUSR1);
  sigaddset(new, SIGTERM);
  pthread_sigmask(SIG_BLOCK, new, old);

}


/**
 * Set the thread signal mask back to the old mask
 * @param old The signal mask to restore
 */
void unset_signal_block(sigset_t *old) {

  pthread_sigmask(SIG_SETMASK, old, NULL);
  
}
