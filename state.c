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
#include "state.h"


/**
 *  Manage service information persistently. Service data is saved to
 *  a state file when monit runs in daemon mode for each poll
 *  cycle. Monit use this file to maintain service data persistently
 *  during reload or restart. The location of the state file may be
 * set from the command line or set in the monitrc file, if not set,
 * the default is ~/.monit.state.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @file
 */


/* ------------------------------------------------------------- Definitions */


/**
 * Fields from the Service_T object type, which we are interested in
 * when handling the state.
 */
typedef struct mystate {
  char               name[STRLEN];
  int                mode;
  int                nstart;
  int                ncycle;
  int                monitor;
  unsigned long long error;
} State_T;


/* -------------------------------------------------------------- Prototypes */


static void close_state(FILE *);
static FILE *open_state(const char *mode);
static void clone_state(Service_T, State_T *);
static void update_service_state(Service_T, State_T *);


/* ------------------------------------------------------------------ Public */


/**
 * Save service state information to the state file
 */
void State_save() {

  int l= 0;
  Service_T s;
  State_T state;
  FILE *S= NULL;
  
  if(! (S= open_state("w")))
      return;

  l= Util_getNumberOfServices();
  
  if(fwrite(&l, 1, sizeof (int), S) != sizeof(int)) {
    LogError("%s: Unable to save monit state information to '%s'\n",
	prog, Run.statefile);
    goto error;
  }
  
  for(s= servicelist; s; s= s->next) {
    clone_state(s, &state);
    if(fwrite(&state, 1, sizeof(State_T), S) != sizeof(State_T)) {
      LogError("%s: An error occured when saving monit state information "
	  "for the service %s\n", prog, s->name);
      goto error;
    }
  }
  
  error:
  close_state(S);
}


/**
 * Check if we should update current services with persistent state
 * information. The logic is as follows: Iff a state file is present
 * *and* older than the running monit daemon's lock file we have had a
 * crash and should update data from the state file.
 * @return TRUE if the state should be updated otherwise FALSE
 */
int State_shouldUpdate() {
  
  if(File_exist(Run.statefile) && File_exist(Run.pidfile)) {
    return (File_getTimestamp(Run.pidfile, S_IFREG) >
	    File_getTimestamp(Run.statefile, S_IFREG));
  }
  
  return FALSE;
  
}


/**
 * Update the current service list with data from the state file. We
 * do *only* change services found in *both* the monitrc file and in
 * the state file. The algorithm:
 *
 * Assume the control file was changed and a new service (B) was added
 * so the monitrc file now contains the services: A B and C. The
 * running monit daemon only knows the services A and C. Upon restart
 * after a crash the monit daemon first read the monitrc file and
 * creates the service list structure with A B and C. We then read the
 * state file and update the service A and C since they are found in
 * the state file, B is not found in this file and therefore not
 * changed.
 *
 * The same strategy is used if a service was removed, e.g. if the
 * service A was removed from monitrc; when reading the state file,
 * service A is not found in the current service list (the list is
 * always generated from monitrc) and therefore A is simply discarded.
 *
 * Finally, after the monit service state is updated this function
 * writes the new state file.
 */
void State_update() {

  int i;
  int l= 0;
  State_T s;
  FILE *S= NULL;
  Service_T service;
  int has_error= FALSE;
  
  if(! (S= open_state("r")))
      return;
  
  errno= 0;
  if(fread(&l, 1, sizeof (int), S) != sizeof(int)) {
    LogError("%s: Unable to read monit state information from '%s'\n",
	prog, Run.statefile);
    has_error= TRUE;
    goto error;
  }

  if(l > 0) {
    for(i=0; i<l; i++) {
      if(fread(&s, 1, sizeof(State_T), S) != sizeof(State_T)) {
	LogError("%s: An error occured when updating monit state information\n",
	    prog);
	has_error= TRUE;
	goto error;
      }
      if((service= Util_getService(s.name))) {
	update_service_state(service, &s);
      }
    }
  }

  error:
  close_state(S);

  if(!has_error)
      State_save();

}


/* ----------------------------------------------------------------- Private */


static FILE *open_state(const char *mode) {

  FILE *S= NULL;
  
  ASSERT(Run.statefile);

  umask(MYPIDMASK);
  
  if((S= fopen(Run.statefile, mode)) == NULL) {
    LogError("%s: Cannot open the monit state file '%s' -- %s\n",
	prog, Run.statefile, STRERROR);
    
    return NULL;
    
  }

  return S;
  
}


static void close_state(FILE *S) {
  if(fclose(S) != 0)
    LogCritical("%s: Cannot close the monit state file '%s' -- %s\n", prog, Run.statefile, STRERROR);
}


static void clone_state(Service_T service, State_T *state) {
  memset(state, 0, sizeof(State_T));
  
  strncpy(state->name, service->name, sizeof(state->name) - 1);
  state->name[sizeof(state->name) - 1] = 0;
  state->nstart= service->nstart;
  state->ncycle= service->ncycle;
  state->monitor= service->monitor;
}


static void update_service_state(Service_T service, State_T *state) {
  service->nstart= state->nstart;
  service->ncycle= state->ncycle;
  /* Keep services in initializing state unless the monitoring should be disabled */
  if (state->monitor == MONITOR_NOT)
        service->monitor= state->monitor;
}
