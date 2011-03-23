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

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif


#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#include "monitor.h"
#include "alert.h"
#include "event.h"
#include "process.h"


/**
 * Implementation of the event interface.
 *
 * @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 * @author Martin Pala <martinp@tildeslash.com>
 * @file
 */


/* ------------------------------------------------------------- Definitions */

EventTable_T Event_Table[]= {
  {Event_Action,     "Action done",             "Action done",                "Action done",              "Action done"},
  {Event_Checksum,   "Checksum failed",         "Checksum succeeded",         "Checksum changed",         "Checksum not changed"},
  {Event_Connection, "Connection failed",       "Connection succeeded",       "Connection changed",       "Connection not changed"},
  {Event_Content,    "Content failed",          "Content succeeded",          "Content match",            "Content doesn't match"},
  {Event_Data,       "Data access error",       "Data access succeeded",      "Data access changed",      "Data access not changed"},
  {Event_Exec,       "Execution failed",        "Execution succeeded",        "Execution changed",        "Execution not changed"},
  {Event_Fsflag,     "Filesystem flags failed", "Filesystem flags succeeded", "Filesystem flags changed", "Filesystem flags not changed"},
  {Event_Gid,        "GID failed",              "GID succeeded",              "GID changed",              "GID not changed"},
  {Event_Heartbeat,  "Heartbeat failed",        "Heartbeat succeeded",        "Heartbeat changed",        "Heartbeat not changed"},
  {Event_Icmp,       "ICMP failed",             "ICMP succeeded",             "ICMP changed",             "ICMP not changed"},
  {Event_Instance,   "Monit instance failed",   "Monit instance succeeded",   "Monit instance changed",   "Monit instance not changed"},
  {Event_Invalid,    "Invalid type",            "Type succeeded",             "Type changed",             "Type not changed"},
  {Event_Nonexist,   "Does not exist",          "Exists",                     "Existence changed",        "Existence not changed"},
  {Event_Permission, "Permission failed",       "Permission succeeded",       "Permission changed",       "Permission not changed"},
  {Event_Pid,        "PID failed",              "PID succeeded",              "PID changed",              "PID not changed"},
  {Event_PPid,       "PPID failed",             "PPID succeeded",             "PPID changed",             "PPID not changed"},
  {Event_Resource,   "Resource limit matched",  "Resource limit succeeded",   "Resource limit changed",   "Resource limit not changed"},
  {Event_Size,       "Size failed",             "Size succeeded",             "Size changed",             "Size not changed"},
  {Event_Timeout,    "Timeout",                 "Timeout recovery",           "Timeout changed",          "Timeout not changed"},
  {Event_Timestamp,  "Timestamp failed",        "Timestamp succeeded",        "Timestamp changed",        "Timestamp not changed"},
  {Event_Uid,        "UID failed",              "UID succeeded",              "UID changed",              "UID not changed"},
  /* Virtual events */
  {Event_Null,       "No Event",                "No Event",                   "No Event",                 "No Event"}
};


/* -------------------------------------------------------------- Prototypes */


static void handle_event(Event_T);
static void handle_action(Event_T, Action_T);
static void Event_queue_add(Event_T);
static void Event_queue_update(Event_T, const char *);


/* ------------------------------------------------------------------ Public */


/**
 * Post a new Event
 * @param service The Service the event belongs to
 * @param id The event identification
 * @param state The event state
 * @param action Description of the event action
 * @param s Optional message describing the event
 */
void Event_post(Service_T service, long id, short state, EventAction_T action, char *s, ...) {
  Event_T e;

  ASSERT(service);
  ASSERT(action);
  ASSERT(state == STATE_FAILED || state == STATE_SUCCEEDED || state == STATE_CHANGED || state == STATE_CHANGEDNOT);

  if ((e = service->eventlist) == NULL) {
    /* Only first failed/changed event can initialize the queue for given event type,
     * thus succeeded events are ignored until first error. */
    if (state == STATE_SUCCEEDED || state == STATE_CHANGEDNOT)
      return;

    /* Initialize event list and add first event. The manadatory informations
     * are cloned so the event is as standalone as possible and may be saved
     * to the queue without the dependency on the original service, thus
     * persistent and managable across monit restarts */
    NEW(e);
    e->id = id;
    gettimeofday(&e->collected, NULL);
    e->source = xstrdup(service->name);
    e->mode = service->mode;
    e->type = service->type;
    e->state = STATE_INIT;
    e->state_map = 1;
    e->action = action;
    if (s) {
      long l;
      va_list ap;

      va_start(ap, s);
      e->message = Util_formatString(s, ap, &l);
      va_end(ap);
    }
    service->eventlist = e;
  } else {
    /* Try to find the event with the same origin and type identification.
     * Each service and each test have its own custom actions object, so
     * we share actions object address to identify event source. */
    do {
      if (e->action == action && e->id == id) {
        gettimeofday(&e->collected, NULL);

        /* Shift the existing event flags to the left
         * and set the first bit based on actual state */
        e->state_map <<= 1;
        e->state_map |= ((state == STATE_SUCCEEDED || state == STATE_CHANGEDNOT) ? 0 : 1);

        /* Update the message */
        if (s) {
          long l;
          va_list ap;

          FREE(e->message);
          va_start(ap, s);
          e->message = Util_formatString(s, ap, &l);
          va_end(ap);
        }
	break;
      }
      e = e->next;
    } while (e);

    if (!e) {
      /* Only first failed/changed event can initialize the queue for given event type,
       * thus succeeded events are ignored until first error. */
      if (state == STATE_SUCCEEDED || state == STATE_CHANGEDNOT)
        return;

      /* Event was not found in the pending events list, we will add it.
       * The manadatory informations are cloned so the event is as standalone
       * as possible and may be saved to the queue without the dependency on
       * the original service, thus persistent and managable across monit
       * restarts */
      NEW(e);
      e->id = id;
      gettimeofday(&e->collected, NULL);
      e->source = xstrdup(service->name);
      e->mode = service->mode;
      e->type = service->type;
      e->state = STATE_INIT;
      e->state_map = 1;
      e->action = action;
      if (s) {
        long l;
        va_list ap;

        va_start(ap, s);
        e->message = Util_formatString(s, ap, &l);
        va_end(ap);
      }
      e->next = service->eventlist;
      service->eventlist = e;
    }
  }

  e->state_changed = Event_check_state(e, state);

  /* In the case that the state changed, update it and reset the counter */
  if (e->state_changed) {
    e->state = state;
    e->count = 1;
  } else
    e->count++;

  handle_event(e);
}


/* -------------------------------------------------------------- Properties */


/**
 * Get the Service where the event orginated
 * @param E An event object
 * @return The Service where the event orginated
 */
Service_T Event_get_source(Event_T E) {
  Service_T s = NULL;

  ASSERT(E);

  if (!(s = Util_getService(E->source)))
    LogError("Service %s not found in monit configuration\n", E->source);

  return s;
}


/**
 * Get the Service name where the event orginated
 * @param E An event object
 * @return The Service name where the event orginated
 */
char *Event_get_source_name(Event_T E) {
  ASSERT(E);
  return (E->source);
}


/**
 * Get the service type of the service where the event orginated
 * @param E An event object
 * @return The service type of the service where the event orginated
 */
int Event_get_source_type(Event_T E) {
  ASSERT(E);
  return (E->type);
}


/**
 * Get the Event timestamp
 * @param E An event object
 * @return The Event timestamp
 */
struct timeval *Event_get_collected(Event_T E) {
  ASSERT(E);
  return &E->collected;
}


/**
 * Get the Event raw state
 * @param E An event object
 * @return The Event raw state
 */
short Event_get_state(Event_T E) {
  ASSERT(E);
  return E->state;
}


/**
 * Return the actual event state based on event state bitmap
 * and event ratio needed to trigger the state change
 * @param E An event object
 * @param S Actual posted state
 * @return The Event raw state
 */
short Event_check_state(Event_T E, short S) {
  int       i;
  int       count = 0;
  short     state = (S == STATE_SUCCEEDED || S == STATE_CHANGEDNOT) ? 0 : 1; /* translate to 0/1 class */
  Action_T  action;
  Service_T service;
  long long flag;

  ASSERT(E);

  if (!(service = Event_get_source(E)))
    return TRUE;

  /* Only true failed/changed state condition can change the initial state */
  if (!state && E->state == STATE_INIT && !(service->error & E->id))
    return FALSE;

  action = !state ? E->action->succeeded : E->action->failed;

  /* Compare as many bits as cycles able to trigger the action */
  for (i = 0; i < action->cycles; i++) {
    /* Check the state of the particular cycle given by the bit position */
    flag = (E->state_map >> i) & 0x1;

    /* Count occurences of the posted state */
    if (flag == state)
      count++;
  }

  /* the internal instance and action events are handled as changed any time since we need to deliver alert whenever it occurs */
  if (E->id == Event_Instance || E->id == Event_Action || (count >= action->count && (S != E->state || S == STATE_CHANGED)))
    return TRUE;
  
  return FALSE;
}


/**
 * Get the Event type
 * @param E An event object
 * @return The Event type
 */
int Event_get_id(Event_T E) {
  ASSERT(E);
  return E->id;
}


/**
 * Get the optionally Event message describing why the event was
 * fired.
 * @param E An event object
 * @return The Event message. May be NULL
 */
const char *Event_get_message(Event_T E) {
  ASSERT(E);
  return E->message;
}


/**
 * Get a textual description of actual event type.
 * @param E An event object
 * @return A string describing the event type in clear text. If the
 * event type is not found NULL is returned.
 */
const char *Event_get_description(Event_T E) {
  EventTable_T *et= Event_Table;

  ASSERT(E);

  while ((*et).id) {
    if (E->id == (*et).id) {
      switch (E->state) {
        case STATE_SUCCEEDED:
          return (*et).description_succeeded;
        case STATE_FAILED:
          return (*et).description_failed;
        case STATE_INIT:
          return (*et).description_failed;
        case STATE_CHANGED:
          return (*et).description_changed;
        case STATE_CHANGEDNOT:
          return (*et).description_changednot;
        default:
          break;
      }
    }
    et++;
  }
  
  return NULL;
}


/**
 * Get an event action id.
 * @param E An event object
 * @return An action id
 */
short Event_get_action(Event_T E) {
  Action_T A = NULL;

  ASSERT(E);

  switch (E->state) {
    case STATE_SUCCEEDED:
    case STATE_CHANGEDNOT:
      A = E->action->succeeded;
      break;
    case STATE_FAILED:
    case STATE_CHANGED:
    case STATE_INIT:
      A = E->action->failed;
      break;
    default:
      break;
  }

  if (! A)
    return ACTION_IGNORE;

  /* In the case of passive mode we replace the description of start, stop
   * or restart action for alert action, because these actions are passive in
   * this mode */
  return (E->mode == MODE_PASSIVE && ((A->id == ACTION_START) || (A->id == ACTION_STOP) || (A->id == ACTION_RESTART))) ? ACTION_ALERT : A->id;
}


/**
 * Get a textual description of actual event action. For instance if the
 * event type is possitive Event_Nonexist, the textual description of
 * failed state related action is "restart". Likewise if the event type is
 * negative Event_Checksumthe textual description of recovery related action
 * is "alert" and so on.
 * @param E An event object
 * @return A string describing the event type in clear text. If the
 * event type is not found NULL is returned.
 */
const char *Event_get_action_description(Event_T E) {
  ASSERT(E);
  return actionnames[Event_get_action(E)];
}


/**
 * Reprocess the partially handled event queue
 */
void Event_queue_process() {
  DIR           *dir = NULL;
  FILE          *file = NULL;
  struct dirent *de = NULL;
  EventAction_T  ea = NULL;
  Action_T       a = NULL;

  /* return in the case that the eventqueue is not enabled or empty */
  if (! Run.eventlist_dir || (! Run.handler_init && ! Run.handler_queue[HANDLER_ALERT] && ! Run.handler_queue[HANDLER_MMONIT]))
    return;

  if (! (dir = opendir(Run.eventlist_dir)) ) {
    if (errno != ENOENT)
      LogError("%s: cannot open the directory %s -- %s\n", prog, Run.eventlist_dir, STRERROR);
    return;
  }

  if ((de = readdir(dir)))
    DEBUG("Processing postponed events queue\n");

  NEW(ea);
  NEW(a);

  while (de) {
    int            size;
    int            handlers_passed = 0;
    int           *version = NULL;
    short         *action = NULL;
    Event_T        e = NULL;
    struct stat    st;
    char           file_name[STRLEN];

    /* In the case that all handlers failed, skip the further processing in
     * this cycle. Alert handler is currently defined anytime (either
     * explicitly or localhost by default) */
    if ( (Run.mmonits && FLAG(Run.handler_flag, HANDLER_MMONIT) && FLAG(Run.handler_flag, HANDLER_ALERT)) || FLAG(Run.handler_flag, HANDLER_ALERT))
      break;

    snprintf(file_name, STRLEN, "%s/%s", Run.eventlist_dir, de->d_name);

    if (!stat(file_name, &st) && S_ISREG(st.st_mode)) {
      DEBUG("%s: processing queued event %s\n", prog, file_name);

      if (! (file = fopen(file_name, "r")) ) {
        LogError("%s: queued event processing failed - cannot open the file %s -- %s\n", prog, file_name, STRERROR);
        goto error1;
      }

      /* read event structure version */
      if (!(version = File_readQueue(file, &size))) {
        LogError("skipping queued event %s - unknown data format\n", file_name);
        goto error2;
      }
      if (size != sizeof(int)) {
        LogError("Aborting queued event %s - invalid size %d\n", file_name, size);
        goto error3;
      }
      if (*version != EVENT_VERSION) {
        LogError("Aborting queued event %s - incompatible data format version %d\n", file_name, *version);
        goto error3;
      }

      /* read event structure */
      if (!(e = File_readQueue(file, &size)))
        goto error3;
      if (size != sizeof(*e))
        goto error4;

      /* read source */
      if (!(e->source = File_readQueue(file, &size)))
        goto error4;

      /* read message */
      if (!(e->message = File_readQueue(file, &size)))
        goto error5;

      /* read event action */
      if (!(action = File_readQueue(file, &size)))
        goto error6;
      if (size != sizeof(short))
        goto error7;
      a->id = *action;
      if (e->state == STATE_FAILED)
        ea->failed = a;
      else
        ea->succeeded = a;
      e->action = ea;

      /* Retry all remaining handlers */

      /* alert */
      if (e->flag & HANDLER_ALERT) {
        if (Run.handler_init)
          Run.handler_queue[HANDLER_ALERT]++;
        if ((Run.handler_flag & HANDLER_ALERT) != HANDLER_ALERT) {
          if ( handle_alert(e) != HANDLER_ALERT ) {
            e->flag &= ~HANDLER_ALERT;
            Run.handler_queue[HANDLER_ALERT]--;
            handlers_passed++;
          } else {
            LogError("Alert handler failed, retry scheduled for next cycle\n");
            Run.handler_flag |= HANDLER_ALERT;
          }
        }
      }

      /* mmonit */
      if (e->flag & HANDLER_MMONIT) {
        if (Run.handler_init)
          Run.handler_queue[HANDLER_MMONIT]++;
        if ((Run.handler_flag & HANDLER_MMONIT) != HANDLER_MMONIT) {
          if ( handle_mmonit(e) != HANDLER_MMONIT ) {
            e->flag &= ~HANDLER_MMONIT;
            Run.handler_queue[HANDLER_MMONIT]--;
            handlers_passed++;
          } else {
            LogError("M/Monit handler failed, retry scheduled for next cycle\n");
            Run.handler_flag |= HANDLER_MMONIT;
          }
        }
      }

      /* If no error persists, remove it from the queue */
      if (e->flag == HANDLER_SUCCEEDED) {
        DEBUG("Removing queued event %s\n", file_name);
        if (unlink(file_name) < 0)
          LogError("Failed to remove queued event file '%s' -- %s\n", file_name, STRERROR);
      } else if (handlers_passed > 0) {
        DEBUG("Updating queued event %s (some handlers passed)\n", file_name);
        Event_queue_update(e, file_name);
      }

error7:
      FREE(action);
error6:
      FREE(e->message);
error5:
      FREE(e->source);
error4:
      FREE(e);
error3:
      FREE(version);
error2:
      fclose(file);
    }
error1:
    de = readdir(dir);
  }
  Run.handler_init = FALSE;
  closedir(dir);
  FREE(a);
  FREE(ea);
  return;
}


/* ----------------------------------------------------------------- Private */


/*
 * Handle the event
 * @param E An event
 */
static void handle_event(Event_T E) {
  Service_T S;

  ASSERT(E);
  ASSERT(E->action);
  ASSERT(E->action->failed);
  ASSERT(E->action->succeeded);

  /* We will handle only first succeeded event, recurrent succeeded events
   * or insufficient succeeded events during failed service state are
   * ignored. Failed events are handled each time. */
  if (!E->state_changed && (E->state == STATE_SUCCEEDED || E->state == STATE_CHANGEDNOT || ((E->state_map & 0x1) ^ 0x1)))
    return;

  S = Event_get_source(E);
  if (!S) {
    LogError("Event handling aborted\n");
    return;
  }

  if (E->message) {
    /* In the case that the service state is initializing yet and error
     * occured, log it and exit. Succeeded events in init state are not
     * logged. Instance and action events are logged always with priority
     * info. */
    if (E->state != STATE_INIT || E->state_map & 0x1) {
      if (E->state == STATE_SUCCEEDED || E->state == STATE_CHANGEDNOT || E->id == Event_Instance || E->id == Event_Action)
        LogInfo("'%s' %s\n", S->name, E->message);
      else
        LogError("'%s' %s\n", S->name, E->message);
    }
    if (E->state == STATE_INIT)
      return;
  }

  if (E->state == STATE_FAILED || E->state == STATE_CHANGED) {
    if (E->id != Event_Instance && E->id != Event_Action) { // We are not interested in setting error flag for instance and action events
      S->error |= E->id;
      /* The error hint provides second dimension for error bitmap and differentiates between failed/changed event states (failed=0, chaged=1) */
      if (E->state == STATE_CHANGED)
        S->error_hint |= E->id;
      else
        S->error_hint &= ~E->id;
    }
    handle_action(E, E->action->failed);
  } else {
    S->error &= ~E->id;
    handle_action(E, E->action->succeeded);
  }

  /* Possible event state change was handled so we will reset the flag. */
  E->state_changed = FALSE;
}


static void handle_action(Event_T E, Action_T A) {
  Service_T s;

  ASSERT(E);
  ASSERT(A);

  E->flag = HANDLER_SUCCEEDED;

  if (A->id == ACTION_IGNORE)
    return;

  /* Alert and mmonit event notification are common actions */
  E->flag |= handle_mmonit(E);
  E->flag |= handle_alert(E);

  /* In the case that some subhandler failed, enqueue the event for
   * partial reprocessing */
  if (E->flag != HANDLER_SUCCEEDED) {
    if (Run.eventlist_dir)
      Event_queue_add(E);
    else
      LogError("Aborting event\n");
  }

  if (!(s = Event_get_source(E))) {
    LogError("Event action handling aborted\n");
    return;
  }

  /* Action event is handled already. For Instance events
   * we don't want actions like stop to be executed
   * to prevent the disabling of system service monitoring */
  if (A->id == ACTION_ALERT || E->id == Event_Instance) {
    return;
  } else if (A->id == ACTION_EXEC) {
    LogInfo("'%s' exec: %s\n", s->name, A->exec->arg[0]);
    spawn(s, A->exec, E);
    return;
  } else {
    if (s->actionratelist && (A->id == ACTION_START || A->id == ACTION_RESTART))
      s->nstart++;

    if (s->mode == MODE_PASSIVE && (A->id == ACTION_START || A->id == ACTION_STOP  || A->id == ACTION_RESTART))
      return;

    control_service(s->name, A->id);
  }
}


/**
 * Add the partialy handled event to the global queue
 * @param E An event object
 */
static void Event_queue_add(Event_T E) {
  FILE        *file = NULL;
  char         file_name[STRLEN];
  int          version = EVENT_VERSION;
  short        action = Event_get_action(E);
  int          rv = FALSE;
  mode_t       mask;

  ASSERT(E);
  ASSERT(E->flag != HANDLER_SUCCEEDED);

  if (!File_checkQueueDirectory(Run.eventlist_dir, 0700)) {
    LogError("%s: Aborting event - cannot access the directory %s\n", prog, Run.eventlist_dir);
    return;
  }
    
  if (!File_checkQueueLimit(Run.eventlist_dir, Run.eventlist_slots)) {
    LogError("%s: Aborting event - queue over quota\n", prog);
    return;
  }
    
  /* compose the file name of actual timestamp and service name */
  snprintf(file_name, STRLEN, "%s/%ld_%lx", Run.eventlist_dir, (long int)time(NULL), (long unsigned)E->source);

  DEBUG("%s: Adding event to the queue file %s for later delivery\n", prog, file_name);

  mask = umask(QUEUEMASK);
  file = fopen(file_name, "w");
  umask(mask);
  if (! file) {
    LogError("%s: Aborting event - cannot open the event file %s -- %s\n", prog, file_name, STRERROR);
    return;
  }

  /* write event structure version */
  if (!(rv = File_writeQueue(file, &version, sizeof(int))))
    goto error;

  /* write event structure */
  if (!(rv = File_writeQueue(file, E, sizeof(*E))))
    goto error;

  /* write source */
  if (!(rv = File_writeQueue(file, E->source, E->source ? strlen(E->source)+1 : 0)))
    goto error;

  /* write message */
  if (!(rv = File_writeQueue(file, E->message, E->message ? strlen(E->message)+1 : 0)))
    goto error;

  /* write event action */
  if (!(rv = File_writeQueue(file, &action, sizeof(short))))
    goto error;

  error:
  fclose(file);
  if (!rv) {
    LogError("%s: Aborting event - unable to save event information to %s\n",  prog, file_name);
    if (unlink(file_name) < 0)
      LogError("Failed to remove event file '%s' -- %s\n", file_name, STRERROR);
  } else {
    if (!Run.handler_init && E->flag & HANDLER_ALERT)
      Run.handler_queue[HANDLER_ALERT]++;
    if (!Run.handler_init && E->flag & HANDLER_MMONIT)
      Run.handler_queue[HANDLER_MMONIT]++;
  }

  return;
}


/**
 * Update the partialy handled event in the global queue
 * @param E An event object
 * @param file_name File name
 */
static void Event_queue_update(Event_T E, const char *file_name) {
  FILE        *file = NULL;
  int          version = EVENT_VERSION;
  short        action = Event_get_action(E);
  int          rv = FALSE;
  mode_t       mask;

  ASSERT(E);
  ASSERT(E->flag != HANDLER_SUCCEEDED);

  if (!File_checkQueueDirectory(Run.eventlist_dir, 0700)) {
    LogError("%s: Aborting event - cannot access the directory %s\n", prog, Run.eventlist_dir);
    return;
  }
    
  DEBUG("%s: Updating event in the queue file %s for later delivery\n", prog, file_name);

  mask = umask(QUEUEMASK);
  file = fopen(file_name, "w");
  umask(mask);
  if (! file)
  {
    LogError("%s: Aborting event - cannot open the event file %s -- %s\n", prog, file_name, STRERROR);
    return;
  }

  /* write event structure version */
  if (!(rv = File_writeQueue(file, &version, sizeof(int))))
    goto error;

  /* write event structure */
  if (!(rv = File_writeQueue(file, E, sizeof(*E))))
    goto error;

  /* write source */
  if (!(rv = File_writeQueue(file, E->source, E->source ? strlen(E->source)+1 : 0)))
    goto error;

  /* write message */
  if (!(rv = File_writeQueue(file, E->message, E->message ? strlen(E->message)+1 : 0)))
    goto error;

  /* write event action */
  if (!(rv = File_writeQueue(file, &action, sizeof(short))))
    goto error;

  error:
  fclose(file);
  if (!rv) {
    LogError("%s: Aborting event - unable to update event information to %s\n",  prog, file_name);
    if (unlink(file_name) < 0)
      LogError("Failed to remove event file '%s' -- %s\n", file_name, STRERROR);
  }

  return;
}

