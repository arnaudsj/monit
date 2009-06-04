/*
 * Copyright (C) 2009 Tildeslash Ltd. All rights reserved.
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

#ifndef MONIT_EVENT_H
#define MONIT_EVENT_H

#include "monitor.h"

#define EVENT_NULL            0x0
#define EVENT_CHECKSUM        0x1
#define EVENT_RESOURCE        0x2
#define EVENT_TIMEOUT         0x4
#define EVENT_TIMESTAMP       0x8
#define EVENT_SIZE            0x10
#define EVENT_CONNECTION      0x20
#define EVENT_PERMISSION      0x40
#define EVENT_UID             0x80
#define EVENT_GID             0x100
#define EVENT_NONEXIST        0x200
#define EVENT_INVALID         0x400
#define EVENT_DATA            0x800
#define EVENT_EXEC            0x1000
#define EVENT_FSFLAG          0x2000
#define EVENT_ICMP            0x4000
#define EVENT_CONTENT         0x8000
#define EVENT_INSTANCE        0x10000
#define EVENT_ACTION          0x20000
#define EVENT_PID             0x40000
#define EVENT_PPID            0x80000
#define EVENT_HEARTBEAT       0x100000
#define EVENT_ALL             0xFFFFFFFF

#define IS_EVENT_SET(value, mask) ((value & mask) != 0)

typedef struct myeventtable {
  int id;
  char *description_failed;
  char *description_succeeded;
  char *description_changed;
  char *description_changednot;
} EventTable_T;

extern EventTable_T Event_Table[];


/**
 * This class implements the <b>event</b> processing machinery used by
 * monit. In monit an event is an object containing a Service_T
 * reference indicating the object where the event orginated, an id
 * specifying the event type, a value representing up or down state
 * and an optional message describing why the event was fired.
 *
 * Clients may use the function Event_post() to post events to the
 * event handler for processing.
 * 
 * @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 * @author Martin Pala, <martinp@tildeslash.com>
 * @version \$Id: event.h,v 1.37 2009/04/19 20:13:57 martinp Exp $
 * @file
 */

/**
 * Post a new Event
 * @param service The Service the event belongs to
 * @param id The event identification
 * @param state The event state
 * @param action Description of the event action
 * @param s Optional message describing the event
 */
void Event_post(Service_T service, long id, short state, EventAction_T action, char *s, ...);


/**
 * Get the Service where the event orginated
 * @param E An event object
 * @return The Service where the event orginated
 */
Service_T Event_get_source(Event_T E);


/**
 * Get the Service name where the event orginated
 * @param E An event object
 * @return The Service name where the event orginated
 */
char *Event_get_source_name(Event_T E);


/**
 * Get the group name of the service where the event orginated
 * @param E An event object
 * @return The group name of the service where the event orginated
 */
char *Event_get_source_group(Event_T E);


/**
 * Get the service type of the service where the event orginated
 * @param E An event object
 * @return The service type of the service where the event orginated
 */
int Event_get_source_type(Event_T E);


/**
 * Get the Event timestamp
 * @param E An event object
 * @return The Event timestamp
 */
struct timeval *Event_get_collected(Event_T E);


/**
 * Get the Event raw state
 * @param E An event object
 * @return The Event raw state
 */
short Event_get_state(Event_T E);


/**
 * Return the actual event state based on event state bitmap
 * and event ratio needed to trigger the state change
 * @param E An event object
 * @param S Actual posted state
 * @return The Event raw state
 */
short Event_check_state(Event_T E, short S);


/**
 * Get the Event type
 * @param E An event object
 * @return The Event type
 */
int Event_get_id(Event_T E);


/**
 * Get the optionally Event message describing why the event was
 * fired.
 * @param E An event object
 * @return The Event message. May be NULL
 */
const char *Event_get_message(Event_T E);


/**
 * Get a textual description of actual event type. For instance if the
 * event type is possitive EVENT_TIMESTAMP, the textual description is
 * "Timestamp error". Likewise if the event type is negative EVENT_CHECKSUM
 * the textual description is "Checksum recovery" and so on.
 * @param E An event object
 * @return A string describing the event type in clear text. If the
 * event type is not found NULL is returned.
 */
const char *Event_get_description(Event_T E);


/**
 * Get an event action id.
 * @param E An event object
 * @return An action id
 */
short Event_get_action(Event_T E);


/**
 * Get a textual description of actual event action. For instance if the
 * event type is possitive EVENT_NONEXIST, the textual description of
 * failed state related action is "restart". Likewise if the event type is
 * negative EVENT_CHECKSUM the textual description of recovery related action
 * is "alert" and so on.
 * @param E An event object
 * @return A string describing the event type in clear text. If the
 * event type is not found NULL is returned.
 */
const char *Event_get_action_description(Event_T E);


/**
 * Reprocess the partialy handled event queue
 */
void Event_queue_process();


#endif
