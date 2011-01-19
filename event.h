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

#ifndef MONIT_EVENT_H
#define MONIT_EVENT_H

#include "monitor.h"


typedef enum {
        Event_Null       = 0x0,
        Event_Checksum   = 0x1,
        Event_Resource   = 0x2,
        Event_Timeout    = 0x4,
        Event_Timestamp  = 0x8,
        Event_Size       = 0x10,
        Event_Connection = 0x20,
        Event_Permission = 0x40,
        Event_Uid        = 0x80,
        Event_Gid        = 0x100,
        Event_Nonexist   = 0x200,
        Event_Invalid    = 0x400,
        Event_Data       = 0x800,
        Event_Exec       = 0x1000,
        Event_Fsflag     = 0x2000,
        Event_Icmp       = 0x4000,
        Event_Content    = 0x8000,
        Event_Instance   = 0x10000,
        Event_Action     = 0x20000,
        Event_Pid        = 0x40000,
        Event_PPid       = 0x80000,
        Event_Heartbeat  = 0x100000,
        Event_All        = 0xFFFFFFFF
} Event_Type;


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
 * event type is possitive Event_Timestamp, the textual description is
 * "Timestamp error". Likewise if the event type is negative Event_Checksum 
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
 * event type is possitive Event_Nonexist, the textual description of
 * failed state related action is "restart". Likewise if the event type is
 * negative Event_Checksum the textual description of recovery related action
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
