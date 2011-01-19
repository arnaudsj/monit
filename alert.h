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


#ifndef MONIT_ALERT_H
#define MONIT_ALERT_H

#include "event.h"


/** Default mail from string */
#define ALERT_FROM    "monit@$HOST"

/** Default mail subject */
#define ALERT_SUBJECT "monit alert --  $EVENT $SERVICE"

/** Default mail message */
#define ALERT_MESSAGE "$EVENT Service $SERVICE \r\n"\
                      "\r\n"\
                      "\tDate:        $DATE\r\n"\
                      "\tAction:      $ACTION\r\n"\
	              "\tHost:        $HOST\r\n"\
	              "\tDescription: $DESCRIPTION\r\n"\
		      "\r\n"\
		      "Your faithful employee,\r\n"\
	              "Monit\r\n"


/**
 *  This module is used for event notifications. Users may register
 *  interest for certain events in the monit control file. When an
 *  event occurs this module is called from the event processing
 *  machinery to notify users who have asked to be alerted for
 *  particular events.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Martin Pala <martinp@tildeslash.com>
 *  @author Christian Hopp <chopp@iei.tu-clausthal.de>
 *
 *  @file
 */


/**
 * Notify registred users about the event
 * @param E An Event object
 * @return If failed, return HANDLER_ALERT flag or HANDLER_SUCCEEDED flag if succeeded
 */
int handle_alert(Event_T E);


#endif
