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


#ifndef MONIT_STATE_H
#define MONIT_STATE_H


/**
 *  Manage service information persistently. Service data is saved to
 *  a state file when monit runs in daemon mode for each poll
 *  cycle. Monit use this file to recover from a crash or to maintain
 *  service data persistently during a reload. The location of the
 *  state file may be set from the command line or set in the monitrc
 *  file, if not set, the default is ~/.monit.state.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @file
 */


/**
 * Save service state information to the state file
 */
void State_save();


/**
 * Check if we should update current services with persistent state
 * information. The logic is as follows: Iff a state file is present
 * *and* older than the running monit daemon's lock file we have had a
 * crash and should update data from the state file.
 * @return TRUE if the state should be updated otherwise FALSE
 */
int State_shouldUpdate();


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
void State_update();


#endif
