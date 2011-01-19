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


#ifndef ENGINE_H
#define ENGINE_H

#include <config.h>

#include "net.h"
#include "processor.h"
#include "cervlet.h"

/*
 * The maximum queue length for incoming connection
 * indications (a request to connect)
 */
#define DEFAULT_QUEUE_LEN  10

typedef struct host_allow {
  unsigned long network;
  unsigned long mask;
  /* For internal use */
  struct host_allow *next;
} *HostsAllow;

/* Public prototypes */
void start_httpd(int port, int backlog, char *bindAddr);
void stop_httpd();
int add_host_allow(char *);
int add_net_allow(char *);
int has_hosts_allow();
void destroy_hosts_allow();


#endif
