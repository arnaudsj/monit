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

#ifdef HAVE_STRING_H
#include <string.h>
#endif 

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif 

#include "monitor.h"
#include "event.h"
#include "process.h"


/**
 *  XML routines for status and event notification message handling.
 *
 *  @author Martin Pala, <martinp@tildeslash.com>
 *
 *  @file
 */


/* -------------------------------------------------------------- Prototypes */


static void document_head(Buffer_T *, int, const char *);
static void document_foot(Buffer_T *);
static void status_service(Service_T, Buffer_T *, short, int);
static void status_servicegroup(ServiceGroup_T, Buffer_T *, short);
static void status_event(Event_T, Buffer_T *);


/* ------------------------------------------------------------------ Public */


/**
 * Return XML formated message for event notification or general status
 * of monitored services and resources.
 * @param E An event object or NULL for general status
 * @param L Status information level
 * @param V Format version
 * @param myip The client-side IP address
 * @return XML document or NULL in the case of error. The caller must free
*  the memory.
 */
char *status_xml(Event_T E, short L, int V, const char *myip) {
  Buffer_T  B;
  Service_T S;
  ServiceGroup_T SG;

  memset(&B, 0, sizeof(Buffer_T));

  document_head(&B, V, myip);

  if (V == 2)
    Util_stringbuffer(&B, "<services>");
  for (S = servicelist_conf; S; S = S->next_conf)
    status_service(S, &B, L, V);
  if (V == 2) {
    Util_stringbuffer(&B, "</services>"
                          "<servicegroups>");
    for (SG = servicegrouplist; SG; SG = SG->next)
      status_servicegroup(SG, &B, L);
    Util_stringbuffer(&B, "</servicegroups>");
  }
  if (E)
    status_event(E, &B);

  document_foot(&B);

  return B.buf;

}


/* ----------------------------------------------------------------- Private */


/**
 * Prints a document header into the given buffer.
 * @param B Buffer object
 * @param V Format version
 * @param myip The client-side IP address
 */
static void document_head(Buffer_T *B, int V, const char *myip) {
  Util_stringbuffer(B,
    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>");
  if (V == 2) {
    Util_stringbuffer(B,
      "<monit id=\"%s\" incarnation=\"%lld\" version=\"%s\">"
      "<server>",
      Run.id,
      (long long)Run.incarnation,
      VERSION);
  } else {
    Util_stringbuffer(B,
      "<monit>"
      "<server>"
      "<id>%s</id>"
      "<incarnation>%lld</incarnation>"
      "<version>%s</version>",
      Run.id,
      (long long)Run.incarnation,
      VERSION);
  }
  Util_stringbuffer(B,
    "<uptime>%ld</uptime>"
    "<poll>%d</poll>"
    "<startdelay>%d</startdelay>"
    "<localhostname>%s</localhostname>"
    "<controlfile>%s</controlfile>",
    (long)Util_getProcessUptime(Run.pidfile),
    Run.polltime,
    Run.startdelay,
    Run.localhostname ? Run.localhostname : "",
    Run.controlfile ? Run.controlfile : "");

  if(Run.dohttpd) {
    Util_stringbuffer(B,
      "<httpd>"
      "<address>%s</address>"
      "<port>%d</port>"
      "<ssl>%d</ssl>"
      "</httpd>",
      Run.bind_addr ? Run.bind_addr : myip,
      Run.httpdport,
      Run.httpdssl);

    if (Run.mmonitcredentials)
        Util_stringbuffer(B,
          "<credentials>"
          "<username>%s</username>"
          "<password>%s</password>"
          "</credentials>",
          Run.mmonitcredentials->uname,
          Run.mmonitcredentials->passwd);
  }
 
  Util_stringbuffer(B,
     "</server>"
     "<platform>"
     "<name>%s</name>"
     "<release>%s</release>"
     "<version>%s</version>"
     "<machine>%s</machine>"
     "<cpu>%d</cpu>"
     "<memory>%lu</memory>"
     "<swap>%lu</swap>"
     "</platform>",
     systeminfo.uname.sysname,
     systeminfo.uname.release,
     systeminfo.uname.version,
     systeminfo.uname.machine,
     systeminfo.cpus,
     systeminfo.mem_kbyte_max,
     systeminfo.swap_kbyte_max);

}


/**
 * Prints a document footer into the given buffer.
 * @param B Buffer object
 */
static void document_foot(Buffer_T *B) {
  Util_stringbuffer(B, "</monit>");
}


/**
 * Prints a service status into the given buffer.
 * @param S Service object
 * @param B Buffer object
 * @param L Status information level
 * @param V Format version
 */
static void status_service(Service_T S, Buffer_T *B, short L, int V) {
  Event_T E = S->eventlist;

  if (V == 2)
    Util_stringbuffer(B,
      "<service name=\"%s\">"
      "<type>%d</type>",
      S->name ? S->name : "",
      S->type);
  else
    Util_stringbuffer(B,
      "<service type=\"%d\">"
      "<name>%s</name>",
      S->type,
      S->name ? S->name : "");
  Util_stringbuffer(B,
    "<collected_sec>%ld</collected_sec>"
    "<collected_usec>%ld</collected_usec>"
    "<status>%d</status>"
    "<status_hint>%d</status_hint>"
    "<monitor>%d</monitor>"
    "<monitormode>%d</monitormode>"
    "<pendingaction>%d</pendingaction>",
    S->collected.tv_sec,
    S->collected.tv_usec,
    S->error,
    S->error_hint,
    S->monitor,
    S->mode,
    S->doaction);

  /* if the service is in error state, display first active error message to provide more details */
  while (E) {
    if ((E->state == STATE_FAILED || E->state == STATE_CHANGED) && (S->error & E->id) && E->message) {
       Util_stringbuffer(B, "<status_message><![CDATA[%s]]></status_message>", E->message);
       break;
    }
    E = E->next;
  } 
  if(L == LEVEL_FULL)
  {
    if(Util_hasServiceStatus(S)) {
      if(S->type == TYPE_FILE || 
         S->type == TYPE_DIRECTORY ||
         S->type == TYPE_FIFO ||
         S->type == TYPE_FILESYSTEM) {
        Util_stringbuffer(B,
  		"<mode>%o</mode>"
  		"<uid>%d</uid>"
  		"<gid>%d</gid>",
  		S->inf->st_mode & 07777,
  		(int)S->inf->st_uid,
  		(int)S->inf->st_gid);
      }
      if(S->type == TYPE_FILE ||
         S->type == TYPE_FIFO ||
         S->type == TYPE_DIRECTORY)  {
        Util_stringbuffer(B,
  		"<timestamp>%ld</timestamp>",
  		(long)S->inf->timestamp);
      }
      if(S->type == TYPE_FILE) {
        Util_stringbuffer(B,
  		"<size>%llu</size>",
  		(unsigned long long) S->inf->priv.file.st_size);
        if(S->checksum) {
          Util_stringbuffer(B,
  		  "<checksum type=\"%s\">%s</checksum>",
  		  checksumnames[S->checksum->type], S->inf->priv.file.cs_sum);
        }
      }
      if(S->type == TYPE_FILESYSTEM) {
        Util_stringbuffer(B,
  		"<flags>%ld</flags>"
  		"<block>"
  		"<percent>%.1f</percent>"
  		"<usage>%.1f MB</usage>"
                "<total>%.1f MB</total>"
  		"</block>",
  		S->inf->priv.filesystem.flags,
  		S->inf->priv.filesystem.space_percent/10.,
  		S->inf->priv.filesystem.f_bsize > 0 ? (float)S->inf->priv.filesystem.space_total / (float)1048576 * (float)S->inf->priv.filesystem.f_bsize : 0,
                S->inf->priv.filesystem.f_bsize > 0 ? (float)S->inf->priv.filesystem.f_blocks / (float)1048576 * (float)S->inf->priv.filesystem.f_bsize : 0);
        if(S->inf->priv.filesystem.f_files > 0) {
          Util_stringbuffer(B,
  		  "<inode>"
                  "<percent>%.1f</percent>"
                  "<usage>%ld</usage>"
                  "<total>%ld</total>"
		  "</inode>",
		  S->inf->priv.filesystem.inode_percent/10.,
		  S->inf->priv.filesystem.inode_total,
                  S->inf->priv.filesystem.f_files);
        }
      }
      if(S->type == TYPE_PROCESS) {
        Util_stringbuffer(B,
  		"<pid>%d</pid>"
  		"<ppid>%d</ppid>"
  		"<uptime>%ld</uptime>",
  		S->inf->priv.process.pid,
  		S->inf->priv.process.ppid,
  		(long)S->inf->priv.process.uptime);
        if(Run.doprocess) {
          Util_stringbuffer(B,
  		  "<children>%d</children>"
  		  "<memory>"
  		  "<percent>%.1f</percent>"
  		  "<percenttotal>%.1f</percenttotal>"
  		  "<kilobyte>%ld</kilobyte>"
  		  "<kilobytetotal>%ld</kilobytetotal>"
  		  "</memory>"
  		  "<cpu>"
		  "<percent>%.1f</percent>"
		  "<percenttotal>%.1f</percenttotal>"
		  "</cpu>",
		  S->inf->priv.process.children,
		  S->inf->priv.process.mem_percent/10.0,
	  	  S->inf->priv.process.total_mem_percent/10.0,
  		  S->inf->priv.process.mem_kbyte,
  		  S->inf->priv.process.total_mem_kbyte,
  		  S->inf->priv.process.cpu_percent/10.0,
  		  S->inf->priv.process.total_cpu_percent/10.0);
        }
      }
      if(S->type == TYPE_HOST && S->icmplist) {
        Icmp_T i;
        for(i= S->icmplist; i; i= i->next) {
          Util_stringbuffer(B,
  		  "<icmp>"
  		  "<type>%s</type>"
  		  "<responsetime>%.3f</responsetime>"
  		  "</icmp>",
  		  icmpnames[i->type],
  		  i->is_available?i->response:-1.);
        }
      }
      if((S->type == TYPE_HOST || S->type == TYPE_PROCESS) && S-> portlist) {
        Port_T p;
        for(p= S->portlist; p; p= p->next) {
          if(p->family == AF_INET) {
            Util_stringbuffer(B,
  		    "<port>"
  		    "<hostname>%s</hostname>"
  		    "<portnumber>%d</portnumber>"
  		    "<request>%s</request>"
  		    "<protocol>%s</protocol>"
  		    "<type>%s</type>"
  		    "<responsetime>%.3f</responsetime>"
  		    "</port>",
  		    p->hostname?p->hostname:"",
  		    p->port,
  		    p->request?p->request:"",
  		    p->protocol->name?p->protocol->name:"",
  		    Util_portTypeDescription(p),
  		    p->is_available?p->response:-1.);
  	  
          } else if(p->family == AF_UNIX) {
            Util_stringbuffer(B,
  		    "<unix>"
		    "<path>%s</path>"
		    "<protocol>%s</protocol>"
		    "<responsetime>%.3f</responsetime>"
		    "</unix>",
		    p->pathname?p->pathname:"",
		    p->protocol->name?p->protocol->name:"",
		    p->is_available?p->response:-1.);
          }
        }
      }
      if(S->type == TYPE_SYSTEM && Run.doprocess) {
				Util_stringbuffer(B,
					"<system>"
					"<load>"
					"<avg01>%.2f</avg01>"
					"<avg05>%.2f</avg05>"
					"<avg15>%.2f</avg15>"
					"</load>"
					"<cpu>"
					"<user>%.1f</user>"
					"<system>%.1f</system>"
#ifdef HAVE_CPU_WAIT
				        "<wait>%.1f</wait>"
#endif
					"</cpu>"
					"<memory>"
					"<percent>%.1f</percent>"
					"<kilobyte>%ld</kilobyte>"
					"</memory>"
                                        "<swap>"
                                        "<percent>%.1f</percent>"
                                        "<kilobyte>%ld</kilobyte>"
                                        "</swap>"
					"</system>",
					systeminfo.loadavg[0],
					systeminfo.loadavg[1],
					systeminfo.loadavg[2],
					systeminfo.total_cpu_user_percent > 0 ? systeminfo.total_cpu_user_percent/10. : 0,
					systeminfo.total_cpu_syst_percent > 0 ? systeminfo.total_cpu_syst_percent/10. : 0,
					#ifdef HAVE_CPU_WAIT
					systeminfo.total_cpu_wait_percent > 0 ? systeminfo.total_cpu_wait_percent/10. : 0,
					#endif
					systeminfo.total_mem_percent/10.,
					systeminfo.total_mem_kbyte,
                                        systeminfo.total_swap_percent/10.,
                                        systeminfo.total_swap_kbyte);
      }
    }
  }
  Util_stringbuffer(B, "</service>");
}


/**
 * Prints a servicegroups into the given buffer.
 * @param SG ServiceGroup object
 * @param B Buffer object
 * @param L Status information level
 */
static void status_servicegroup(ServiceGroup_T SG, Buffer_T *B, short L) {
  ServiceGroupMember_T SGM;

  Util_stringbuffer(B, "<servicegroup name=\"%s\">", SG->name);
  for (SGM = SG->members; SGM; SGM = SGM->next)
    Util_stringbuffer(B, "<service>%s</service>", SGM->name);
  Util_stringbuffer(B, "</servicegroup>");
}


/**
 * Prints a event description into the given buffer.
 * @param E Event object
 * @param B Buffer object
 */
static void status_event(Event_T E, Buffer_T *B) {
  Service_T s;
  struct timeval *tv;

  ASSERT(E);

  tv = Event_get_collected(E);

  Util_stringbuffer(B,
    "<event>"
    "<collected_sec>%ld</collected_sec>"
    "<collected_usec>%ld</collected_usec>"
    "<service>%s</service>"
    "<type>%d</type>"
    "<id>%d</id>"
    "<state>%d</state>"
    "<action>%d</action>"
    "<message><![CDATA[%s]]></message>",
    tv->tv_sec,
    tv->tv_usec,
    Event_get_id(E) == Event_Instance ? "Monit" : Event_get_source_name(E),
    Event_get_source_type(E),
    Event_get_id(E),
    Event_get_state(E),
    Event_get_action(E),
    Event_get_message(E));
  if ((s = Event_get_source(E)) && s->token)
    Util_stringbuffer(B, "<token>%s</token>", s->token);
  Util_stringbuffer(B,
    "</event>");
}

