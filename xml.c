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
 *  @version \$Id: xml.c,v 1.56 2009/04/21 21:32:10 martinp Exp $
 *
 *  @file
 */


/* ------------------------------------------------------------- Definitions */


/** Defines an output buffer object */
typedef struct mybuffer {
  char          *buf;                               /**< Output buffer       */
  size_t         bufsize;                           /**< Output buffer size  */
  size_t         bufused;                           /**< Output buffer usage */
} Buffer_T;


/* -------------------------------------------------------------- Prototypes */


static void document_head(Buffer_T *);
static void document_foot(Buffer_T *);
static void status_service(Service_T, Buffer_T *, short);
static void status_event(Event_T, Buffer_T *);
static void buf_print(Buffer_T *, const char *, ...);


/* ------------------------------------------------------------------ Public */


/**
 * Return XML formated message for event notification or general status
 * of monitored services and resources.
 * @param E An event object or NULL for general status
 * @param L Status information level
 * @return XML document or NULL in the case of error. The caller must free
*  the memory.
 */
char *status_xml(Event_T E, short L) {

  Buffer_T  B;
  Service_T S;

  memset(&B, 0, sizeof(Buffer_T));

  document_head(&B);

  if(E)
  {
    /* there is no use for status level in the event (at least now) */
    status_event(E, &B);
  }
  else
  {
    for(S = servicelist_conf; S; S = S->next_conf)
    {
      status_service(S, &B, L);
    }
  }
  document_foot(&B);

  return B.buf;

}


/* ----------------------------------------------------------------- Private */


/**
 * Prints a document header into the given buffer.
 * @param B Buffer object
 */
static void document_head(Buffer_T *B) {

  buf_print(B,
   "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>"
   "<monit>"
   "<server>"
   "<id>%s</id>"
   "<incarnation>%ld</incarnation>"
   "<version>%s</version>"
   "<uptime>%ld</uptime>"
   "<poll>%d</poll>"
   "<startdelay>%d</startdelay>"
   "<localhostname>%s</localhostname>"
   "<controlfile>%s</controlfile>",
   Run.id,
   Run.incarnation,
   VERSION,
   (long)Util_getProcessUptime(Run.pidfile),
   Run.polltime,
   Run.startdelay,
   Run.localhostname ? Run.localhostname : "",
   Run.controlfile ? Run.controlfile : "");

  if(Run.dohttpd) {
    buf_print(B,
      "<httpd>"
      "<address>%s</address>"
      "<port>%d</port>"
      "<ssl>%d</ssl>"
      "</httpd>",
      Run.bind_addr?Run.bind_addr:"",
      Run.httpdport,
      Run.httpdssl);
  }
 
  buf_print(B,
     "</server>"
     "<platform>"
     "<name>%s</name>"
     "<release>%s</release>"
     "<version>%s</version>"
     "<machine>%s</machine>"
     "<cpu>%d</cpu>"
     "<memory>%lu</memory>"
     "</platform>",
     systeminfo.uname.sysname,
     systeminfo.uname.release,
     systeminfo.uname.version,
     systeminfo.uname.machine,
     systeminfo.cpus,
     systeminfo.mem_kbyte_max);

}


/**
 * Prints a document footer into the given buffer.
 * @param B Buffer object
 */
static void document_foot(Buffer_T *B) {

  buf_print(B, "</monit>");

}


/**
 * Prints a service status into the given buffer.
 * @param S Service object
 * @param B Buffer object
 * @param L Status information level
 */
static void status_service(Service_T S, Buffer_T *B, short L) {
  Event_T E = S->eventlist;
  buf_print(B,
	    "<service type=\"%d\">"
	    "<collected_sec>%ld</collected_sec>"
	    "<collected_usec>%ld</collected_usec>"
	    "<name>%s</name>"
	    "<status>%llu</status>"
	    "<status_hint>%llu</status_hint>"
	    "<monitor>%d</monitor>"
	    "<monitormode>%d</monitormode>"
	    "<pendingaction>%d</pendingaction>"
	    "<group>%s</group>",
	    S->type,
	    S->collected.tv_sec,
	    S->collected.tv_usec,
	    S->name?S->name:"",
	    S->error,
	    S->error_hint,
	    S->monitor,
	    S->mode,
	    S->doaction,
	    S->group?S->group:"");
  /* if the service is in error state, display first active error message to provide more details */
  while (E) {
    if ((E->state == STATE_FAILED || E->state == STATE_CHANGED) && (S->error & E->id) && E->message) {
       buf_print(B, "<status_message>%s</status_message>", E->message);
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
        buf_print(B,
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
        buf_print(B,
  		"<timestamp>%ld</timestamp>",
  		(long)S->inf->timestamp);
      }
      if(S->type == TYPE_FILE) {
        buf_print(B,
  		"<size>%llu</size>",
  		(unsigned long long) S->inf->st_size);
        if(S->checksum) {
          buf_print(B,
  		  "<checksum type=\"%s\">%s</checksum>",
  		  checksumnames[S->checksum->type], S->inf->cs_sum);
        }
      }
      if(S->type == TYPE_FILESYSTEM) {
        buf_print(B,
  		"<flags>%ld</flags>"
  		"<block>"
  		"<percent>%.1f</percent>"
  		"<usage>%.1f MB</usage>"
                "<total>%.1f MB</total>"
  		"</block>",
  		S->inf->flags,
  		S->inf->space_percent/10.,
  		(float)S->inf->space_total / (float)1048576 * (float)S->inf->f_bsize,
                (float)S->inf->f_blocks / (float)1048576 * (float)S->inf->f_bsize);
        if(S->inf->f_files > 0) {
          buf_print(B,
  		  "<inode>"
                  "<percent>%.1f</percent>"
                  "<usage>%ld</usage>"
                  "<total>%ld</total>"
		  "</inode>",
		  S->inf->inode_percent/10.,
		  S->inf->inode_total,
                  S->inf->f_files);
        }
      }
      if(S->type == TYPE_PROCESS) {
        buf_print(B,
  		"<pid>%d</pid>"
  		"<ppid>%d</ppid>"
  		"<uptime>%ld</uptime>",
  		S->inf->pid,
  		S->inf->ppid,
  		(long)S->inf->uptime);
        if(Run.doprocess) {
          buf_print(B,
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
		  S->inf->children,
		  S->inf->mem_percent/10.0,
	  	  S->inf->total_mem_percent/10.0,
  		  S->inf->mem_kbyte,
  		  S->inf->total_mem_kbyte,
  		  S->inf->cpu_percent/10.0,
  		  S->inf->total_cpu_percent/10.0);
        }
      }
      if(S->type == TYPE_HOST && S->icmplist) {
        Icmp_T i;
        for(i= S->icmplist; i; i= i->next) {
          buf_print(B,
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
            buf_print(B,
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
            buf_print(B,
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
				buf_print(B,
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
					"</system>",
					systeminfo.loadavg[0],
					systeminfo.loadavg[1],
					systeminfo.loadavg[2],
					systeminfo.total_cpu_user_percent/10.,
					systeminfo.total_cpu_syst_percent/10.,
					#ifdef HAVE_CPU_WAIT
					systeminfo.total_cpu_wait_percent/10.,
					#endif
					systeminfo.total_mem_percent/10.,
					systeminfo.total_mem_kbyte);
      }
    }
  }
  buf_print(B, "</service>");
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

  if(!(s = Event_get_source(E)))
    return;

  tv = Event_get_collected(E);

  buf_print(B,
    "<event>"
    "<collected_sec>%ld</collected_sec>"
    "<collected_usec>%ld</collected_usec>"
    "<service>%s</service>"
    "<type>%d</type>"
    "<group>%s</group>"
    "<id>%d</id>"
    "<state>%d</state>"
    "<action>%d</action>"
    "<message>%s</message>",
    tv->tv_sec,
    tv->tv_usec,
    Event_get_id(E) == EVENT_INSTANCE ? "Monit" : Event_get_source_name(E),
    Event_get_source_type(E),
    Event_get_source_group(E),
    Event_get_id(E),
    Event_get_state(E),
    Event_get_action(E),
    Event_get_message(E));
  if (s->token) {
    buf_print(B,
      "<token>%s</token>",
      s->token);
  }
  buf_print(B,
    "</event>");
}


/**
 * Prints a string into the given buffer.
 * @param B Buffer object
 * @param m A formated string to be written to the buffer
 */
static void buf_print(Buffer_T *B, const char *m, ...) {
  if(m)
  {
    va_list  ap;
    char    *buf;
    long     need= 0;
    ssize_t  have= 0;

    va_start(ap, m);
    buf = Util_formatString(m, ap, &need);
    va_end(ap);

    have = (*B).bufsize - (*B).bufused;
    if(have <= need)
    {
      (*B).bufsize += (need + STRLEN);
      (*B).buf = xresize((*B).buf, (*B).bufsize);
      if(!(*B).bufused)
      {
        memset((*B).buf, 0, (*B).bufsize);
      }
    }
    memcpy(&(*B).buf[(*B).bufused], buf, need);
    (*B).bufused += need;
    (*B).buf[(*B).bufused]= 0;
    FREE(buf);
  }
}

