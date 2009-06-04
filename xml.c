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
   "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\r\n"
   "<monit>\r\n"
   "\t<server>\r\n"
   "\t\t<id>%s</id>\r\n"
   "\t\t<incarnation>%ld</incarnation>\r\n"
   "\t\t<version>%s</version>\r\n"
   "\t\t<uptime>%ld</uptime>\r\n"
   "\t\t<poll>%d</poll>\r\n"
   "\t\t<startdelay>%d</startdelay>\r\n"
   "\t\t<localhostname>%s</localhostname>\r\n"
   "\t\t<controlfile>%s</controlfile>\r\n",
   Run.id,
   Run.incarnation,
   VERSION,
   (long)Util_getProcessUptime(Run.pidfile),
   Run.polltime,
   Run.startdelay,
   Run.localhostname ? Run.localhostname : "",
   Run.controlfile ? Run.controlfile : "");

  if(Run.dohttpd)
  {
    buf_print(B,
      "\t\t<httpd>\r\n"
      "\t\t\t<address>%s</address>\r\n"
      "\t\t\t<port>%d</port>\r\n"
      "\t\t\t<ssl>%d</ssl>\r\n"
      "\t\t</httpd>\r\n",
      Run.bind_addr?Run.bind_addr:"",
      Run.httpdport,
      Run.httpdssl);
  }
 
  buf_print(B,
   "\t</server>\r\n"
   "\t<platform>\r\n"
   "\t\t<name>%s</name>\r\n"
   "\t\t<release>%s</release>\r\n"
   "\t\t<version>%s</version>\r\n"
   "\t\t<machine>%s</machine>\r\n"
   "\t\t<cpu>%d</cpu>\r\n"
   "\t\t<memory>%lu</memory>\r\n"
   "\t</platform>\r\n",
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

  buf_print(B, "</monit>\r\n");

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
	    "\t<service type=\"%d\">\r\n"
	    "\t\t<collected_sec>%ld</collected_sec>\r\n"
	    "\t\t<collected_usec>%ld</collected_usec>\r\n"
	    "\t\t<name>%s</name>\r\n"
	    "\t\t<status>%llu</status>\r\n"
	    "\t\t<status_hint>%llu</status_hint>\r\n"
	    "\t\t<monitor>%d</monitor>\r\n"
	    "\t\t<monitormode>%d</monitormode>\r\n"
	    "\t\t<pendingaction>%d</pendingaction>\r\n"
	    "\t\t<group>%s</group>\r\n",
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
       buf_print(B, "\t\t<status_message>%s</status_message>\r\n", E->message);
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
  		"\t\t<mode>%o</mode>\r\n"
  		"\t\t<uid>%d</uid>\r\n"
  		"\t\t<gid>%d</gid>\r\n",
  		S->inf->st_mode & 07777,
  		(int)S->inf->st_uid,
  		(int)S->inf->st_gid);
      }
      if(S->type == TYPE_FILE ||
         S->type == TYPE_FIFO ||
         S->type == TYPE_DIRECTORY)  {
        buf_print(B,
  		"\t\t<timestamp>%ld</timestamp>\r\n",
  		(long)S->inf->timestamp);
      }
      if(S->type == TYPE_FILE) {
        buf_print(B,
  		"\t\t<size>%llu</size>\r\n",
  		(unsigned long long) S->inf->st_size);
        if(S->checksum) {
          buf_print(B,
  		  "\t\t<checksum type=\"%s\">%s</checksum>\r\n",
  		  checksumnames[S->checksum->type], S->inf->cs_sum);
        }
      }
      if(S->type == TYPE_FILESYSTEM) {
        buf_print(B,
  		"\t\t<flags>%ld</flags>\r\n"
  		"\t\t<block>\r\n"
  		"\t\t\t<percent>%.1f</percent>\r\n"
  		"\t\t\t<usage>%.1f MB</usage>\r\n"
                "\t\t\t<total>%.1f MB</total>\r\n"
  		"\t\t</block>\r\n",
  		S->inf->flags,
  		S->inf->space_percent/10.,
  		(float)S->inf->space_total / (float)1048576 * (float)S->inf->f_bsize,
                (float)S->inf->f_blocks / (float)1048576 * (float)S->inf->f_bsize);
        if(S->inf->f_files > 0) {
          buf_print(B,
  		  "\t\t<inode>\r\n"
                  "\t\t\t<percent>%.1f</percent>\r\n"
                  "\t\t\t<usage>%ld</usage>\r\n"
                  "\t\t\t<total>%ld</total>\r\n"
		  "\t\t</inode>\r\n",
		  S->inf->inode_percent/10.,
		  S->inf->inode_total,
                  S->inf->f_files);
        }
      }
      if(S->type == TYPE_PROCESS) {
        buf_print(B,
  		"\t\t<pid>%d</pid>\r\n"
  		"\t\t<ppid>%d</ppid>\r\n"
  		"\t\t<uptime>%ld</uptime>\r\n",
  		S->inf->pid,
  		S->inf->ppid,
  		(long)S->inf->uptime);
        if(Run.doprocess) {
          buf_print(B,
  		  "\t\t<children>%d</children>\r\n"
  		  "\t\t<memory>\r\n"
  		  "\t\t\t<percent>%.1f</percent>\r\n"
  		  "\t\t\t<percenttotal>%.1f</percenttotal>\r\n"
  		  "\t\t\t<kilobyte>%ld</kilobyte>\r\n"
  		  "\t\t\t<kilobytetotal>%ld</kilobytetotal>\r\n"
  		  "\t\t</memory>\r\n"
  		  "\t\t<cpu>\r\n"
		  "\t\t\t<percent>%.1f</percent>\r\n"
		  "\t\t\t<percenttotal>%.1f</percenttotal>\r\n"
		  "\t\t</cpu>\r\n",
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
  		  "\t\t<icmp>\r\n"
  		  "\t\t\t<type>%s</type>\r\n"
  		  "\t\t\t<responsetime>%.3f</responsetime>\r\n"
  		  "\t\t</icmp>\r\n",
  		  icmpnames[i->type],
  		  i->is_available?i->response:-1.);
        }
      }
      if((S->type == TYPE_HOST || S->type == TYPE_PROCESS) && S-> portlist) {
        Port_T p;
        for(p= S->portlist; p; p= p->next) {
          if(p->family == AF_INET) {
            buf_print(B,
  		    "\t\t<port>\r\n"
  		    "\t\t\t<hostname>%s</hostname>\r\n"
  		    "\t\t\t<portnumber>%d</portnumber>\r\n"
  		    "\t\t\t<request>%s</request>\r\n"
  		    "\t\t\t<protocol>%s</protocol>\r\n"
  		    "\t\t\t<type>%s</type>\r\n"
  		    "\t\t\t<responsetime>%.3f</responsetime>\r\n"
  		    "\t\t</port>\r\n",
  		    p->hostname?p->hostname:"",
  		    p->port,
  		    p->request?p->request:"",
  		    p->protocol->name?p->protocol->name:"",
  		    Util_portTypeDescription(p),
  		    p->is_available?p->response:-1.);
  	  
          } else if(p->family == AF_UNIX) {
            buf_print(B,
  		    "\t\t<unix>\r\n"
		    "\t\t\t<path>%s</path>\r\n"
		    "\t\t\t<protocol>%s</protocol>\r\n"
		    "\t\t\t<responsetime>%.3f</responsetime>\r\n"
		    "\t\t</unix>\r\n",
		    p->pathname?p->pathname:"",
		    p->protocol->name?p->protocol->name:"",
		    p->is_available?p->response:-1.);
          }
        }
      }
      if(S->type == TYPE_SYSTEM && Run.doprocess) {
				buf_print(B,
					"\t\t<system>\r\n"
					"\t\t\t<load>\r\n"
					"\t\t\t\t<avg01>%.2f</avg01>\r\n"
					"\t\t\t\t<avg05>%.2f</avg05>\r\n"
					"\t\t\t\t<avg15>%.2f</avg15>\r\n"
					"\t\t\t</load>\r\n"
					"\t\t\t<cpu>\r\n"
					"\t\t\t\t<user>%.1f</user>\r\n"
					"\t\t\t\t<system>%.1f</system>\r\n"
#ifdef HAVE_CPU_WAIT
				        "\t\t\t\t<wait>%.1f</wait>\r\n"
#endif
					"\t\t\t</cpu>\r\n"
					"\t\t\t<memory>\r\n"
					"\t\t\t\t<percent>%.1f</percent>\r\n"
					"\t\t\t\t<kilobyte>%ld</kilobyte>\r\n"
					"\t\t\t</memory>\r\n"
					"\t\t</system>\r\n",
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
  buf_print(B, "\t</service>\r\n");
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
    "\t<event>\r\n"
    "\t\t<collected_sec>%ld</collected_sec>\r\n"
    "\t\t<collected_usec>%ld</collected_usec>\r\n"
    "\t\t<service>%s</service>\r\n"
    "\t\t<type>%d</type>\r\n"
    "\t\t<group>%s</group>\r\n"
    "\t\t<id>%d</id>\r\n"
    "\t\t<state>%d</state>\r\n"
    "\t\t<action>%d</action>\r\n"
    "\t\t<message>%s</message>\r\n",
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
      "\t\t<token>%s</token>\r\n",
      s->token);
  }
  buf_print(B,
    "\t</event>\r\n");
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

