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

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include "monitor.h"
#include "cervlet.h" 
#include "engine.h"
#include "processor.h"
#include "base64.h"
#include "event.h" 
#include "alert.h"
#include "process.h"
#include "device.h"

#define ACTION(c) !strncasecmp(req->url, c, sizeof(c))

/* URL Commands supported */
#define HOME        "/"
#define TEST        "/_monit"
#define ABOUT       "/_about"
#define PING        "/_ping"
#define GETID       "/_getid"
#define PIXEL       "/_pixel"
#define STATUS      "/_status"
#define RUN         "/_runtime"
#define VIEWLOG     "/_viewlog"
#define DOACTION    "/_doaction"

/* Private prototypes */
static int is_readonly(HttpRequest);
static void printPixel(HttpResponse);
static void doGet(HttpRequest, HttpResponse);
static void doPost(HttpRequest, HttpResponse);
static void do_home(HttpRequest, HttpResponse);
static void do_home_system(HttpRequest, HttpResponse);
static void do_home_filesystem(HttpRequest, HttpResponse);
static void do_home_directory(HttpRequest, HttpResponse);
static void do_home_file(HttpRequest, HttpResponse);
static void do_home_fifo(HttpRequest, HttpResponse);
static void do_home_process(HttpRequest, HttpResponse);
static void do_home_host(HttpRequest, HttpResponse);
static void do_about(HttpRequest, HttpResponse);
static void do_ping(HttpRequest, HttpResponse);
static void do_getid(HttpRequest, HttpResponse);
static void do_runtime(HttpRequest, HttpResponse);
static void do_viewlog(HttpRequest, HttpResponse);
static void handle_action(HttpRequest, HttpResponse);
static void handle_do_action(HttpRequest, HttpResponse);
static void handle_run(HttpRequest, HttpResponse);
static void is_monit_running(HttpRequest, HttpResponse);
static void do_service(HttpRequest, HttpResponse, Service_T);
static void print_alerts(HttpResponse, Mail_T);
static void print_buttons(HttpRequest, HttpResponse, Service_T);
static void print_service_rules_port(HttpResponse, Service_T);
static void print_service_rules_icmp(HttpResponse, Service_T);
static void print_service_rules_perm(HttpResponse, Service_T);
static void print_service_rules_uid(HttpResponse, Service_T);
static void print_service_rules_gid(HttpResponse, Service_T);
static void print_service_rules_timestamp(HttpResponse, Service_T);
static void print_service_rules_filesystem(HttpResponse, Service_T);
static void print_service_rules_size(HttpResponse, Service_T);
static void print_service_rules_match(HttpResponse, Service_T);
static void print_service_rules_checksum(HttpResponse, Service_T);
static void print_service_rules_process(HttpResponse, Service_T);
static void print_service_rules_resource(HttpResponse, Service_T);
static void print_service_params_port(HttpResponse, Service_T);
static void print_service_params_icmp(HttpResponse, Service_T);
static void print_service_params_perm(HttpResponse, Service_T);
static void print_service_params_uid(HttpResponse, Service_T);
static void print_service_params_gid(HttpResponse, Service_T);
static void print_service_params_timestamp(HttpResponse, Service_T);
static void print_service_params_filesystem(HttpResponse, Service_T);
static void print_service_params_size(HttpResponse, Service_T);
static void print_service_params_match(HttpResponse, Service_T);
static void print_service_params_checksum(HttpResponse, Service_T);
static void print_service_params_process(HttpResponse, Service_T);
static void print_service_params_resource(HttpResponse, Service_T);
static void print_status(HttpRequest, HttpResponse);
static void status_service_txt(Service_T, HttpResponse, short);
static char *get_service_status_html(Service_T);
static char *get_service_status_text(Service_T);


/**
 *  Implementation of doGet and doPost routines used by the cervlet
 *  processor module. This particilary cervlet will provide
 *  information about the monit deamon and programs monitored by
 *  monit.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Martin Pala <martinp@tildeslash.com>
 *  @author Christian Hopp <chopp@iei.tu-clausthal.de>
 *
 *  @version \$Id: cervlet.c,v 1.260 2009/05/28 07:13:12 hauk Exp $
 *
 *  @file
 */


/* ------------------------------------------------------------------ Public */


/**
 * Callback hook to the Processor module for registering this modules
 * doGet and doPost methods.
 */
void init_service() {
  
  add_Impl(doGet, doPost);
  
}


/* ----------------------------------------------------------------- Private */


/**
 * Called by the Processor (via the service method)
 * to handle a POST request.
 */
static void doPost(HttpRequest req, HttpResponse res) {

  set_content_type(res, "text/html");

  if(ACTION(RUN)) {
    handle_run(req, res);
  } else if(ACTION(DOACTION)) {
    handle_do_action(req, res);
  } else {
    handle_action(req, res);
  }

}


/**
 * Called by the Processor (via the service method)
 * to handle a GET request.
 */
static void doGet(HttpRequest req, HttpResponse res) {

  set_content_type(res, "text/html");

  if(ACTION(HOME)) {
    LOCK(Run.mutex)
      do_home(req, res);
    END_LOCK;
  } else if(ACTION(RUN)) {
    handle_run(req, res);
  } else if(ACTION(TEST)) {
    is_monit_running(req, res);
  } else if(ACTION(VIEWLOG)) {
    do_viewlog(req, res);
  } else if(ACTION(ABOUT)) {
    do_about(req, res);
  } else if(ACTION(PING)) {
    do_ping(req, res);
  } else if(ACTION(GETID)) {
    do_getid(req, res);
  } else if(ACTION(PIXEL)) {
    printPixel(res);
  } else if(ACTION(STATUS)) {
    print_status(req, res);
  } else if(ACTION(DOACTION)) {
    handle_do_action(req, res);
  } else {
    handle_action(req, res);
  }
   
}


/* ----------------------------------------------------------------- Helpers */


static void is_monit_running(HttpRequest req, HttpResponse res) {

  int status;
  int monit= exist_daemon();

  if(monit) {
    status= SC_OK;
  } else {
    status= SC_GONE;
  }

  set_status(res, status);
  
}
    

static void do_home(HttpRequest req, HttpResponse res) {

  char *uptime= Util_getUptime(Util_getProcessUptime(Run.pidfile), "&nbsp;");
 
  HEAD("", Run.polltime)
  out_print(res,
    "<table cellspacing=\"0\" cellpadding=\"5\" width=\"100%%\" border=\"0\">"
    " <tr bgcolor=\"#BBDDFF\">"
    "  <td colspan=2 valign=\"top\" align=\"left\" bgcolor=\"#EFF7FF\" width=\"100%%\">"
    "  <br><h2 align=\"center\">Monit Service Manager</h2>"
    "  <p align=\"center\">Monit is <a href='_runtime'>running</a> on %s "
    "  with <i>uptime, %s</i> and monitoring:</p><br>"
    "  </td>"
    " </tr>"
    "</table>"
    "<table cellspacing=\"0\" cellpadding=\"0\" width=\"100%%\" border=\"0\">"
    "  <tr valign=\"middle\" bgcolor=\"#6F6F6F\">"
    "    <td><img src=\"_pixel\" width=\"1\" height=\"1\" alt=\"\"></td>"
    "  </tr>"
    "</table>", Run.localhostname, uptime);

  FREE(uptime);
  
  do_home_system(req, res);
  do_home_process(req, res);
  do_home_filesystem(req, res);
  do_home_file(req, res);
  do_home_fifo(req, res);
  do_home_directory(req, res);
  do_home_host(req, res);
  
  FOOT
      
}


static void do_about(HttpRequest req, HttpResponse res) {

  out_print(res,
    "<html><head><title>about monit</title></head><body bgcolor=white>"
    "<br><h1><center><a href='http://mmonit.com/monit/'>"
    "monit " VERSION "</a></center></h1>");
  out_print(res,
    "<ul>"
    "<li style='padding-bottom:10px;'>Copyright &copy; 2000-2009 by <a "
    "href=\"http://tildeslash.com/\">Tildeslash Ltd"
    "</a>. All Rights Reserved.</li>"
    "<li>Portions of this software are copyright &copy; 1995, 1996 "
    "<a href='http://www.gnu.org/'>Free Software Foundation, Inc.</a></li></ul>");
  out_print(res, "<hr size='1'>");
  out_print(res,
    "<p>This program is free software; you can redistribute it and/or "
    "modify it under the terms of the GNU General Public License version 3</p>"
    "<p>This program is distributed in the hope that it will be useful, but "
    "WITHOUT ANY WARRANTY; without even the implied warranty of "
    "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the "
    "<a href='http://www.gnu.org/licenses/gpl.html'>GNU "
    "General Public License</a> for more details.</p>"
    "<p style='border-top:1px solid #ccc; padding-top:1em;'>"
    "Running Monit on more than one server? Use <a href='http://mmonit.com/'>"
    "M/Monit</a> to manage all your Monit instances.</p>"
    "<p style='font-weight: bold;'>Please consider making a <a href=\"http://mmonit.com/monit/donate/\">"
    "donation</a> to support our work with Monit.</p>");
  out_print(res,
    "<center><p style='padding-top:20px;'>[Click <a href=\".\">here</a> to "
    "go back to Monit]</p></body></html>");

}


static void do_ping(HttpRequest req, HttpResponse res) {
  out_print(res, "pong");
}


static void do_getid(HttpRequest req, HttpResponse res) {
  out_print(res, "%s", Run.id);
}

static void do_runtime(HttpRequest req, HttpResponse res) {

  int pid=  exist_daemon();
  
  HEAD("_runtime", 1000)
  out_print(res,
	    "<center><h3>Monit runtime status</h3><center><br>");
  out_print(res,"<table cellspacing=0 cellpadding=3 border=1 width=\"90%%\" style=\"border:1px solid #ccc;border-collapse:collapse;\">"
	    "<tr><td width=\"40%%\" bgcolor=\"#edf5ff\"><b>Parameter</b></td>"
	    "<td width=\"60%%\" bgcolor=\"#edf5ff\"><b>Value</b></td></tr>");
  out_print(res, "<tr><td>Monit ID</td><td>%s</td></tr>", Run.id);
  out_print(res, "<tr><td>Host</td><td>%s</td></tr>",  Run.localhostname);
  out_print(res,
	    "<tr><td>Process id</td><td>%d</td></tr>", pid);
  out_print(res,
	    "<tr><td>Effective user running Monit</td>"
	    "<td>%s</td></tr>", Run.Env.user);
  out_print(res,
	    "<tr><td>Controlfile</td><td>%s</td></tr>", Run.controlfile);
  if(Run.logfile)
    out_print(res,
	    "<tr><td>Logfile</td><td>%s</td></tr>", Run.logfile);
  out_print(res,
	    "<tr><td>Pidfile</td><td>%s</td></tr>", Run.pidfile);
  out_print(res,
	    "<tr><td>State file</td><td>%s</td></tr>", Run.statefile);
  out_print(res,
	    "<tr><td>Debug</td><td>%s</td></tr>",
	    Run.debug?"True":"False");
  out_print(res,
	    "<tr><td>Log</td><td>%s</td></tr>", Run.dolog?"True":"False");
  out_print(res,
	    "<tr><td>Use syslog</td><td>%s</td></tr>",
	    Run.use_syslog?"True":"False");

  if(Run.eventlist_dir) {
    char slots[STRLEN];
    if(Run.eventlist_slots < 0)
      snprintf(slots, STRLEN, "unlimited");
    else
      snprintf(slots, STRLEN, "%d", Run.eventlist_slots);
    out_print(res,
              "<tr><td>Event queue</td>"
              "<td>base directory %s with %d slots</td></tr>",
              Run.eventlist_dir, Run.eventlist_slots);
  }

  if(Run.mmonits) {
    Mmonit_T c= Run.mmonits;
    out_print(res, "<tr><td>M/Monit server(s)</td><td>");
    for(c= Run.mmonits; c; c= c->next)
    {
      out_print(res,
        "%s with timeout %d seconds%s%s%s%s</td></tr>%s",
        c->url->url,
        c->timeout,
        c->ssl.use_ssl?" ssl version ":"",
        c->ssl.use_ssl?sslnames[c->ssl.version]:"",
        c->ssl.certmd5?" server cert md5 sum ":"",
        c->ssl.certmd5?c->ssl.certmd5:"",
        c->next?"<tr><td>&nbsp;</td><td>":"");
    }
    printf("\n");
  }

  if(Run.mailservers) {
    out_print(res, "<tr><td>Mail server(s)</td><td>");
    MailServer_T mta= Run.mailservers;
    for(mta= Run.mailservers; mta; mta= mta->next)
	out_print(res, "%s:%d%s&nbsp;",
          mta->host, mta->port, mta->ssl.use_ssl?"(ssl)":"");
    out_print(res, "</td></tr>");
  }
  
  if(Run.MailFormat.from)
    out_print(res,
	    "<tr><td>Default mail from</td><td>%s</td></tr>",
	    Run.MailFormat.from);
  if(Run.MailFormat.subject)
    out_print(res,
	    "<tr><td>Default mail subject</td><td>%s</td></tr>",
	    Run.MailFormat.subject);
  if(Run.MailFormat.message)
    out_print(res,
	    "<tr><td>Default mail message</td><td>%s</td></tr>",
            Run.MailFormat.message);

  out_print(res,
	    "<tr><td>Poll time</td><td>%d seconds with start delay %d seconds</td></tr>",
	    Run.polltime, Run.startdelay);
  out_print(res,
	    "<tr><td>httpd bind address</td><td>%s</td></tr>",
	    Run.bind_addr?Run.bind_addr:"Any/All");
  out_print(res,
	    "<tr><td>httpd portnumber</td><td>%d</td></tr>", Run.httpdport);
  out_print(res,
	    "<tr><td>httpd signature</td><td>%s</td></tr>",
	    Run.httpdsig?"True":"False");
  out_print(res,
	    "<tr><td>Use ssl encryption</td><td>%s</td></tr>",
	    Run.httpdssl?"True":"False");
  if (Run.httpdssl) {
    out_print(res,
	      "<tr><td>PEM key/certificate file</td><td>%s</td></tr>",
	      Run.httpsslpem);
    
    if (Run.httpsslclientpem!=NULL) {
      out_print(res,
		"<tr><td>Client PEM key/certification"
		"</td><td>%s</td></tr>", "Enabled");
      out_print(res,
		"<tr><td>Client PEM key/certificate file"
		"</td><td>%s</td></tr>", Run.httpsslclientpem);
    } else {
      out_print(res,
		"<tr><td>Client PEM key/certification"
		"</td><td>%s</td></tr>", "Disabled");
    }
    out_print(res,
	      "<tr><td>Allow self certified certificates "
	      "</td><td>%s</td></tr>", Run.allowselfcert?"True":"False");
  }
  
  out_print(res,
	    "<tr><td>httpd auth. style</td><td>%s</td></tr>",
	    (Run.credentials!=NULL)&&(has_hosts_allow())?
	    "Basic Authentication and Host/Net allow list":
	    (Run.credentials!=NULL)?"Basic Authentication":
	    (has_hosts_allow())?"Host/Net allow list":
	    "No authentication");

  print_alerts(res, Run.maillist);

  out_print(res,"</table>");

  if(!is_readonly(req)) {
    out_print(res,
      "<table cellspacing=16>"
      "<tr nowrap>");
    out_print(res,
      "<td>"
      "<font size=+1 color='#f0000'>Stop Monit http server?</font>"
      "</td>"
      "<td align=right>"
      "<form method=POST action=\"_runtime\">"
      "<input type=hidden name=\"action\" value=\"stop\">"
      "<input type=submit value=Go style='font-size: 12pt'>"
      "</form>"
      "</td>");

    out_print(res,
      "<td>"
      "<font size=+1>Force validate now?</font>"
      "</td>"
      "<td align=right>"
      "<form method=POST action=\"_runtime\">"
      "<input type=hidden name=\"action\" value=\"validate\">"
      "<input type=submit value=Go style='font-size: 12pt'>"
      "</form>"
      "</td>");

    if(Run.dolog && !Run.use_syslog) {
      out_print(res,
      "<td>"
      "<font size=+1>View Monit logfile?</font>"
      "</td>"
      "<td align=right>"
      "<form method=GET action=\"_viewlog\">"
      "<input type=submit value=Go style='font-size: 12pt'></font>"
      "</form>"
      "</td>");
    }
    out_print(res,
      "</tr>"
      "</table>");
  }
  
  FOOT

}


static void do_viewlog(HttpRequest req, HttpResponse res) {
  
  if(is_readonly(req)) {
    send_error(res, SC_FORBIDDEN,
	       "You do not have sufficent privilegs to access this page");
    return;
  }
  
  HEAD("_viewlog", 100)
      
  if(Run.dolog && !Run.use_syslog) {
    
    struct stat sb;
    
    if(!stat(Run.logfile, &sb)) {
      
      FILE *f= fopen(Run.logfile, "r");
      if(f) {
	
        #define BUFSIZE 8192

	int n;
	char buf[BUFSIZE+1];
	
	out_print(res, "<br><p><form><textarea cols=120 rows=30 readonly>");
	
	while((n= fread(buf, sizeof(char), BUFSIZE, f)) > 0) {
	  
	  buf[n]= 0;
	  out_print(res, "%s", buf);
	  
	}
	
        fclose(f);
	out_print(res, "</textarea></form>");
	
      } else {
	
	out_print(res, "Error opening logfile: %s", STRERROR);
	
      }
      
    } else {
      
      out_print(res, "Error stating logfile: %s", STRERROR);
      
    }
    
  } else {
    
    out_print(res,
    "<b>Cannot view logfile:</b><br>");
    if(!Run.dolog) {
      
      out_print(res, "Monit was started without logging");
      
    } else {
      
      out_print(res, "Monit uses syslog");
      
    }
    
  }
  
  FOOT
  
}


static void handle_action(HttpRequest req, HttpResponse res) {

  char *name= req->url;
  const char *action;
  Service_T s;
  
  if(!(s = Util_getService(++name))) {
    send_error(res, SC_NOT_FOUND, "There is no service by that name");
    return;
  }
  if((action = get_parameter(req, "action"))) {
    const char *token = NULL;

    if(is_readonly(req)) {
      send_error(res, SC_FORBIDDEN,
        "You do not have sufficent privilegs to access this page");
      return;
    }
    if((s->doaction = Util_getAction(action)) == ACTION_IGNORE) {
      send_error(res, SC_BAD_REQUEST, "Invalid action");
      return;
    }
    token = get_parameter(req, "token");
    s->token = token?xstrdup(token):NULL;
    LogDebug("%s service '%s' on user request\n", action, s->name);
    Run.doaction = TRUE; /* set the global flag */
    do_wakeupcall();
  }
  do_service(req, res, s);

}


static void handle_do_action(HttpRequest req, HttpResponse res) {

  Service_T s;
  int doaction = ACTION_IGNORE;
  const char *action = get_parameter(req, "action");

  if(action) {
    HttpParameter p;
    char *token = NULL;

    if(is_readonly(req)) {
      send_error(res, SC_FORBIDDEN, "You do not have sufficent privilegs to access this page");
      return;
    }
    if((doaction = Util_getAction(action)) == ACTION_IGNORE) {
      send_error(res, SC_BAD_REQUEST, "Invalid action");
      return;
    }

    token = (char*)get_parameter(req, "token");

    for(p= req->params; p; p= p->next) {

      if(!strcasecmp(p->name, "service")) {
        s  = Util_getService(p->value);

        if(!s) {
          send_error(res, SC_BAD_REQUEST, "There is no service by that name");
          return;
        }

        s->doaction = doaction;
        s->token = token;

        LogDebug("%s service '%s' on user request\n", action, s->name);
      }
    }

    if (token) {
      Service_T q = NULL;
      /* Make sure only the last service gets the service token */
      for (s = servicelist; s; s= s->next) {
        if (s->token) {
          s->token = NULL;
          q = s;
        }
      }
      if (q)
        q->token = xstrdup(token);
    }

    Run.doaction = TRUE; 
    do_wakeupcall();
  }

}


static void handle_run(HttpRequest req, HttpResponse res) {
         
  const char *action= get_parameter(req, "action");
         
  if(action) {
    if(is_readonly(req)) {
      send_error(res, SC_FORBIDDEN,
        "You do not have sufficent privilegs to access this page");
      return;
    }
    if(IS(action, "validate")) {
      LogInfo("The Monit http server woke up on user request\n");
      do_wakeupcall();
    } else if(IS(action, "stop")) {
      LogInfo("The Monit http server stopped on user request\n");
      send_error(res, SC_SERVICE_UNAVAILABLE,
        "The Monit http server is stopped");
      stop_httpd();
      return;
    }
  }
         
  LOCK(Run.mutex)
    do_runtime(req, res);
  END_LOCK;
         
}


static void do_service(HttpRequest req, HttpResponse res, Service_T s) {

  Dependant_T d;
  char *status;
  char time[STRLEN];

  ASSERT(s);

  LOCK(s->mutex)

    HEAD(s->name, Run.polltime)

    out_print(res,
      "<p><br><h3>%s status</h3><br>"
      "<table cellspacing=0 cellpadding=3 border=1 width=\"90%%\" style=\"border:1px solid #ccc;border-collapse:collapse;\">"
      "<tr>"
      "<td width=\"30%%\" bgcolor=\"#edf5ff\"><b>Parameter</b></td>"
      "<td width=\"70%%\" bgcolor=\"#edf5ff\"><b>Value</b></td>"
      "</tr>"
      "<tr>"
      "<td>Name</td>"
      "<td>%s</td>"
      "</tr>",
      servicetypes[s->type],
      s->name);

    if(s->path && *s->path)
      out_print(res,
        "<tr>"
        "<td>%s</td>"
        "<td>%s</td>"
        "</tr>",
        pathnames[s->type],
        s->path);

    status= get_service_status_html(s);
    out_print(res,
      "<tr><td>Status</td><td>%s</td></tr>", status);
    FREE(status);

    if(s->group)
      out_print(res,
        "<tr><td>Group</td><td><font color='#0000ff'>%s</font></td></tr>",
        s->group);

    out_print(res,
      "<tr><td>Monitoring mode</td><td>%s</td></tr>", modenames[s->mode]);

    out_print(res,
      "<tr><td>Monitoring status</td><td><font color='#ff8800'>%s"
      "</font></td></tr>",
      monitornames[s->monitor]);

    for(d= s->dependantlist; d; d= d->next) {
      if(d->dependant != NULL) {
        out_print(res,
          "<tr><td>Depends on service </td><td> <a href=%s> %s </a></td></tr>",
          d->dependant, d->dependant);
      }
    }

    if(s->start) {
      int i= 0;
      out_print(res, "<tr><td>Start program</td><td>'");
      while(s->start->arg[i]) {
        if(i) out_print(res, " ");
        out_print(res, "%s", s->start->arg[i++]);
      }
      out_print(res, "'");
      if(s->start->has_uid)
        out_print(res, " as uid %d", s->start->uid);
      if(s->start->has_gid)
        out_print(res, " as gid %d", s->start->gid);
      out_print(res, " timeout %d second(s)", s->start->timeout);
      out_print(res, "</td></tr>");
    }

    if(s->stop) {
      int i= 0;
      out_print(res, "<tr><td>Stop program</td><td>'");
      while(s->stop->arg[i]) {
        if(i) out_print(res, " ");
        out_print(res, "%s", s->stop->arg[i++]);
      }
      out_print(res, "'");
      if(s->stop->has_uid)
        out_print(res, " as uid %d", s->stop->uid);
      if(s->stop->has_gid)
        out_print(res, " as gid %d", s->stop->gid);
      out_print(res, " timeout %d second(s)", s->stop->timeout);
      out_print(res, "</td></tr>");
    }

    out_print(res,
      "<tr><td>Check service</td><td>every %d cycle</td></tr>",
      s->every?s->every:1);

    if(s->def_timeout && s->action_TIMEOUT) {
      EventAction_T a= s->action_TIMEOUT;
      out_print(res,
        "<tr><td>Timeout</td>"
        "<td>If %d restart within %d cycles then %s else if succeeded "
        "then %s</td></tr>",
         s->to_start,
         s->to_cycle,
         a->failed->description,
         a->succeeded->description);
    }

    ctime_r((const time_t *)&s->collected.tv_sec, time);
    out_print(res,
      "<tr><td>Data collected</td><td>%s</td></tr>",
      time);

    /* Parameters */
    print_service_params_icmp(res, s);
    print_service_params_port(res, s);
    print_service_params_perm(res, s);
    print_service_params_uid(res, s);
    print_service_params_gid(res, s);
    print_service_params_timestamp(res, s);
    print_service_params_filesystem(res, s);
    print_service_params_size(res, s);
    print_service_params_match(res, s);
    print_service_params_checksum(res, s);
    print_service_params_process(res, s);
    print_service_params_resource(res, s);

    /* Rules */
    print_service_rules_icmp(res, s);
    print_service_rules_port(res, s);
    print_service_rules_perm(res, s);
    print_service_rules_uid(res, s);
    print_service_rules_gid(res, s);
    print_service_rules_timestamp(res, s);
    print_service_rules_filesystem(res, s);
    print_service_rules_size(res, s);
    print_service_rules_match(res, s);
    print_service_rules_checksum(res, s);
    print_service_rules_process(res, s);
    print_service_rules_resource(res, s);

    print_alerts(res, s->maillist);

    out_print(res, "</table>");

    print_buttons(req, res, s);

    FOOT

  END_LOCK;

}


static void printPixel(HttpResponse res) {

  static int l;
  Socket_T S= res->S;
  static unsigned char *pixel= NULL;
  
  if(! pixel) {
    pixel= xcalloc(sizeof(unsigned char), strlen(PIXEL_GIF));
    l= decode_base64(pixel, PIXEL_GIF);
  }
  if (l) {
    res->is_committed= TRUE;
    socket_print(S, "HTTP/1.0 200 OK\r\n");
    socket_print(S, "Content-length: %d\r\n", l);
    socket_print(S, "Content-Type: image/gif\r\n");
    socket_print(S, "Connection: close\r\n\r\n");
    socket_write(S, pixel, l);
  }
  
}


static void do_home_system(HttpRequest req, HttpResponse res) {
  
  char      *status;
  Service_T  s = Run.system;

  status= get_service_status_html(s);

  out_print(res,
    "<br><p>&nbsp;</p>"
    "<table cellspacing=0 cellpadding=3 border=0 width=\"90%%\">"
    "<tr>"
    "<td width=\"20%%\"><h3><b>System</b></h3></td>"
    "<td align=\"left\"><h3><b>Status</b></h3></td>");

  if(Run.doprocess) {
    out_print(res,
      "<td align=\"right\"><h3><b>Load</b></h3></td>"
      "<td align=\"right\"><h3><b>CPU</b></h3></td>"
      "<td align=\"right\"><h3><b>Memory</b></h3></td>");
  }

  out_print(res,
    "</tr>"
    "<tr bgcolor=\"#EFEFEF\">"
    "<td align=\"left\"><a href='%s'>%s</a></td>"
    "<td align=\"left\">%s</td>",
    s->name, s->name,
    status);
  FREE(status);

  if(Run.doprocess) {
    out_print(res,
      "<td align=\"right\" width=\"20%%\">[%.2f]&nbsp;[%.2f]&nbsp;[%.2f]</td>"
      "<td align=\"right\" width=\"20%%\">"
      "%.1f%%us,&nbsp;%.1f%%sy"
    #ifdef HAVE_CPU_WAIT
      ",&nbsp;%.1f%%wa"
    #endif
      "</td>"
      "<td align=\"right\" width=\"20%%\">%.1f%% [%ld&nbsp;kB]</td>",
      systeminfo.loadavg[0], systeminfo.loadavg[1], systeminfo.loadavg[2],
      systeminfo.total_cpu_user_percent/10., systeminfo.total_cpu_syst_percent/10.,
    #ifdef HAVE_CPU_WAIT
      systeminfo.total_cpu_wait_percent/10.,
    #endif
      systeminfo.total_mem_percent/10., systeminfo.total_mem_kbyte);
  }

  out_print(res,
    "</tr>"
    "</table>");
}


static void do_home_process(HttpRequest req, HttpResponse res) {

  Service_T      s;
  char          *status;
  int            on= TRUE;
  int            header= TRUE;

  for(s= servicelist_conf; s; s= s->next_conf) {
    
    if(s->type != TYPE_PROCESS) continue;
    
    if(header) {
      
      out_print(res,
        "<br><p>&nbsp;</p>"
        "<table cellspacing=0 cellpadding=3 border=0 width=\"90%%\">"
        "<tr>"
        "<td width=\"20%%\"><h3><b>Process</b></h3></td>"
        "<td align=\"left\"><h3><b>Status</b></h3></td>"
        "<td align=\"right\"><h3><b>Uptime</b></h3></td>");

      if(Run.doprocess) {
        out_print(res,
          "<td align=\"right\"><h3><b>CPU</b></h3></td>"
          "<td align=\"right\"><h3><b>Memory</b></h3></td>");
      }

      out_print(res, "</tr>");


      header= FALSE;

    }

    status= get_service_status_html(s);
    out_print(res,
      "<tr %s>"
      "<td width=\"20%%\"><a href='%s'>%s</a></td>"
      "<td align=\"left\">%s</td>",
      on?"bgcolor=\"#EFEFEF\"":"",
      s->name, s->name,
      status);
    FREE(status);

    if(!Util_hasServiceStatus(s)) {

      out_print(res,
        "<td align=\"right\">-</td>");

      if(Run.doprocess) {
        out_print(res,
        "<td align=\"right\">-</td>"
        "<td align=\"right\">-</td>");
      }

    } else {

      char *uptime= Util_getUptime(s->inf->uptime, "&nbsp;");
      out_print(res,
        "<td align=\"right\">%s</td>", uptime);
      FREE(uptime);

      if(Run.doprocess) {
        out_print(res,
	  "<td align=\"right\"><font%s>%.1f%%</font></td>",
          (s->error & EVENT_RESOURCE)?" color='#ff0000'":"",
	  s->inf->cpu_percent/10.0);
        out_print(res,
	  "<td align=\"right\"><font%s>%.1f%% [%ld&nbsp;kB]</font></td></tr>",
          (s->error & EVENT_RESOURCE)?" color='#ff0000'":"",
	  s->inf->mem_percent/10.0, s->inf->mem_kbyte);
      }

    }

    out_print(res, "</tr>");

    on= on?FALSE:TRUE;
    
  }
  
  if(!header)
    out_print(res, "</table>");
  
}


static void do_home_filesystem(HttpRequest req, HttpResponse res) {
  
  Service_T     s;
  char         *status;
  int           on= TRUE;
  int           header= TRUE;
  
  for(s= servicelist_conf; s; s= s->next_conf) {

    if(s->type != TYPE_FILESYSTEM) continue;
    
    if(header) {
      
      out_print(res,
	"<br><p>&nbsp;</p>"
	"<table cellspacing=0 cellpadding=3 border=0 width=\"90%%\">"
	"<tr>"
	"<td width=\"20%%\"><h3><b>Filesystem</b></h3></td>"
	"<td align=\"left\"><h3><b>Status</b></h3></td>"
	"<td align=\"right\"><h3><b>Space usage</b></h3></td>"
	"<td align=\"right\"><h3><b>Inodes usage</b></h3></td>"
	"</tr>");
      
      header= FALSE;
      
    }

    status= get_service_status_html(s);
    out_print(res,
      "<tr %s>"
      "<td width=\"20%%\"><a href='%s'>%s</a></td>"
      "<td align=\"left\">%s</td>",
      on?"bgcolor=\"#EFEFEF\"":"",
      s->name, s->name,
      status);
    FREE(status);

    if(!Util_hasServiceStatus(s)) {

      out_print(res,
	"<td align=\"right\">- [-]</td>"
	"<td align=\"right\">- [-]</td>");

    } else {
      
      out_print(res,
	"<td align=\"right\">%.1f%% [%.1f&nbsp;MB]</td>",
        s->inf->space_percent/10.,
	(float)s->inf->space_total / (float)1048576 * (float)s->inf->f_bsize);

      if(s->inf->f_files > 0) {

        out_print(res,
	  "<td align=\"right\">%.1f%% [%ld&nbsp;objects]</td>",
          s->inf->inode_percent/10.,
	  s->inf->inode_total);

      } else {

        out_print(res,
	  "<td align=\"right\">not supported by filesystem</td>");

      }

    }

    out_print(res, "</tr>");

    on= on?FALSE:TRUE;

  }
  
  if(!header)
    out_print(res, "</table>");
  
}


static void do_home_file(HttpRequest req, HttpResponse res) {
  
  Service_T  s;
  char      *status;
  int        on= TRUE;
  int        header= TRUE;
  
  for(s= servicelist_conf; s; s= s->next_conf) {
    
    if(s->type != TYPE_FILE) continue;
    
    if(header) {
      
      out_print(res,
	"<br><p>&nbsp;</p>"
	"<table cellspacing=0 cellpadding=3 border=0 width=\"90%%\">"
	"<tr>"
	"<td width=\"20%%\"><h3><b>File</b></h3></td>"
	"<td align=\"left\"><h3><b>Status</b></h3></td>"
	"<td align=\"right\"><h3><b>Size</b></h3></td>"
	"<td align=\"right\"><h3><b>Permission</b></h3></td>"
	"<td align=\"right\"><h3><b>UID</b></h3></td>"
	"<td align=\"right\"><h3><b>GID</b></h3></td>"
	"</tr>");
      
      header= FALSE;
      
    }

    status= get_service_status_html(s);
    out_print(res,
      "<tr %s>"
      "<td width=\"20%%\"><a href='%s'>%s</a></td>"
      "<td align=\"left\">%s</td>",
      on?"bgcolor=\"#EFEFEF\"":"",
      s->name, s->name,
      status);
    FREE(status);
    
    if(!Util_hasServiceStatus(s)) {
      
      out_print(res,
	"<td align=\"right\">-</td>"
	"<td align=\"right\">-</td>"
	"<td align=\"right\">-</td>"
	"<td align=\"right\">-</td>");

    } else {
      
      out_print(res,
	"<td align=\"right\">%llu&nbsp;B</td>"
	"<td align=\"right\">%04o</td>"
	"<td align=\"right\">%d</td>"
	"<td align=\"right\">%d</td>",
	(unsigned long long)s->inf->st_size,
	s->inf->st_mode & 07777,
	s->inf->st_uid,
	s->inf->st_gid);

    }
    
    out_print(res, "</tr>");

    on= on?FALSE:TRUE;
    
  }
  
  if(!header)
    out_print(res, "</table>");
  
}


static void do_home_fifo(HttpRequest req, HttpResponse res) {
  
  Service_T  s;
  char      *status;
  int        on= TRUE;
  int        header= TRUE;
  
  for(s= servicelist_conf; s; s= s->next_conf) {
    
    if(s->type != TYPE_FIFO) continue;
    
    if(header) {
      
      out_print(res,
	"<br><p>&nbsp;</p>"
	"<table cellspacing=0 cellpadding=3 border=0 width=\"90%%\">"
	"<tr>"
	"<td width=\"20%%\"><h3><b>Fifo</b></h3></td>"
	"<td align=\"left\"><h3><b>Status</b></h3></td>"
	"<td align=\"right\"><h3><b>Permission</b></h3></td>"
	"<td align=\"right\"><h3><b>UID</b></h3></td>"
	"<td align=\"right\"><h3><b>GID</b></h3></td>"
	"</tr>");
      
      header= FALSE;
      
    }

    status= get_service_status_html(s);
    out_print(res,
      "<tr %s>"
      "<td width=\"20%%\"><a href='%s'>%s</a></td>"
      "<td align=\"left\">%s</td>",
      on?"bgcolor=\"#EFEFEF\"":"",
      s->name, s->name,
      status);
    FREE(status);
    
    if(!Util_hasServiceStatus(s)) {
      
      out_print(res,
	"<td align=\"right\">-</td>"
	"<td align=\"right\">-</td>"
	"<td align=\"right\">-</td>");

    } else {
      
      out_print(res,
	"<td align=\"right\">%o</td>"
	"<td align=\"right\">%d</td>"
	"<td align=\"right\">%d</td>",
	s->inf->st_mode & 07777,
	s->inf->st_uid,
	s->inf->st_gid);

    }
    
    out_print(res, "</tr>");

    on= on?FALSE:TRUE;
    
  }
  
  if(!header)
    out_print(res, "</table>");
  
}


static void do_home_directory(HttpRequest req, HttpResponse res) {
  
  Service_T        s;
  char            *status;
  int              on= TRUE;
  int              header= TRUE;
  
  for(s= servicelist_conf; s; s= s->next_conf) {
    
    if(s->type != TYPE_DIRECTORY) continue;

    if(header) {

      out_print(res,
	"<br><p>&nbsp;</p>"
	"<table cellspacing=0 cellpadding=3 border=0 width=\"90%%\">"
	"<tr>"
	"<td width=\"20%%\"><h3><b>Directory</b></h3></td>"
	"<td align=\"left\"><h3><b>Status</b></h3></td>"
	"<td align=\"right\"><h3><b>Permission</b></h3></td>"
	"<td align=\"right\"><h3><b>UID</b></h3></td>"
	"<td align=\"right\"><h3><b>GID</b></h3></td>"
	"</tr>");
      
      header= FALSE;
      
    }

    status= get_service_status_html(s);
    out_print(res,
      "<tr %s>"
      "<td width=\"20%%\"><a href='%s'>%s</a></td>"
      "<td align=\"left\">%s</td>",
      on?"bgcolor=\"#EFEFEF\"":"",
      s->name, s->name,
      status);
    FREE(status);
    
    if(!Util_hasServiceStatus(s)) {
      
      out_print(res,
	"<td align=\"right\">-</td>"
	"<td align=\"right\">-</td>"
	"<td align=\"right\">-</td>");
      
    } else {
      
      out_print(res,
	"<td align=\"right\">%o</td>"
	"<td align=\"right\">%d</td>"
	"<td align=\"right\">%d</td>",
	s->inf->st_mode & 07777,
	s->inf->st_uid,
	s->inf->st_gid);
      
    }
    
    out_print(res, "</tr>");

    on= on?FALSE:TRUE;
    
  }
  
  if(!header)
    out_print(res, "</table>");
  
}


static void do_home_host(HttpRequest req, HttpResponse res) {

  Service_T  s;
  Icmp_T     icmp;
  Port_T     port;
  char      *status;
  int        on= TRUE;
  int        header= TRUE;
  
  for(s= servicelist_conf; s; s= s->next_conf) {

    if(s->type != TYPE_HOST) continue;

    if(header) {
      
      out_print(res,
	"<br><p>&nbsp;</p>"
	"<table cellspacing=0 cellpadding=3 border=0 width=\"90%%\">"
	"<tr>"
	"<td width=\"20%%\"><h3><b>Host</b></h3></td>"
	"<td align=\"left\"><h3><b>Status</b></h3></td>"
	"<td align=\"right\"><h3><b>Protocol(s)</b></h3></td>"
	"</tr>");
      
      header= FALSE;
      
    }
    
    status= get_service_status_html(s);
    out_print(res,
      "<tr %s>"
      "<td width=\"20%%\"><a href='%s'>%s</a></td>"
      "<td align=\"left\">%s</td>",
      on?"bgcolor=\"#EFEFEF\"":"",
      s->name, s->name,
      status);
    FREE(status);

    if(!Util_hasServiceStatus(s)) {

      out_print(res,
        "<td align=\"right\">-</td>");

    } else {

      out_print(res,
        "<td align=\"right\">");

      if(s->icmplist) {
        for(icmp= s->icmplist; icmp; icmp= icmp->next) {
	  if(icmp != s->icmplist)
	    out_print(res, "&nbsp;&nbsp;<b>|</b>&nbsp;&nbsp;");
	  out_print(res, "<font%s>[ICMP %s]</font>",
            (icmp->is_available)?"":" color='#ff0000'",
            icmpnames[icmp->type]);
        }
      }

      if(s->icmplist && s->portlist)
        out_print(res, "&nbsp;&nbsp;<b>|</b>&nbsp;&nbsp;");
      
      if(s->portlist) {
        for(port= s->portlist; port; port= port->next) {
	  if(port != s->portlist)
	    out_print(res, "&nbsp;&nbsp;<b>|</b>&nbsp;&nbsp;");
	  out_print(res, "<font%s>[%s] at port %d</font>",
            (port->is_available)?"":" color='#ff0000'",
            port->protocol->name, port->port);
        }
      }

      out_print(res, "</td>");

    }
    
    out_print(res, "</tr>");

    on= on?FALSE:TRUE;
    
  }
  
  if(!header)
    out_print(res, "</table>");

}


/* ------------------------------------------------------------------------- */


static void print_alerts(HttpResponse res, Mail_T s) {

  Mail_T r;
  
  for(r= s; r; r= r->next) {
    out_print(res,
	      "<tr bgcolor=\"#EFEFEF\"><td>Alert mail to</td>"
	      "<td>%s</td></tr>", r->to?r->to:"");
    out_print(res, "<tr><td>Alert on</td><td>");

    if(r->events == EVENT_NULL) {
      out_print(res, "No events");
    } else if(r->events == EVENT_ALL) {
      out_print(res, "All events");
    } else {
      if(IS_EVENT_SET(r->events, EVENT_ACTION))
	  out_print(res, "Action ");
      if(IS_EVENT_SET(r->events, EVENT_CHECKSUM))
	  out_print(res, "Checksum ");
      if(IS_EVENT_SET(r->events, EVENT_CONNECTION))
	  out_print(res, "Connection ");
      if(IS_EVENT_SET(r->events, EVENT_CONTENT))
	  out_print(res, "Content ");
      if(IS_EVENT_SET(r->events, EVENT_DATA))
	  out_print(res, "Data ");
      if(IS_EVENT_SET(r->events, EVENT_EXEC))
	  out_print(res, "Exec ");
      if(IS_EVENT_SET(r->events, EVENT_FSFLAG))
	  out_print(res, "Fsflags ");
      if(IS_EVENT_SET(r->events, EVENT_GID))
	  out_print(res, "Gid ");
      if(IS_EVENT_SET(r->events, EVENT_ICMP))
	  out_print(res, "Icmp ");
      if(IS_EVENT_SET(r->events, EVENT_INSTANCE))
          out_print(res, "Instance ");
      if(IS_EVENT_SET(r->events, EVENT_INVALID))
	  out_print(res, "Invalid ");
      if(IS_EVENT_SET(r->events, EVENT_NONEXIST))
	  out_print(res, "Nonexist ");
      if(IS_EVENT_SET(r->events, EVENT_PERMISSION))
	  out_print(res, "Permission ");
      if(IS_EVENT_SET(r->events, EVENT_PID))
	  out_print(res, "PID ");
      if(IS_EVENT_SET(r->events, EVENT_PPID))
	  out_print(res, "PPID ");
      if(IS_EVENT_SET(r->events, EVENT_RESOURCE))
	  out_print(res, "Resource ");
      if(IS_EVENT_SET(r->events, EVENT_SIZE))
	  out_print(res, "Size ");
      if(IS_EVENT_SET(r->events, EVENT_TIMEOUT))
	  out_print(res, "Timeout ");
      if(IS_EVENT_SET(r->events, EVENT_TIMESTAMP))
	  out_print(res, "Timestamp ");
      if(IS_EVENT_SET(r->events, EVENT_UID))
	  out_print(res, "Uid ");
    }
      
    out_print(res, "</td></tr>");

    if(r->reminder) {
       out_print(res,
         "<tr><td>Alert reminder</td><td>%u cycles</td></tr>",
         r->reminder);
    }

  }

}


static void print_buttons(HttpRequest req, HttpResponse res, Service_T s) {

  if(is_readonly(req)) {
    /*
     * A read-only REMOTE_USER does not get access to these buttons
     */
    return;
  }
  
  out_print(res, "<table cellspacing=16><tr nowrap><td><font size=+1>");
  /* Start program */
  if(s->start)
      out_print(res, 
		"<td><form method=POST action=%s>"
		"<input type=hidden value='start' name=action>"
		"<input type=submit value='Start service' style='font-size: "
		"12pt'></form></td>", s->name);
  /* Stop program */
  if(s->stop)
      out_print(res, 
		"<td><form method=POST action=%s>"
		"<input type=hidden value='stop' name=action>"
		"<input type=submit value='Stop service' style='font-size: "
		"12pt'></form></td>", s->name);
  /* Restart program */
  if(s->start && s->stop)
      out_print(res, 
		"<td><form method=POST action=%s>"
		"<input type=hidden value='restart' name=action>"
		"<input type=submit value='Restart service' style='font-size: "
		"12pt'></form></td>", s->name);
  /* (un)monitor */
  out_print(res, 
	    "<td><form method=POST action=%s>"
	    "<input type=hidden value='%s' name=action>"
	    "<input type=submit value='%s' style='font-size: 12pt'>"
	    "</form></td></tr></table>",
	    s->name,
            s->monitor?"unmonitor":"monitor",
            s->monitor?"Disable monitoring":"Enable monitoring");

}


static void print_service_rules_port(HttpResponse res, Service_T s) {

  if(s->portlist) {

    char          ratio1[STRLEN];
    char          ratio2[STRLEN];
    Port_T        p;
    EventAction_T a;

    for(p= s->portlist; p; p= p->next) {
      a= p->action;

      Util_getEventratio(a->failed, ratio1);
      Util_getEventratio(a->succeeded, ratio2);

      if(p->family == AF_INET) {
        out_print(res,
          "<tr><td>Port</td><td>"
          "If failed %s:%d%s [%s via %s] with timeout %d seconds %s then %s "
          "else if succeeded %s then %s</td></tr>",
          p->hostname, p->port, p->request?p->request:"",
          p->protocol->name, Util_portTypeDescription(p),
          p->timeout,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
        if(p->SSL.certmd5 != NULL)
          out_print(res,
            "<tr><td>Server certificate md5 sum</td><td>%s</td></tr>",
            p->SSL.certmd5);
      } else if(p->family == AF_UNIX) {
        out_print(res,
          "<tr><td>Unix Socket</td><td>"
          "If failed %s [%s] with timeout %ds %s then %s else if succeeded %s then %s"
          "</td></tr>",
          p->pathname, p->protocol->name, p->timeout,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
      }
    }
  }
}


static void print_service_rules_icmp(HttpResponse res, Service_T s) {

  if(s->icmplist) {

    char          ratio1[STRLEN];
    char          ratio2[STRLEN];
    Icmp_T        i;
    EventAction_T a;

    for(i= s->icmplist; i; i= i->next) {
      a= i->action;
      
      Util_getEventratio(a->failed, ratio1);
      Util_getEventratio(a->succeeded, ratio2);

      out_print(res,
        "<tr><td>ICMP</td><td>"
        "If failed %s count %d with timeout %d seconds %s then %s else if succeeded %s then %s"
        "</td></tr>",
        icmpnames[i->type], i->count, i->timeout,
        ratio1, a->failed->description,
        ratio2, a->succeeded->description);
    }
  }
}


static void print_service_rules_perm(HttpResponse res, Service_T s) {

  if(s->perm) {

    char          ratio1[STRLEN];
    char          ratio2[STRLEN];
    EventAction_T a= s->perm->action;

    Util_getEventratio(a->failed, ratio1);
    Util_getEventratio(a->succeeded, ratio2);

    out_print(res, "<tr><td>Associated permission</td>"
      "<td>If failed %o %s then %s else if succeeded %s then %s</td></tr>",
      s->perm->perm,
      ratio1, a->failed->description,
      ratio2, a->succeeded->description);

  }
}


static void print_service_rules_uid(HttpResponse res, Service_T s) {

  if(s->uid) {

    char          ratio1[STRLEN];
    char          ratio2[STRLEN];
    EventAction_T a= s->uid->action;

    Util_getEventratio(a->failed, ratio1);
    Util_getEventratio(a->succeeded, ratio2);

    out_print(res, "<tr><td>Associated UID</td>"
      "<td>If failed %d %s then %s else if succeeded %s then %s</td></tr>",
      (int)s->uid->uid,
      ratio1, a->failed->description,
      ratio2, a->succeeded->description);
  }
}


static void print_service_rules_gid(HttpResponse res, Service_T s) {

  if(s->gid) {

    char          ratio1[STRLEN];
    char          ratio2[STRLEN];
    EventAction_T a= s->gid->action;

    Util_getEventratio(a->failed, ratio1);
    Util_getEventratio(a->succeeded, ratio2);

    out_print(res, "<tr><td>Associated GID</td>"
      "<td>If failed %d %s then %s else if succeeded %s then %s</td></tr>",
      (int)s->gid->gid,
      ratio1, a->failed->description,
      ratio2, a->succeeded->description);
  }
}


static void print_service_rules_timestamp(HttpResponse res, Service_T s) {

  if(s->timestamplist) {

    char          ratio1[STRLEN];
    char          ratio2[STRLEN];
    Timestamp_T   t;
    EventAction_T a;

    for(t= s->timestamplist; t; t= t->next) {

      a= t->action;

      Util_getEventratio(a->failed, ratio1);
      Util_getEventratio(a->succeeded, ratio2);

      if(t->test_changes) {

        out_print(res,
          "<tr><td>Associated timestamp</td><td>If changed %s then %s</td></tr>",
          ratio1, a->failed->description);

      } else {

        out_print(res,
          "<tr><td>Associated timestamp</td>"
          "<td>If %s %d second(s) %s then %s else if succeeded %s then %s</td></tr>",
          operatornames[t->operator], t->time,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
      }
    }
  }
}


static void print_service_rules_filesystem(HttpResponse res, Service_T s) {

  if(s->type == TYPE_FILESYSTEM) {

    char ratio1[STRLEN];

    out_print(res, "<tr><td>Filesystem flags</td><td>If changed %s then %s</td></tr>\n",
      Util_getEventratio(s->action_FSFLAG->failed, ratio1),
      s->action_FSFLAG->failed->description);
  }

  if(s->filesystemlist) {
      
    char          ratio1[STRLEN];
    char          ratio2[STRLEN];
    Filesystem_T  dl;
    EventAction_T a;

    for(dl= s->filesystemlist; dl; dl= dl->next) {

      a= dl->action;

      Util_getEventratio(a->failed, ratio1);
      Util_getEventratio(a->succeeded, ratio2);

      if(dl->resource == RESOURCE_ID_INODE) {
	  
        if(dl->limit_absolute > -1) {
          out_print(res,
	    "<tr><td>Inodes usage limit</td><td>If %s %ld %s "
	    "then %s else if succeeded %s then %s</td></tr>",
	    operatornames[dl->operator],
	    dl->limit_absolute,
            ratio1, a->failed->description,
            ratio2, a->succeeded->description);
        } else {
          out_print(res,
	    "<tr><td>Inodes usage limit</td><td>If %s %.1f%% %s "
	    "then %s else if succeeded %s then %s</td></tr>",
	    operatornames[dl->operator],
	    dl->limit_percent/10.,
            ratio1, a->failed->description,
            ratio2, a->succeeded->description);
        }
	  
      } else if(dl->resource == RESOURCE_ID_SPACE) {
	  
        if(dl->limit_absolute > -1) {
          out_print(res,
	    "<tr><td>Space usage limit</td><td>If %s %ld blocks %s "
	    "then %s else if succeeded %s then %s</td></tr>",
            operatornames[dl->operator],
	    dl->limit_absolute,
            ratio1, a->failed->description,
            ratio2, a->succeeded->description);
        } else {
          out_print(res,
	    "<tr><td>Space usage limit</td><td>If %s %.1f%% %s "
	    "then %s else if succeeded %s then %s</td></tr>",
            operatornames[dl->operator],
	    dl->limit_percent/10.,
            ratio1, a->failed->description,
            ratio2, a->succeeded->description);
        }
      }
    }
  }
}
      

static void print_service_rules_size(HttpResponse res, Service_T s) {

  if(s->sizelist) {

    char          ratio1[STRLEN];
    char          ratio2[STRLEN];
    Size_T        sl;
    EventAction_T a;

    for(sl= s->sizelist; sl; sl= sl->next) {

      a= sl->action;

      Util_getEventratio(a->failed, ratio1);
      Util_getEventratio(a->succeeded, ratio2);

      if(sl->test_changes) {

        out_print(res,
          "<tr><td>Associated size</td><td>If changed %s then %s</td></tr>",
          ratio1, a->failed->description);

      } else {

        out_print(res,
          "<tr><td>Associated size</td>"
          "<td>If %s %llu byte(s) %s then %s else if succeeded %s then %s</td></tr>",
          operatornames[sl->operator], sl->size,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);

      }
    }
  }
}

static void print_service_rules_match(HttpResponse res, Service_T s) {

  if(s->matchlist) {

    char          ratio1[STRLEN];
    Match_T       ml;
    EventAction_T a;

    for(ml= s->matchlist; ml; ml= ml->next) {

      a= ml->action;

      Util_getEventratio(a->failed, ratio1);

      out_print(res,
                "<tr><td>Associated regex</td><td>If %s match "
                "\"%s\" %s then %s</td></tr>",
                ml->not?"not ":"", ml->match_string,
                ratio1, a->failed->description);
      
    }
  }
}


static void print_service_rules_checksum(HttpResponse res, Service_T s) {

  if(s->checksum) {

    char          ratio1[STRLEN];
    char          ratio2[STRLEN];
    Checksum_T     cs= s->checksum;
    EventAction_T  a= cs->action;

    Util_getEventratio(a->failed, ratio1);
    Util_getEventratio(a->succeeded, ratio2);

    if(cs->test_changes) {

      out_print(res,
        "<tr><td>Associated checksum</td><td>if changed %s %s then %s</td></tr>",
        checksumnames[cs->type],
        ratio1, a->failed->description);

    } else {

      out_print(res, "<tr><td>Associated checksum</td><td>"
        "if failed %s(%s) %s then %s else if succeeded %s then %s</td></tr>",
        cs->hash, checksumnames[cs->type],
        ratio1, a->failed->description,
        ratio2, a->succeeded->description);

    }
  }
}
  

static void print_service_rules_process(HttpResponse res, Service_T s) {

  if(s->type == TYPE_PROCESS) {

    char ratio1[STRLEN];

    out_print(res, "<tr><td>Pid</td><td>If changed %s then %s</td></tr>\n",
      Util_getEventratio(s->action_PID->failed, ratio1),
      s->action_PID->failed->description);
    out_print(res, "<tr><td>Ppid</td><td>If changed %s then %s</td></tr>\n",
      Util_getEventratio(s->action_PPID->failed, ratio1),
      s->action_PPID->failed->description);
  }
}


static void print_service_rules_resource(HttpResponse res, Service_T s) {

  if(s->resourcelist) {

    char          ratio1[STRLEN];
    char          ratio2[STRLEN];
    Resource_T    q;
    EventAction_T a;
    
    for (q= s->resourcelist; q; q= q->next) {

      a= q->action;

      Util_getEventratio(a->failed, ratio1);
      Util_getEventratio(a->succeeded, ratio2);

      switch (q->resource_id) {
	
      case RESOURCE_ID_CPU_PERCENT: 
	  
	out_print(res,"<tr><td>CPU usage limit</td>"
	  "<td>If %s %.1f%% %s then %s "
          "else if succeeded %s then %s</td></tr>", 
	  operatornames[q->operator],
	  q->limit/10.0,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
	break;
	  
      case RESOURCE_ID_TOTAL_CPU_PERCENT: 
	  
	out_print(res,"<tr><td>CPU usage limit (incl. children)</td>"
	  "<td>If %s %.1f%% %s then %s "
          "else if succeeded %s then %s</td></tr>", 
	  operatornames[q->operator],
	  q->limit/10.0,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
	break;
	  
      case RESOURCE_ID_CPUUSER: 
	  
	out_print(res,"<tr><td>CPU user limit</td>"
	  "<td>If %s %.1f%% %s then %s "
          "else if succeeded %s then %s</td></tr>", 
	  operatornames[q->operator],
	  q->limit/10.0,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
	break;
	  
      case RESOURCE_ID_CPUSYSTEM: 
	  
	out_print(res,"<tr><td>CPU system limit</td>"
	  "<td>If %s %.1f%% %s then %s "
          "else if succeeded %s then %s</td></tr>", 
	  operatornames[q->operator],
	  q->limit/10.0,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
	break;
	  
      case RESOURCE_ID_CPUWAIT: 
	  
	out_print(res,"<tr><td>CPU wait limit</td>"
	  "<td>If %s %.1f%% %s then %s "
          "else if succeeded %s then %s</td></tr>", 
	  operatornames[q->operator],
	  q->limit/10.0,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
	break;
	  
      case RESOURCE_ID_MEM_PERCENT: 
	  
	out_print(res,"<tr><td>Memory usage limit</td>"
	  "<td>If %s %.1f%% %s then %s "
          "else if succeeded %s then %s</td></tr>", 
	  operatornames[q->operator],
	  q->limit/10.0,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
	break;
	  
      case RESOURCE_ID_MEM_KBYTE: 
	  
	out_print(res,"<tr><td>Memory amount limit</td>"
	  "<td>If %s %ld %s then %s "
          "else if succeeded %s then %s</td></tr>", 
	  operatornames[q->operator],
	  q->limit,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
	break;
	  
      case RESOURCE_ID_LOAD1: 
	  
	out_print(res,"<tr><td>Load average (1min)</td>"
	  "<td>If %s %.1f %s then %s "
          "else if succeeded %s then %s</td></tr>", 
	  operatornames[q->operator],
	  q->limit/10.0,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
	break;
	  
      case RESOURCE_ID_LOAD5: 
	  
	out_print(res,"<tr><td>Load average (5min)</td>"
	  "<td>If %s %.1f %s then %s else if succeeded %s "
          "then %s</td></tr>", 
	  operatornames[q->operator],
	  q->limit/10.0,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
	break;
	  
      case RESOURCE_ID_LOAD15: 

	out_print(res,"<tr><td>Load average (15min)</td>"
	  "<td>If %s %.1f %s then %s else if succeeded %s "
          "then %s</td></tr>", 
	  operatornames[q->operator],
	  q->limit/10.0,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
	break;
	  
      case RESOURCE_ID_CHILDREN:

	out_print(res,"<tr><td>Children</td>"
	  "<td>If %s %d %s then %s else if succeeded %s "
          "then %s</td></tr>",
	  operatornames[q->operator],
	  q->limit,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
	break;
	  
      case RESOURCE_ID_TOTAL_MEM_KBYTE:

	out_print(res,"<tr><td>Memory amount limit (incl. children)</td>"
	  "<td>If %s %d %s then %s else if succeeded %s then %s"
          "</td></tr>",
	  operatornames[q->operator],
	  q->limit,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
	break;
	  
      case RESOURCE_ID_TOTAL_MEM_PERCENT:

	out_print(res,"<tr><td>Memory usage limit (incl. children)</td>"
	  "<td>If %s %.1f%% %s then %s else if succeeded %s then %s"
          "</td></tr>",
	  operatornames[q->operator],
	  q->limit/10.0,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
	break;
	  
      }    
    }
  }
}


static void print_service_params_port(HttpResponse res, Service_T s) {

  if((s->type == TYPE_HOST ||
      s->type == TYPE_PROCESS) &&
      s-> portlist) {

    Port_T p;

    if(!Util_hasServiceStatus(s)) {

      for(p= s->portlist; p; p= p->next)
        if(p->family == AF_INET) {
          out_print(res,
            "<tr><td>Port Response time</td><td>-</td></tr>");
        } else if(p->family == AF_UNIX) {
          out_print(res,
            "<tr><td>Unix Socket Response time</td><td>-</td></tr>");
        }

    } else {

      for(p= s->portlist; p; p= p->next) {
        if(p->family == AF_INET) {
          if(!p->is_available) {
            out_print(res,
              "<tr><td>Port Response time</font></td><td>"
              "<font color='#ff0000'>connection failed to %s:%d%s [%s via %s]</font>"
              "</td></tr>",
              p->hostname, p->port, p->request?p->request:"",
              p->protocol->name, Util_portTypeDescription(p));
          } else {
            out_print(res,
              "<tr><td>Port Response time</td>"
              "<td>%.3fs to %s:%d%s [%s via %s]</td></tr>",
              p->response, p->hostname, p->port, p->request?p->request:"",
              p->protocol->name, Util_portTypeDescription(p));
          }
        } else if(p->family == AF_UNIX) {
          if(!p->is_available) {
            out_print(res,
              "<tr><td>Unix Socket Response time</font></td><td>"
              "<font color='#ff0000'>connection failed to %s [%s]</font>"
              "</td></tr>",
              p->pathname, p->protocol->name);
          } else {
            out_print(res,
              "<tr><td>Unix Socket Response time</td>"
              "<td>%.3fs to %s [%s]</td></tr>",
              p->response, p->pathname, p->protocol->name);
          }
        }
      }
    }
  }
}


static void print_service_params_icmp(HttpResponse res, Service_T s) {

  if(s->type == TYPE_HOST && s->icmplist) {

    Icmp_T i;

    if(!Util_hasServiceStatus(s)) {

      for(i= s->icmplist; i; i= i->next)
        out_print(res, "<tr><td>ICMP Response time</td><td>-</td></tr>");

    } else {

      for(i= s->icmplist; i; i= i->next) {
        if(!i->is_available) {
          out_print(res,
            "<tr><td>ICMP Response time</font></td><td><font color='#ff0000'>"
            "connection failed [%s]</font></td></tr>", icmpnames[i->type]);
        } else {
          out_print(res,
            "<tr><td>ICMP Response time</td><td>%.3fs [%s]</td></tr>",
            i->response, icmpnames[i->type]);
        }
      }
    }
  }
}


static void print_service_params_perm(HttpResponse res, Service_T s) {

  if(s->type == TYPE_FILE ||
     s->type == TYPE_FIFO ||
     s->type == TYPE_DIRECTORY ||
     s->type == TYPE_FILESYSTEM) {

    if(!Util_hasServiceStatus(s)) {

      out_print(res, "<tr><td>Permission</td><td>-</font></td></tr>");

    } else {

      out_print(res,
        "<tr><td>Permission</td><td><font%s>%o</font></td></tr>",
        (s->error & EVENT_PERMISSION)?" color='#ff0000'":"",
        s->inf->st_mode & 07777);

    }
  }
}


static void print_service_params_uid(HttpResponse res, Service_T s) {

  if(s->type == TYPE_FILE ||
     s->type == TYPE_FIFO ||
     s->type == TYPE_DIRECTORY ||
     s->type == TYPE_FILESYSTEM) {

    if(!Util_hasServiceStatus(s)) {

      out_print(res, "<tr><td>UID</td><td>-</font></td></tr>");

    } else {

      out_print(res,
        "<tr><td>UID</td><td><font%s>%d</font></td></tr>",
        (s->error & EVENT_UID)?" color='#ff0000'":"",
        (int)s->inf->st_uid);

    }
  }
}


static void print_service_params_gid(HttpResponse res, Service_T s) {

  if(s->type == TYPE_FILE ||
     s->type == TYPE_FIFO ||
     s->type == TYPE_DIRECTORY ||
     s->type == TYPE_FILESYSTEM) {

    if(!Util_hasServiceStatus(s)) {

      out_print(res, "<tr><td>GID</td><td>-</font></td></tr>");

    } else {

      out_print(res,
        "<tr><td>GID</td><td><font%s>%d</font></td></tr>",
        (s->error & EVENT_GID)?" color='#ff0000'":"",
        (int)s->inf->st_gid);

    }
  }
}


static void print_service_params_timestamp(HttpResponse res, Service_T s) {

  if(s->type == TYPE_FILE ||
     s->type == TYPE_FIFO ||
     s->type == TYPE_DIRECTORY) {

    if(!Util_hasServiceStatus(s)) {

      out_print(res, "<tr><td>Timestamp</td><td>-</font></td></tr>");

    } else {

      char time[STRLEN];
      ctime_r((const time_t *)&s->inf->timestamp, time);

      out_print(res,
        "<tr><td>Timestamp</td><td><font%s>%s</font></td></tr>",
        (s->error & EVENT_TIMESTAMP)?" color='#ff0000'":"", time);

    }
  }
}


static void print_service_params_filesystem(HttpResponse res, Service_T s) {

  if(s->type == TYPE_FILESYSTEM) {

    if(!Util_hasServiceStatus(s)) {

      out_print(res,
        "<tr><td>Filesystem flags</td><td>-</td></tr>");
      out_print(res,
        "<tr><td>Blocks total</td><td>-</td></tr>");
      out_print(res,
        "<tr><td>Blocks free for non superuser</td><td>-</td></tr>");
      out_print(res,
        "<tr><td>Blocks free total</td><td>-</td></tr>");
      out_print(res,
        "<tr><td>Block size</td><td>-</td></tr>");
      out_print(res,
        "<tr><td>Inodes total</td><td>-</td></tr>");
      out_print(res,
        "<tr><td>Inodes free</td><td>-</td></tr>");

    } else {

      out_print(res,
        "<tr><td>Filesystem flags</td><td>%#lx</td></tr>",
        s->inf->flags);
      out_print(res,
        "<tr><td>Blocks total</td><td>%ld [%.1f MB]</td></tr>",
        s->inf->f_blocks,
        (float) s->inf->f_blocks/1048576*s->inf->f_bsize);
      out_print(res,
        "<tr><td>Blocks free for non superuser</td>"
        "<td>%ld [%.1f MB] [%.1f%%]</td></tr>",
        s->inf->f_blocksfree,
        (float)s->inf->f_blocksfree / (float)1048576 * (float)s->inf->f_bsize,
        (float)100 * (float)s->inf->f_blocksfree / (float)s->inf->f_blocks);
      out_print(res,
        "<tr><td>Blocks free total</td>"
        "<td><font%s>%ld [%.1f MB] [%.1f%%]</font></td></tr>",
        (s->error & EVENT_RESOURCE)?" color='#ff0000'":"",
        s->inf->f_blocksfreetotal,
        (float)s->inf->f_blocksfreetotal / (float)1048576 * (float)s->inf->f_bsize,
        (float)100 * (float)s->inf->f_blocksfreetotal / (float)s->inf->f_blocks);
      out_print(res,
        "<tr><td>Block size</td><td>%ld B</td></tr>", s->inf->f_bsize);

      if(s->inf->f_files > 0) {

        out_print(res,
          "<tr><td>Inodes total</td><td>%ld</td></tr>", s->inf->f_files);
        out_print(res,
          "<tr><td>Inodes free</td><td><font%s>%ld [%.1f%%]</font></td></tr>",
          (s->error & EVENT_RESOURCE)?" color='#ff0000'":"",
          s->inf->f_filesfree,
          (float)100 * (float)s->inf->f_filesfree / (float)s->inf->f_files);

      }
    }
  }
}

  
static void print_service_params_size(HttpResponse res, Service_T s) {

  if(s->type == TYPE_FILE) {

    if(!Util_hasServiceStatus(s)) {

      out_print(res,
        "<tr><td>Size</td><td>-</font></td></tr>");

    } else {

      out_print(res,
        "<tr><td>Size</td><td><font%s>%llu B</td></tr>",
        (s->error & EVENT_SIZE)?" color='#ff0000'":"",
        (unsigned long long) s->inf->st_size);

    }
  }
}

static void print_service_params_match(HttpResponse res, Service_T s) {

  if(s->type == TYPE_FILE) {

    if(!Util_hasServiceStatus(s)) {

      out_print(res,
        "<tr><td>Match regex</td><td>-</font></td></tr>");

    } else {

      out_print(res,
        "<tr><td>Match regex</td><td><font%s>%s</td></tr>",
        (s->error & EVENT_CONTENT)?" color='#ff0000'":"",
        (s->error & EVENT_CONTENT)?"yes":"no");
    }
  }
}


static void print_service_params_checksum(HttpResponse res, Service_T s) {

  if(s->type == TYPE_FILE && s->checksum) {

    if(!Util_hasServiceStatus(s)) {

      out_print(res, "<tr><td>Checksum</td><td>-</font></td></tr>");

    } else {

      out_print(res,
        "<tr><td>Checksum</td><td><font%s>%s(%s)</font></td></tr>",
        (s->error & EVENT_CHECKSUM)?" color='#ff0000'":"", s->inf->cs_sum,
        checksumnames[s->checksum->type]);

    }
  }
}


static void print_service_params_process(HttpResponse res, Service_T s) {

  if(s->type == TYPE_PROCESS) {

    if(!Util_hasServiceStatus(s)) {

      out_print(res,
        "<tr><td>Process id </td><td>-</td></tr>"
        "<tr><td>Parent process id </td><td>-</td></tr>"
        "<tr><td>Process uptime</td><td>-</td></tr>");

    } else {

      char *uptime;

      out_print(res,
        "<tr><td>Process id </td><td>%d</td></tr>",
        s->inf->pid);
      out_print(res,
        "<tr><td>Parent process id </td><td>%d</td></tr>",
        s->inf->ppid);

      uptime= Util_getUptime(s->inf->uptime, "&nbsp;");
      out_print(res,
        "<tr><td>Process uptime</td><td>%s</td></tr>",
        uptime);
      FREE(uptime);
    }
  }
}


static void print_service_params_resource(HttpResponse res, Service_T s) {

  if(Run.doprocess && (s->type == TYPE_PROCESS || s->type == TYPE_SYSTEM) ) {

    if(!Util_hasServiceStatus(s)) {
      if(s->type == TYPE_PROCESS) {
        out_print(res,
          "<tr><td>CPU usage</td><td>-</td></tr>"
          "<tr><td>Memory usage</td><td>-</td></tr>"
          "<tr><td>Children</td><td>-</td></tr>"
          "<tr><td>Total CPU usage (incl. children)</td><td>-</td></tr>"
          "<tr><td>Total memory usage (incl. children)</td><td>-</td></tr>");
      } else if(s->type == TYPE_SYSTEM) {
        out_print(res,
          "<tr><td>Load average</td><td>-</td></tr>"
          "<tr><td>CPU usage</td><td>-</td></tr>"
          "<tr><td>Memory usage</td><td>-</td></tr>");
      }
    } else {

      if(s->type == TYPE_PROCESS) {
        out_print(res,
          "<tr><td>CPU usage</td><td><font%s>%.1f%%</font></td></tr>",
          (s->error & EVENT_RESOURCE)?" color='#ff0000'":"",
          s->inf->cpu_percent/10.0);
        out_print(res,
          "<tr><td>Memory usage</td><td><font%s>%.1f%% [%ldkB]</font></td></tr>",
          (s->error & EVENT_RESOURCE)?" color='#ff0000'":"",
          s->inf->mem_percent/10.0, s->inf->mem_kbyte);
        out_print(res,
          "<tr><td>Children</td><td><font%s>%d</font></td></tr>",
          (s->error & EVENT_RESOURCE)?" color='#ff0000'":"",
          s->inf->children);
        out_print(res,
          "<tr><td>Total CPU usage (incl. children)</td><td><font%s>%.1f%%"
          "</font></td></tr>",
          (s->error & EVENT_RESOURCE)?" color='#ff0000'":"",
          s->inf->total_cpu_percent/10.0);
        out_print(res,
          "<tr><td>Total memory usage (incl. children)</td>"
          "<td><font%s>%.1f%% [%ldkB]</font></td></tr>",
          (s->error & EVENT_RESOURCE)?" color='#ff0000'":"",
          s->inf->total_mem_percent/10.0, s->inf->total_mem_kbyte);
      } else if(s->type == TYPE_SYSTEM) {
        out_print(res,
          "<tr><td>Load average</td><td><font%s>[%.2f] [%.2f] [%.2f]</font></td></tr>",
          (s->error & EVENT_RESOURCE)?" color='#ff0000'":"",
          systeminfo.loadavg[0],
          systeminfo.loadavg[1],
          systeminfo.loadavg[2]);
        out_print(res,
          "<tr><td>CPU usage</td><td><font%s>%.1f%%us %.1f%%sy"
        #ifdef HAVE_CPU_WAIT
          " %.1f%%wa"
        #endif
          "%s",
          (s->error & EVENT_RESOURCE)?" color='#ff0000'":"",
          systeminfo.total_cpu_user_percent/10.,
          systeminfo.total_cpu_syst_percent/10.,
        #ifdef HAVE_CPU_WAIT
          systeminfo.total_cpu_wait_percent/10.,
        #endif
          "</font></td></tr>");
        out_print(res,
          "<tr><td>Memory usage</td><td><font%s>%ld kB [%.1f%%]</font></td></tr>",
          (s->error & EVENT_RESOURCE)?" color='#ff0000'":"",
          systeminfo.total_mem_kbyte,
          systeminfo.total_mem_percent/10.);
      }
    }
  }
}


static int is_readonly(HttpRequest req) {

  if(req->remote_user) {
    Auth_T user_creds = Util_getUserCredentials(req->remote_user);
    return ( user_creds?user_creds->is_readonly:TRUE );
  }

  return FALSE;

}


/* ----------------------------------------------------------- Status output */


/* Print status in the given format. Text status is default. */
static void print_status(HttpRequest req, HttpResponse res)
{
  Service_T s;
  short level = LEVEL_FULL;
  const char *stringFormat = get_parameter(req, "format");
  const char *stringLevel = get_parameter(req, "level");

  if(stringLevel && Util_startsWith(stringLevel, LEVEL_NAME_SUMMARY))
  {
    level = LEVEL_SUMMARY;
  }

  if(stringFormat && Util_startsWith(stringFormat, "xml"))
  {
    char *D = status_xml(NULL, level);
    out_print(res, "%s", D);
    FREE(D);
    set_content_type(res, "text/xml");
  }
  else
  {
    char *uptime = Util_getUptime(Util_getProcessUptime(Run.pidfile), " ");
    out_print(res, "The Monit daemon %s uptime: %s\n\n", VERSION, uptime);
    FREE(uptime);

    for(s= servicelist_conf; s; s= s->next_conf)
    {
      status_service_txt(s, res, level);
    }
    set_content_type(res, "text/plain");
  }
}


static void status_service_txt(Service_T s, HttpResponse res, short level) {
  char *status = get_service_status_text(s);

  if(level == LEVEL_SUMMARY)
  {
    char prefix[STRLEN];

    snprintf(prefix, STRLEN, "%s '%s'", servicetypes[s->type], s->name);
    out_print(res, "%-35s %s\n", prefix, status);
  }
  else
  {
    char time[STRLEN];

    out_print(res,
	    "%s '%s'\n"
	    "  %-33s %s\n"
	    "  %-33s %s\n",
	    servicetypes[s->type], s->name,
	    "status", status,
	    "monitoring status", monitornames[s->monitor]);

    if(Util_hasServiceStatus(s)) {
      if(s->type == TYPE_FILE ||
         s->type == TYPE_FIFO || 
         s->type == TYPE_DIRECTORY || 
         s->type == TYPE_FILESYSTEM) {
        out_print(res,
  		"  %-33s %o\n"
  		"  %-33s %d\n"
  		"  %-33s %d\n",
  		"permission", s->inf->st_mode & 07777,
  		"uid", (int)s->inf->st_uid,
  		"gid", (int)s->inf->st_gid);
      }
      if(s->type == TYPE_FILE ||
         s->type == TYPE_FIFO || 
         s->type == TYPE_DIRECTORY) {
        ctime_r((const time_t *)&s->inf->timestamp, time);
        out_print(res,
  		"  %-33s %s",
  		"timestamp", time);
      }
      if(s->type == TYPE_FILE) {
        out_print(res,
  		"  %-33s %llu B\n",
  		"size", (unsigned long long) s->inf->st_size);
        if(s->checksum) {
  	out_print(res,
  		  "  %-33s %s(%s)\n",
  		  "checksum", s->inf->cs_sum, 
  		  checksumnames[s->checksum->type]);
        }
      }
      if(s->type == TYPE_FILESYSTEM) {
        out_print(res,
  		"  %-33s %#lx\n"
  		"  %-33s %ld B\n"
  		"  %-33s %ld [%.1f MB]\n"
  		"  %-33s %ld [%.1f MB] [%.1f%%]\n"
  		"  %-33s %ld [%.1f MB] [%.1f%%]\n",
  		"filesystem flags",
  		s->inf->flags,
  		"block size",
  		s->inf->f_bsize,
  		"blocks total",
  		s->inf->f_blocks,
  		((float)s->inf->f_blocks/(float)1048576*
  		 (float)s->inf->f_bsize),
  		"blocks free for non superuser",
  		s->inf->f_blocksfree,
  		((float)s->inf->f_blocksfree/(float)1048576*
  		 (float)s->inf->f_bsize),
  		((float)100*(float)s->inf->f_blocksfree/
  		 (float)s->inf->f_blocks),
  		"blocks free total",
  		s->inf->f_blocksfreetotal,
  		((float)s->inf->f_blocksfreetotal/(float)1048576*
  		 (float)s->inf->f_bsize),
  		((float)100*(float)s->inf->f_blocksfreetotal/
  		 (float)s->inf->f_blocks));
        if(s->inf->f_files > 0) {
  	out_print(res,
  		  "  %-33s %ld\n"
  		  "  %-33s %ld [%.1f%%]\n",
  		  "inodes total",
  		  s->inf->f_files,
  		  "inodes free",
  		  s->inf->f_filesfree,
  		  ((float)100*(float)s->inf->f_filesfree/
  		   (float)s->inf->f_files));
        }
      }
      if(s->type == TYPE_PROCESS) {
        char *uptime= Util_getUptime(s->inf->uptime, " ");
        out_print(res,
  		"  %-33s %d\n"
  		"  %-33s %d\n"
  		"  %-33s %s\n",
    		"pid", s->inf->pid,
  		"parent pid", s->inf->ppid,
  		"uptime", uptime);
        FREE(uptime);
        if(Run.doprocess)	{
  	out_print(res,
  		  "  %-33s %d\n"
  		  "  %-33s %ld\n"
  		  "  %-33s %ld\n"
  		  "  %-33s %.1f%%\n"
		  "  %-33s %.1f%%\n"
		  "  %-33s %.1f%%\n"
		  "  %-33s %.1f%%\n",
		  "children", s->inf->children,
		  "memory kilobytes", s->inf->mem_kbyte,
		  "memory kilobytes total", s->inf->total_mem_kbyte,
		  "memory percent", s->inf->mem_percent/10.0,
		  "memory percent total", s->inf->total_mem_percent/10.0,
		  "cpu percent", s->inf->cpu_percent/10.0,
  		  "cpu percent total", s->inf->total_cpu_percent/10.0);
        }
      }
      if(s->type == TYPE_HOST && s->icmplist) {
        Icmp_T i;
        for(i= s->icmplist; i; i= i->next) {
  	out_print(res,
  		  "  %-33s %.3fs [%s]\n",
  		  "icmp response time", i->is_available?i->response:-1.,
  		  icmpnames[i->type]);
        }
      }
      if((s->type == TYPE_HOST || s->type == TYPE_PROCESS) && s-> portlist) {
        Port_T p;
        for(p= s->portlist; p; p= p->next) {
  	if(p->family == AF_INET) {
  	  out_print(res,
  		    "  %-33s %.3fs to %s:%d%s [%s via %s]\n",
  		    "port response time", p->is_available?p->response:-1., 
  		    p->hostname,
		    p->port, p->request?p->request:"", p->protocol->name,
                    Util_portTypeDescription(p));
  	} else if(p->family == AF_UNIX) {
  	  out_print(res,
  		    "  %-33s %.3fs to %s [%s]\n",
  		    "unix socket response time", p->is_available?p->response:-1.,
  		    p->pathname, p->protocol->name);
  	}
        }
      }
      if(s->type == TYPE_SYSTEM && Run.doprocess) {
        out_print(res,
          "  %-33s [%.2f] [%.2f] [%.2f]\n"
          "  %-33s %.1f%%us %.1f%%sy"
        #ifdef HAVE_CPU_WAIT
          " %.1f%%wa"
        #endif
          "\n"
          "  %-33s %ld kB [%.1f%%]\n",
          "load average",
          systeminfo.loadavg[0],
          systeminfo.loadavg[1],
          systeminfo.loadavg[2],
          "cpu",
          systeminfo.total_cpu_user_percent/10.,
          systeminfo.total_cpu_syst_percent/10.,
        #ifdef HAVE_CPU_WAIT
          systeminfo.total_cpu_wait_percent/10.,
        #endif
          "memory usage",
          systeminfo.total_mem_kbyte,
          systeminfo.total_mem_percent/10.);
      }
    }
    ctime_r((const time_t *)&s->collected.tv_sec, time);
    out_print(res, "  %-33s %s\n", "data collected", time);
  }
  FREE(status);
}


static char *get_service_status_html(Service_T s) {

  char         *status= NULL;
  char          doaction[STRLEN];
  EventTable_T *et= Event_Table;

  ASSERT(s);

  memset(doaction, 0, STRLEN);
  if(s->doaction) {
    snprintf(doaction, STRLEN-1, " - %s pending", actionnames[s->doaction]);
  }

  status= xcalloc(sizeof(char), STRLEN);
  
  /* In the case that the service is not monitored, we will return immediately,
   * because we are not able to describe actual service state */
  if(s->monitor == MONITOR_NOT) {
    snprintf(status, STRLEN, "<font color='#ff8800'>not monitored%s</font>",
      doaction);
    return status;
  } else if(s->monitor == MONITOR_INIT) {
    snprintf(status, STRLEN, "<font color='#ff8800'>initializing%s</font>",
      doaction);
    return status;
  }

  /* In the case that error is zero, service is up without errors */
  if(!s->error) {
    snprintf(status, STRLEN, "<font color='#00ff00'>%s%s</font>",
      statusnames[s->type], doaction);
    return status;
  }

  /* In the case that the service has actualy some failure, error
   * will be non zero. We will check the bitmap and print the description
   * of the first error found */
  while((*et).id) {
    if(s->error & (*et).id) {
      if (s->error_hint & (*et).id)
        snprintf(status, STRLEN, "<font color='#ff0000'>%s%s</font>", (*et).description_changed, doaction);
      else
        snprintf(status, STRLEN, "<font color='#ff0000'>%s%s</font>", (*et).description_failed, doaction);
      return status;
    }
    et++;
  }

  /* We should not pass through here */
  snprintf(status, STRLEN, "<font color='#ff0000'>unknown%s</font>",
    doaction);
  return status;

}


static char *get_service_status_text(Service_T s) {

  char         *status= NULL;
  char          doaction[STRLEN];
  EventTable_T *et= Event_Table;

  ASSERT(s);

  memset(doaction, 0, STRLEN);
  if(s->doaction) {
    snprintf(doaction, STRLEN, " - %s pending", actionnames[s->doaction]);
  }

  status= xcalloc(sizeof(char), STRLEN);
  
  /* In the case that the service is not monitored, we will return immediately,
   * because we are not able to describe actual service state */
  if(s->monitor == MONITOR_NOT) {
    snprintf(status, STRLEN, "not monitored%s", doaction);
    return status;
  } else if(s->monitor == MONITOR_INIT) {
    snprintf(status, STRLEN, "initializing%s", doaction);
    return status;
  }

  /* In the case that error is zero, service is up without errors */
  if(!s->error) {
    snprintf(status, STRLEN, "%s%s", statusnames[s->type], doaction);
    return status;
  }

  /* In the case that the service has actualy some failure, error
   * will be non zero. We will check the bitmap and print the description
   * of the first error found */
  while((*et).id) {
    if(s->error & (*et).id) {
      if (s->error_hint & (*et).id)
        snprintf(status, STRLEN, "%s%s", (*et).description_changed, doaction);
      else
        snprintf(status, STRLEN, "%s%s", (*et).description_failed, doaction);
      return status;
    }
    et++;
  }

  /* We should not pass through here */
  snprintf(status, STRLEN, "unknown%s", doaction);
  return status;

}

