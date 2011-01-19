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

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "protocol.h"

#undef   READ_SIZE
#define  READ_SIZE  1024

/* Private prototypes */
static int check_apache_stat(Socket_T s);

/**
 * Check an Apache server to monitor its status.
 * Do this using the server-status report from mod_status, which 
 * will only be available if the server is responding to 
 * some extent.
 *
 * Currently based on the Scoreboard response, which is available
 * even with ExtendedStatus Off on Apache config file.
 *
 * @author David Fletcher, <david@megapico.co.uk>
 * @file
 */
int check_apache_status(Socket_T s) {

  char host[STRLEN];
  const char *request= "/server-status?auto";

  ASSERT(s);

  if(socket_print(s, "GET %s HTTP/1.1\r\n"
		  "Host: %s\r\n"
		  "Accept: */*\r\n"
		  "User-Agent: %s/%s\r\n"
		  "Connection: close\r\n\r\n",
		  request, Util_getHTTPHostHeader(s, host, STRLEN), 
		  prog, VERSION) < 0) {
    LogError("HTTP: error sending data -- %s\n", STRERROR);
    return FALSE;
  }
  
  return check_apache_stat(s);  
  
}


/* ----------------------------------------------------------------- Private */


/**
 * Extract the Scoreboard line from the mod_status response.
 * Count the active apache child processes, and those which are
 * in other states. If each percentage exceeds the corresponding
 * limit, then return FALSE.
 * @param s A socket
 * @param limit The maximum percentage of logging processes
 * @return TRUE if logging is OK otherwise FALSE
 */
static int check_apache_stat(Socket_T s) {
  
  int scored = 0;
  int errors = 0;
  char line[READ_SIZE];
  char search_string[READ_SIZE + 1];

  int loglimit= 0;
  int closelimit= 0;
  int dnslimit= 0;
  int keepalivelimit= 0;
  int replylimit= 0;
  int requestlimit= 0;
  int startlimit= 0;
  int waitlimit= 0;
  int gracefullimit= 0;
  int cleanuplimit= 0;
  
  int no_logging = 0;
  int no_close = 0;
  int no_dns = 0;
  int no_keepalive = 0;
  int no_reply = 0;
  int no_request = 0;
  int no_start = 0;
  int no_wait = 0;
  int no_graceful = 0;
  int no_cleanup = 0;
  int active_servers = 0;
  char *p;
  Port_T myPort= (Port_T)socket_get_Port(s);

  ASSERT(myPort);

  loglimit= myPort->ApacheStatus.loglimit;
  closelimit= myPort->ApacheStatus.closelimit;
  dnslimit= myPort->ApacheStatus.dnslimit;
  keepalivelimit= myPort->ApacheStatus.keepalivelimit;
  replylimit= myPort->ApacheStatus.replylimit;
  requestlimit= myPort->ApacheStatus.requestlimit;
  startlimit= myPort->ApacheStatus.startlimit;
  waitlimit= myPort->ApacheStatus.waitlimit;
  gracefullimit= myPort->ApacheStatus.gracefullimit;
  cleanuplimit= myPort->ApacheStatus.cleanuplimit;


  while(NULL != socket_readln(s, line, READ_SIZE)) {
    if(Util_startsWith(line, "Scoreboard")) {   
      if(1 != sscanf(line, "%*s%*[: ]%1024s", search_string)) {
       Util_chomp(line);
       LogError("APACHE-STATUS error: parsing Apache status response '%s'\n",
         line);
       return FALSE;
      }else{
        scored = 1;
      }
    }
  }
  
  DEBUG("Scoreboard: %s\n", search_string);
  
  /* Check that some scoreboard line was found, if not return an error */
  if(!scored){
    LogError("APACHE-STATUS error: no scoreboard line returned by Apache\n");
    return FALSE;
  }
  
  /* Total each of the status messages in the scoreboard */
  for(p = search_string ; *p ; p++){
    active_servers++;
    switch(*p){
    case 'S':
      no_start++;
      break;
    case 'R':
      no_request++;
      break;
    case 'W':
      no_reply++;
      break;
    case 'K':
      no_keepalive++;
      break;
    case 'D':
      no_dns++;
      break;
    case 'C':
      no_close++;
      break;
    case 'L':
      no_logging++;
      break;
    case 'G':
      no_graceful++;
      break;
    case 'I':
      no_cleanup++;
      break;
    case '_':
      no_wait++;
      break;
    case '.':
      active_servers--;
      break;
    }
  }

  if(active_servers <= 0){
    LogError("APACHE-STATUS warning: No idle server or threads found\n");
    /* This is not really an error, only a very bussy server */
    return TRUE;
  }

  /* 
   * Conditions are only tested if the limit parameter is greater than zero. 
   */
  
  if(loglimit > 0){
    if(Util_evalQExpression(myPort->ApacheStatus.loglimitOP, 
			    (100 * no_logging / active_servers), loglimit)) {
      LogError("APACHE-STATUS error:"
          " %i percent of Apache processes are logging\n", loglimit);
      errors++;
    }
  }

  if(startlimit > 0){
    if(Util_evalQExpression(myPort->ApacheStatus.startlimitOP, 
			    (100 * no_start / active_servers), startlimit)) {
      LogError("APACHE-STATUS error:"
          " %i percent of Apache processes are starting\n", startlimit);
      errors++;
    }
  }

  if(requestlimit > 0){
    if(Util_evalQExpression(myPort->ApacheStatus.requestlimitOP, 
		    (100 * no_request / active_servers), requestlimit)) {
      LogError("APACHE-STATUS error:"
          " %i percent of Apache processes are reading requests\n", 
	  requestlimit);
      errors++;
    }
  }

  if(replylimit > 0 ){
    if(Util_evalQExpression(myPort->ApacheStatus.replylimitOP, 
			    (100 * no_reply / active_servers), replylimit)) {
      LogError("APACHE-STATUS error:"
          " %i percent of Apache processes are sending a reply\n", replylimit);
      errors++;
    }
  }

  if(keepalivelimit > 0){
    if(Util_evalQExpression(myPort->ApacheStatus.keepalivelimitOP, 
		    (100 * no_keepalive / active_servers), keepalivelimit)) {
      LogError("APACHE-STATUS error:"
	  " %i percent of Apache processes are in keepalive\n", keepalivelimit);
      errors++;
    }
  }

  if(dnslimit > 0){
    if(Util_evalQExpression(myPort->ApacheStatus.dnslimitOP, 
			    (100 * no_dns / active_servers), dnslimit)) {
      LogError("APACHE-STATUS error:"
	  " %i percent of Apache processes are waiting for DNS\n", dnslimit);
      errors++;
    }
  }

  if(closelimit > 0){
    if(Util_evalQExpression(myPort->ApacheStatus.closelimitOP, 
			    (100 * no_close / active_servers), closelimit)){
      LogError("APACHE-STATUS error:"
	  " %i percent of Apache processes are closing connections\n", 
	  closelimit);
      errors++;
    }
  }

  if(gracefullimit > 0){
    if(Util_evalQExpression(myPort->ApacheStatus.gracefullimitOP, 
		     (100 * no_graceful / active_servers), gracefullimit)) {
      LogError("APACHE-STATUS error:"
	  " %i percent of Apache processes are finishing gracefully\n", 
	  gracefullimit);
      errors++;
    }
  }

  if(cleanuplimit > 0){
    if(Util_evalQExpression(myPort->ApacheStatus.cleanuplimitOP, 
		    (100 * no_cleanup / active_servers), cleanuplimit)) {
      LogError("APACHE-STATUS error:"
	  " %i percent of Apache processes are in idle cleanup\n", 
	  cleanuplimit);
      errors++;
    }
  }

  if(waitlimit > 0){
    if(Util_evalQExpression(myPort->ApacheStatus.waitlimitOP, 
			    (100 * no_wait / active_servers), waitlimit)) {
      LogError("APACHE-STATUS error:"
	  " %i percent of Apache processes are waiting for a connection\n", 
	  waitlimit);
      errors++;
    }
  }

  return (errors==0);
  
}
