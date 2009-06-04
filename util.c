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

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

#ifdef HAVE_PAM_PAM_APPL_H
#include <pam/pam_appl.h>
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#include "monitor.h"
#include "engine.h"
#include "md5.h"
#include "sha.h"
#include "base64.h"
#include "alert.h"
#include "process.h"
#include "event.h"


/* Private prototypes */
static char   x2c(char *hex);
static char  *is_str_defined(char *);
static void   printevents(unsigned int);
static int    is_url_unsafe(unsigned char *);
#ifdef HAVE_LIBPAM
#ifdef SOLARIS
static int    PAMquery(int, struct pam_message **, struct pam_response **, void *);
#else
static int    PAMquery(int, const struct pam_message **, struct pam_response **, void *);
#endif
static int    PAMcheckPasswd(const char *, const char *);
static Auth_T PAMcheckUserGroup(const char *);
#endif


struct ad_user {
  const char *login;
  const char *passwd;
};


/**
 *  General purpose utility methods.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author "Martin Pala" <martinp@tildeslash.com>
 *  @author Christian Hopp <chopp@iei.tu-clausthal.de>
 *  @author Michael Amster, <mamster@webeasy.com> 
 *
 *  @version \$Id: util.c,v 1.241 2009/05/28 21:35:30 martinp Exp $
 *  @file
 */


/* ------------------------------------------------------------------ Public */


/**
 * Return only the filename with leading directory components
 * removed. This function does not modify the path string.
 * @param path A file path string
 * @return A pointer to the basename in path
 */
char *Util_basename(char* path) {
  
  char *fname;

  ASSERT(path);

  fname= strrchr(path, '/');
  
  return(fname ? ++fname : path);
  
}


/**
  * Removes everything from the first line break or newline (CR|LF)
  * @param s A string to be chomped
  * @return The chomped string
  */
char *Util_chomp(char *s) {

  ASSERT(s);
  
  for (; *s; s++) {
    if (('\r' == *s) || ('\n' == *s)) {
      *s= 0; break;
    }
  }

  return s;
  
}


/**
 * Remove leading and trailing space from the string
 * @param s A string
 * @return s with leading and trailing spaces removed 
 */
char *Util_trim(char *s) {

  ASSERT(s);
  
  Util_ltrim(s);
  Util_rtrim(s);

  return s;
  
}


/**
 * Remove leading white space [ \t\r\n] from the string.
 * @param s A string
 * @return s with leading spaces removed
 */
char *Util_ltrim(char *s) {
  
  char *t= s;

  ASSERT(s);

  while(*t==' ' || *t=='\t' || *t=='\r' || *t=='\n') t++;
  if(t!=s) {
    char *r= s;
    do {
      *r++= *t;
    } while(*t++);
  }

  return s;

}


/**
 * Remove trailing white space [ \t\r\n] from the string
 * @param s A string
 * @return s with trailing spaces removed
 */
char *Util_rtrim(char *s) {

  char *t= s;

  ASSERT(s);

  while(*s) s++;
  while(*--s==' ' || *s=='\t' || *s=='\r' || *s=='\n') *s= 0;
  
  return t;

}

/**
 * Remove any enclosing quotes ["'] from the string
 * @param s A string
 */
void Util_trimQuotes(char *s) {

  char *t= s;
  char tmp=0;

  ASSERT(s);

  if(*t==39 || *t==34 ) {

    tmp=*t;
    t++;

  } else {

    return;
    
  }

  while ( *t != tmp && *t != '\0' ) {
    *(t-1) = *t;
    t++;
  }

  *(t-1) = '\0';
  
  return;

}


char *Util_trunc(char *s, int n) {
        ASSERT(n>=0);
        if (s) {
                int sl = strlen(s);
                if (sl > (n + 4)) {
                        int e = n+3;
                        for (; n < e; n++)
                                s[n]= '.';
                        s[n]= 0;
                }
        }
        return s;
}


/**
 * Replace all occurrences of the <code>old</code> char in the string
 * <code>s</code> with the <code>new</code> char.
 * @param s A string
 * @param old The old char
 * @param new The new char
 * @return s where all occurrence of old are replaced with new
 */
char *Util_replace(char *s, char old, char new) {

  char *t= s;

  while (s&&*s) { if(*s==old) *s=new; s++; }

  return (t);

}


/**
 * Replace all occurrences of the sub-string old in the string src
 * with the sub-string new. The method is case sensitive for the
 * sub-strings new and old. The string parameter src must be an
 * allocated string, not a character array.
 * @param src An allocated string reference (e.g. &string)
 * @param old The old sub-string
 * @param new The new sub-string
 * @return src where all occurrences of the old sub-string are
 * replaced with the new sub-string. 
 */
char *Util_replaceString(char **src, const char *old, const char *new) {

  int i;
  int d;
  
  ASSERT(src);
  ASSERT(*src);
  ASSERT(old);
  ASSERT(new);
  
  i= Util_countWords(*src, old);
  d= strlen(new)-strlen(old);
  
  if(i==0)
    return *src;
  if(d>0)
    d*= i;
  else
    d= 0;
  
  {
    char *p, *q;
    int l= strlen(old);
    char *buf= xcalloc(sizeof(char), strlen(*src)+d+1);
    
    q= *src;
    *buf= 0;
    
    while((p= strstr(q, old))) {
      
      *p= '\0';
      strcat(buf, q);
      strcat(buf, new);
      p+= l;
      q= p;
      
    }
    
    strcat(buf, q);
    FREE(*src);
    *src= buf;
  }
  
  return *src;
  
}


/**
 * Count the number the sub-string word occurs in s.
 * @param s The String to search for word in
 * @param word 	The sub-string to count in s
 */
int Util_countWords(char *s, const char *word) {

  int i= 0;
  char *p= s;

  ASSERT(s && word);
  
  while((p= strstr(p, word))) { i++;  p++; }

  return i;

}


/**
 * Return TRUE if the string <i>a</i> starts with the string
 * <i>b</i>. The test is <i>case-insensitive</i> but depends on that
 * all characters in the two strings can be translated in the current
 * locale.
 * @param a The string to search for b in
 * @param b The sub-string to test a against
 * @return TRUE if a starts with b, otherwise FALSE
 */
int Util_startsWith(const char *a, const char *b) {

  if((!a || !b) || toupper((int)*a)!=toupper((int)*b)) return FALSE;

  while(*a && *b) {
    
    if(toupper((int)*a++) != toupper((int)*b++)) return FALSE;
    
  }

  return TRUE;

}


/**
 * Exchanges \escape sequences in a string
 * @param buf A string
 */
void Util_handleEscapes(char *buf) {
  
  int editpos;
  int insertpos;
  
  ASSERT(buf);
  
  for(editpos=insertpos=0; *(buf+editpos)!='\0'; editpos++, insertpos++) {
    
    if(*(buf+editpos) == '\\' ) {
      
      switch(*(buf+editpos+1)) {
        
        case 'n': 
          *(buf+insertpos)='\n';
          editpos++;
          break;
          
        case 't':
          *(buf+insertpos)='\t';
          editpos++;
          break;
          
        case 'r':
          *(buf+insertpos)='\r';
          editpos++;
          break;
          
        case ' ':
          *(buf+insertpos)=' ';
          editpos++;
          break;
          
        case '0':
          if(*(buf+editpos+2)=='x') {
            if((*(buf+editpos+3)=='0' && *(buf+editpos+4)=='0')) {
              /* Don't swap \0x00 with 0 to avoid truncating the string. 
              Currently the only place where we support sending of 0 bytes
              is in check_generic(). The \0x00 -> 0 byte swap is performed
              there and in-place.
              */
              *(buf+insertpos)=*(buf+editpos);
            } else {
              *(buf+insertpos)=x2c(&buf[editpos+3]);
              editpos+=4;
            } 
          }
          break;
          
        case '\\':
          *(buf+insertpos)='\\';
          editpos++;
          break;
          
        default:
          *(buf+insertpos)=*(buf+editpos);
          
      }  
      
    } else {
      
      *(buf+insertpos)=*(buf+editpos);
      
    }  
    
  }
  *(buf+insertpos)='\0';
  
}


/**
 * Variant of Util_handleEscapes() which only handle \0x00 escape sequences 
 * in a string
 * @param buf A string
 * @return The new length of buf
 */
int Util_handle0Escapes(char *buf) {
  
  int editpos;
  int insertpos;
  
  ASSERT(buf);
  
  for(editpos=insertpos=0; *(buf+editpos)!='\0'; editpos++, insertpos++) {
    
    if(*(buf+editpos) == '\\' ) {
      
      switch(*(buf+editpos+1)) {
        
        case '0':
          if(*(buf+editpos+2)=='x') {
            *(buf+insertpos)=x2c(&buf[editpos+3]);
            editpos+=4;
          }
          break;

        default:
          *(buf+insertpos)=*(buf+editpos);
          
      }  
      
    } else {
      
      *(buf+insertpos)=*(buf+editpos);
      
    }  
    
  }
  *(buf+insertpos)='\0';
  
  return insertpos;
  
}


/**
 * Convert a digest buffer to a char string
 * @param digest buffer containing a MD digest
 * @param mdlen digest length
 * @param result buffer to write the result to. Must be at least
 * 41 bytes long.
 */
char *Util_digest2Bytes(unsigned char *digest, int mdlen, MD_T result) {
        int i;
        unsigned char *tmp= (unsigned char*)result;
        static unsigned char hex[] = "0123456789abcdef";     
        ASSERT(mdlen * 2 < MD_SIZE); // Overflow guard
        for(i= 0; i < mdlen; i++) {
                *tmp++ = hex[digest[i] >> 4];
                *tmp++ = hex[digest[i] & 0xf];
        }
        *tmp = '\0';
        return result;
}


/**
 * @param name A service name as stated in the config file
 * @return the named service or NULL if not found
 */
Service_T Util_getService(const char *name) {

  Service_T s;

  ASSERT(name);

  for(s= servicelist; s; s= s->next) {
    if(IS(s->name, name)) {
      return s;
    }
  }

  return NULL;

}


/**
 * Get the length of the service list, that is; the number of services
 * managed by monit
 * @return The number of services monitored
 */
int Util_getNumberOfServices() {
  int i= 0;
  Service_T s;
  for(s= servicelist; s; s= s->next) i+=1;
  return i;
}


/**
 * @param name A service name as stated in the config file
 * @return TRUE if the service name exist in the
 * servicelist, otherwise FALSE
 */
int Util_existService(const char *name) {

  ASSERT(name);

  return Util_getService(name)?TRUE:FALSE;

}


/**
 * Print the Runtime object
 */
void Util_printRunList() {
  
  printf("Runtime constants:\n");
  printf(" %-18s = %s\n", "Control file", is_str_defined(Run.controlfile));
  printf(" %-18s = %s\n", "Log file", is_str_defined(Run.logfile));
  printf(" %-18s = %s\n", "Pid file", is_str_defined(Run.pidfile));
  printf(" %-18s = %s\n", "Debug", Run.debug?"True":"False");
  printf(" %-18s = %s\n", "Log", Run.dolog?"True":"False");
  printf(" %-18s = %s\n", "Use syslog", Run.use_syslog?"True":"False");
  printf(" %-18s = %s\n", "Is Daemon", Run.isdaemon?"True":"False");
  printf(" %-18s = %s\n", "Use process engine", Run.doprocess?"True":"False");
  printf(" %-18s = %d seconds with start delay %d seconds\n", "Poll time", Run.polltime, Run.startdelay);
  printf(" %-18s = %d bytes\n", "Expect buffer", Run.expectbuffer);

  if(Run.eventlist_dir) {
    char slots[STRLEN];

    if(Run.eventlist_slots < 0)
      snprintf(slots, STRLEN, "unlimited"); 
    else
      snprintf(slots, STRLEN, "%d", Run.eventlist_slots);

    printf(" %-18s = base directory %s with %s slots\n",
      "Event queue", Run.eventlist_dir, slots);
  }

  if(Run.mmonits) {
    Mmonit_T c= Run.mmonits;
    printf(" %-18s = ", "M/Monit(s)");
    for(c= Run.mmonits; c; c= c->next)
    {
      printf("%s with timeout %d seconds%s%s%s%s%s%s",
        c->url->url,
        c->timeout,
	(c->ssl.use_ssl && c->ssl.version) ? " ssl version " : "",
	(c->ssl.use_ssl && c->ssl.version) ? sslnames[c->ssl.version] : "",
	c->ssl.certmd5?" server cert md5 sum ":"",
	c->ssl.certmd5?c->ssl.certmd5:"",
        c->url->user?" using credentials":"",
        c->next?",\n                    = ":"");
    }
    printf("\n");
  }

  if(Run.mailservers) {
    printf(" %-18s = ", "Mail server(s)");
    MailServer_T mta= Run.mailservers;
    for(mta= Run.mailservers; mta; mta= mta->next)
	printf("%s:%d%s%s",
          mta->host,
          mta->port,
          mta->ssl.use_ssl?"(ssl)":"",
          mta->next?", ":" ");
    printf("with timeout %d seconds", Run.mailserver_timeout);
    if(Run.mail_hostname)
      printf(" using '%s' as my hostname", Run.mail_hostname);
    printf("\n");
  }

  printf(" %-18s = %s\n", "Mail from", is_str_defined(Run.MailFormat.from));
  printf(" %-18s = %s\n", "Mail subject",
	 is_str_defined(Run.MailFormat.subject));
  printf(" %-18s = %-.20s%s\n", "Mail message",
	 Run.MailFormat.message?
	 Run.MailFormat.message:"(not defined)",
	 Run.MailFormat.message?"..(truncated)":"");

  printf(" %-18s = %s\n", "Start monit httpd", Run.dohttpd?"True":"False");
  
  if(Run.dohttpd) {
    
    printf(" %-18s = %s\n", "httpd bind address",
	   Run.bind_addr?Run.bind_addr:"Any/All");
    printf(" %-18s = %d\n", "httpd portnumber", Run.httpdport);
    printf(" %-18s = %s\n", "httpd signature", Run.httpdsig?"True":"False");
    printf(" %-18s = %s\n", "Use ssl encryption", Run.httpdssl?"True":"False");

    if(Run.httpdssl) {

      printf(" %-18s = %s\n", "PEM key/cert file", Run.httpsslpem);

      if(Run.httpsslclientpem!=NULL) {
	printf(" %-18s = %s\n", "Client cert file", Run.httpsslclientpem);
      } else {
	printf(" %-18s = %s\n", "Client cert file", "None");
      } 

      printf(" %-18s = %s\n", "Allow self certs", 
	     Run.allowselfcert?"True":"False");

    }

    printf(" %-18s = %s\n", "httpd auth. style",
	   (Run.credentials!=NULL)&&has_hosts_allow()?
	   "Basic Authentication and Host/Net allow list":
	   (Run.credentials!=NULL)?"Basic Authentication":
	   has_hosts_allow()?"Host/Net allow list":
	   "No authentication!");
     
  }

  {
    Mail_T list;
    for(list= Run.maillist; list; list= list->next) {
      printf(" %-18s = %s\n", "Alert mail to", is_str_defined(list->to));
      printf("   %-16s = ", "Alert on");
      printevents(list->events);
      if(list->reminder)
        printf("   %-16s = %u cycles\n", "Alert reminder", list->reminder);
    }
  }

  printf("\n");
  
}


/**
 * Print a service object
 * @param p A Service_T object
 */
void Util_printService(Service_T s) {
  
  Port_T n;
  Icmp_T i;
  Mail_T r;
  Filesystem_T dl;
  Resource_T q;
  Timestamp_T t;
  Size_T sl;
  Match_T ml;
  Dependant_T d;
  char string[STRLEN];
  char ratio1[STRLEN];
  char ratio2[STRLEN];

  ASSERT(s);
 
  snprintf(string, STRLEN, "%s Name", servicetypes[s->type]);
  printf("%-21s = %s\n", string, s->name);
  if(s->group)
    printf(" %-20s = %s\n", "Group", s->group);
  if(s->type == TYPE_PROCESS)
    printf(" %-20s = %s\n", "Pid file", s->path);
  else if(s->type != TYPE_HOST && s->type != TYPE_SYSTEM)
    printf(" %-20s = %s\n", "Path", s->path);
  printf(" %-20s = %s\n", "Monitoring mode", modenames[s->mode]);
  if(s->start) {
    int i = 0;

    printf(" %-20s = '", "Start program");
    while(s->start->arg[i]) {
      if(i) printf(" ");
      printf("%s", s->start->arg[i++]);
    }
    printf("'");
    if(s->start->has_uid)
      printf(" as uid %d", s->start->uid);
    if(s->start->has_gid)
      printf(" as gid %d", s->start->gid);
    printf(" timeout %d second(s)", s->start->timeout);
    printf("\n");
  }
  if(s->stop) {
    int i = 0;

    printf(" %-20s = '", "Stop program");
    while(s->stop->arg[i]) {
      if(i) printf(" ");
      printf("%s", s->stop->arg[i++]);
    }
    printf("'");
    if(s->stop->has_uid)
      printf(" as uid %d", s->stop->uid);
    if(s->stop->has_gid)
      printf(" as gid %d", s->stop->gid);
    printf(" timeout %d second(s)", s->stop->timeout);
    printf("\n");
  }

  for(d= s->dependantlist; d; d= d->next)
    if(d->dependant != NULL)
      printf(" %-20s = %s\n", "Depends on Service", d->dependant);

  if(s->type == TYPE_PROCESS) {
    printf(" %-20s = if changed %s then %s\n",
      "Pid",
      Util_getEventratio(s->action_PID->failed, ratio1),
      s->action_PID->failed->description);

    printf(" %-20s = if changed %s then %s\n",
      "Ppid",
      Util_getEventratio(s->action_PPID->failed, ratio1),
      s->action_PPID->failed->description);
  }

  if(s->type == TYPE_FILESYSTEM) {
    printf(" %-20s = if changed %s then %s\n",
      "Filesystem flags",
      Util_getEventratio(s->action_FSFLAG->failed, ratio1),
      s->action_FSFLAG->failed->description);
  }

  if(s->checksum && s->checksum->action) {
    Checksum_T cs= s->checksum;
    EventAction_T a= cs->action;

    Util_getEventratio(a->failed, ratio1);
    Util_getEventratio(a->succeeded, ratio2);

    if(cs->test_changes)
      printf(" %-20s = if changed %s %s then %s\n",
        "Checksum", checksumnames[cs->type],
        ratio1, a->failed->description);
    else
      printf(" %-20s = if failed %s(%s) %s then %s else if succeeded %s then %s\n",
        "Checksum", cs->hash, checksumnames[cs->type],
        ratio1, a->failed->description,
        ratio2, a->succeeded->description);
  }
  
  if(s->perm && s->perm->action) {
    EventAction_T a= s->perm->action;

    Util_getEventratio(a->failed, ratio1);
    Util_getEventratio(a->succeeded, ratio2);

    printf(" %-20s = if failed %04o %s then %s else if succeeded %s then %s\n",
      "Permission", s->perm->perm,
      ratio1, a->failed->description,
      ratio2, a->succeeded->description);
  }

  if(s->uid && s->uid->action) {
    EventAction_T a= s->uid->action;

    Util_getEventratio(a->failed, ratio1);
    Util_getEventratio(a->succeeded, ratio2);

    printf(" %-20s = if failed %d %s then %s else if succeeded %s then %s\n",
      "UID", (int)s->uid->uid,
      ratio1, a->failed->description,
      ratio2, a->succeeded->description);
  }

  if(s->gid && s->gid->action) {
    EventAction_T a= s->gid->action;

    Util_getEventratio(a->failed, ratio1);
    Util_getEventratio(a->succeeded, ratio2);

    printf(" %-20s = if failed %d %s then %s else if succeeded %s then %s\n",
      "GID", (int)s->gid->gid,
      ratio1, a->failed->description,
      ratio2, a->succeeded->description);
  }

  if(s->icmplist)
    for(i= s->icmplist; i; i= i->next) {
      EventAction_T a= i->action;

      Util_getEventratio(a->failed, ratio1);
      Util_getEventratio(a->succeeded, ratio2);

      printf(" %-20s = if failed %s count %d with timeout %d seconds %s then %s "
        "else if succeeded %s then %s\n",
        "ICMP", icmpnames[i->type], i->count, i->timeout,
        ratio1, a->failed->description,
        ratio2, a->succeeded->description);
    }

  if(s->portlist) {
    
    for(n= s->portlist; n; n= n->next) {
      EventAction_T a= n->action;
      
      Util_getEventratio(a->failed, ratio1);
      Util_getEventratio(a->succeeded, ratio2);

      if(n->family == AF_INET) {
	
	   printf(" %-20s = if failed %s:%d%s [%s via %s] with "
             "timeout %d seconds %s then %s else if succeeded %s then %s\n",
	     "Port", n->hostname, n->port, n->request?n->request:"",
             n->protocol->name, Util_portTypeDescription(n),
             n->timeout,
             ratio1, a->failed->description,
             ratio2, a->succeeded->description);
	  
	   if(n->SSL.certmd5 != NULL)
	     printf(" %-20s = %s\n", "Server cert md5 sum", n->SSL.certmd5);

      } else if(n->family == AF_UNIX) {
	
        printf(" %-20s = if failed %s [protocol %s] with timeout %d seconds "
          "%s then %s else if succeeded %s then %s\n",
          "Unix Socket", n->pathname, n->protocol->name, n->timeout,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
	
      }
      
    }
    
  }
  
  for(t= s->timestamplist; t; t= t->next) {
    EventAction_T a= t->action;

    Util_getEventratio(a->failed, ratio1);
    Util_getEventratio(a->succeeded, ratio2);

    if(t->test_changes)
      printf(" %-20s = if changed %s then %s\n",
        "Timestamp",
        ratio1, a->failed->description);
    else
      printf(" %-20s = if %s %d second(s) %s then %s else if succeeded %s then %s\n",
        "Timestamp", operatornames[t->operator], t->time,
        ratio1, a->failed->description,
        ratio2, a->succeeded->description);
    
  }

  for(sl= s->sizelist; sl; sl= sl->next) {
    EventAction_T a= sl->action;
    
    Util_getEventratio(a->failed, ratio1);
    Util_getEventratio(a->succeeded, ratio2);

    if(sl->test_changes)
      printf(" %-20s = if changed %s then %s\n",
        "Size",
        ratio1, a->failed->description);
    else
      printf(" %-20s = if %s %llu byte(s) %s then %s else if succeeded %s then %s\n",
        "Size", operatornames[sl->operator], sl->size,
        ratio1, a->failed->description,
        ratio2, a->succeeded->description);
    
  }

  for(ml= s->matchlist; ml; ml= ml->next) {
    EventAction_T a= ml->action;
    
    Util_getEventratio(a->failed, ratio1);

    printf(" %-20s = if%s match \"%s\" %s then %s\n",
           "Regex", ml->not?" not":"", ml->match_string,
           ratio1, a->failed->description);
    
  }
  
  for(dl= s->filesystemlist; dl; dl= dl->next) {
    EventAction_T a= dl->action;
    
    Util_getEventratio(a->failed, ratio1);
    Util_getEventratio(a->succeeded, ratio2);

    if(dl->resource == RESOURCE_ID_INODE) {
	    
      if(dl->limit_absolute > -1) {
        printf(" %-20s = if %s %ld %s then %s else if succeeded %s then %s\n",
          "Inodes usage limit",
          operatornames[dl->operator],
          dl->limit_absolute,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
      } else {
        printf(" %-20s = if %s %.1f%% %s then %s else if succeeded %s then %s\n",
          "Inodes usage limit",
          operatornames[dl->operator],
          dl->limit_percent/10.,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
      }
      
    } else if(dl->resource == RESOURCE_ID_SPACE) {
	    
      if(dl->limit_absolute > -1) {
        printf(" %-20s = if %s %ld blocks %s then %s else if succeeded %s then %s\n",
          "Space usage limit",
          operatornames[dl->operator],
          dl->limit_absolute,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
      } else {
        printf(" %-20s = if %s %.1f%% %s then %s else if succeeded %s then %s\n",
          "Space usage limit",
          operatornames[dl->operator],
          dl->limit_percent/10.,
          ratio1, a->failed->description,
          ratio2, a->succeeded->description);
      }

    }
    
  }

  for(q= s->resourcelist; q; q= q->next) {
    EventAction_T a= q->action;

    Util_getEventratio(a->failed, ratio1);
    Util_getEventratio(a->succeeded, ratio2);

    switch(q->resource_id) {

    case RESOURCE_ID_CPU_PERCENT: 

      printf(" %-20s = if %s %.1f%% %s then %s "
        "else if succeeded %s then %s\n", 
        "CPU usage limit", 
        operatornames[q->operator], q->limit/10.0,
        ratio1, a->failed->description,
        ratio2, a->succeeded->description);
      break;

    case RESOURCE_ID_TOTAL_CPU_PERCENT: 

      printf(" %-20s = if %s %.1f%% %s then %s "
        "else if succeeded %s then %s\n", 
        "CPU usage limit (incl. children)", 
        operatornames[q->operator], q->limit/10.0,
        ratio1, a->failed->description,
        ratio2, a->succeeded->description);
      break;

    case RESOURCE_ID_CPUUSER: 

      printf(" %-20s = if %s %.1f%% %s then %s "
        "else if succeeded %s then %s\n", 
        "CPU user limit", 
        operatornames[q->operator], q->limit/10.0,
        ratio1, a->failed->description,
        ratio2, a->succeeded->description);
      break;

    case RESOURCE_ID_CPUSYSTEM: 

      printf(" %-20s = if %s %.1f%% %s then %s "
        "else if succeeded %s then %s\n", 
        "CPU system limit", 
        operatornames[q->operator], q->limit/10.0,
        ratio1, a->failed->description,
        ratio2, a->succeeded->description);
      break;

    case RESOURCE_ID_CPUWAIT: 

      printf(" %-20s = if %s %.1f%% %s then %s "
        "else if succeeded %s then %s\n", 
        "CPU wait limit", 
        operatornames[q->operator], q->limit/10.0,
        ratio1, a->failed->description,
        ratio2, a->succeeded->description);
      break;

    case RESOURCE_ID_MEM_PERCENT: 

      printf(" %-20s = if %s %.1f%% %s then %s "
        "else if succeeded %s then %s\n", 
        "Memory usage limit", 
        operatornames[q->operator], q->limit/10.0,
        ratio1, a->failed->description,
        ratio2, a->succeeded->description);
      break;

    case RESOURCE_ID_MEM_KBYTE: 

      printf(" %-20s = if %s %ldkB %s then %s "
        "else if succeeded %s then %s\n", 
        "Memory amount limit", 
        operatornames[q->operator], q->limit,
        ratio1, a->failed->description,
        ratio2, a->succeeded->description);
      break;

    case RESOURCE_ID_LOAD1: 

      printf(" %-20s = if %s %.1f %s then %s "
        "else if succeeded %s then %s\n", 
        "Load avg. (1min)", 
        operatornames[q->operator], q->limit/10.0,
        ratio1, a->failed->description,
        ratio2, a->succeeded->description);
      break;

    case RESOURCE_ID_LOAD5: 

      printf(" %-20s = if %s %.1f %s then %s "
        "else if succeeded %s then %s\n", 
        "Load avg. (5min)", 
        operatornames[q->operator], q->limit/10.0,
        ratio1, a->failed->description,
        ratio2, a->succeeded->description);
      break;

    case RESOURCE_ID_LOAD15: 

      printf(" %-20s = if %s %.1f %s then %s "
        "else if succeeded %s then %s\n", 
        "Load avg. (15min)", 
        operatornames[q->operator], q->limit/10.0,
        ratio1, a->failed->description,
        ratio2, a->succeeded->description);
      break;

    case RESOURCE_ID_CHILDREN:

      printf(" %-20s = If %s %ld %s then %s "
        "else if succeeded %s then %s\n",
        "Children", operatornames[q->operator], q->limit,
        ratio1, a->failed->description,
        ratio2, a->succeeded->description);
      break;

    case RESOURCE_ID_TOTAL_MEM_KBYTE:

      printf(" %-20s = If %s %ld %s then %s "
        "else if succeeded %s then %s\n",
        "Memory amount limit (incl. children)",
        operatornames[q->operator], q->limit,
        ratio1, a->failed->description,
        ratio2, a->succeeded->description);
      break;

    case RESOURCE_ID_TOTAL_MEM_PERCENT:

      printf(" %-20s = If %s %.1f%% %s then %s "
        "else if succeeded %s then %s\n",
        "Memory usage limit (incl. children)",
        operatornames[q->operator], q->limit/10.0,
        ratio1, a->failed->description,
        ratio2, a->succeeded->description);
      break;

    }    
  }

  if(s->def_every)
    printf(" %-20s = Check service every %d cycles\n", "Every", s->every);
  
  if(s->def_timeout && s->action_TIMEOUT) {
    EventAction_T a= s->action_TIMEOUT;
    printf(" %-20s = If %d restart within %d cycles then %s "
      "else if succeeded then %s\n",
      "Timeout",
      s->to_start,
      s->to_cycle,
      a->failed->description,
      a->succeeded->description);
  }

  for(r= s->maillist; r; r= r->next) {
    printf(" %-20s = %s\n", "Alert mail to", is_str_defined(r->to));
    printf("   %-18s = ", "Alert on");
    printevents(r->events);
    if(r->reminder)
      printf("   %-18s = %u cycles\n", "Alert reminder", r->reminder);
  }

  printf("\n");
  
}


/**
 * Print all the services in the servicelist
 */
void Util_printServiceList() {

  Service_T s;
  char ruler[STRLEN];
  
  printf("The service list contains the following entries:\n\n");
  
  for(s= servicelist_conf; s; s= s->next_conf) {
    
    Util_printService(s);
    
  }

  memset(ruler, '-', STRLEN);
  printf("%-.79s\n", ruler);
  
}

/**
 * Print file hashes from stdin or from the given file
 */
void Util_printHash(char *filename) {
  
  unsigned char buf[STRLEN], buf2[STRLEN];
  FILE * fhandle;
  int fresult;
  int i;

  if (filename == NULL) {
    fhandle = stdin;
  } else {
    fhandle = fopen(filename, "r");
    if ( fhandle == NULL ) {
      goto fileerror;
    }
  }
  fresult=Util_getStreamDigests(fhandle, buf, buf2);
  if(fresult) {
    goto fileerror;
  }
  if (filename==NULL) {
    printf("SHA1(stdin) = ");
  } else {
    printf("SHA1(%s) = ", filename);
    fclose(fhandle);
  }
  for(i= 0; i < 20; ++i) {
    printf("%02x", buf[i]);
  }
  if (filename==NULL) {
    printf("\nMD5(stdin)  = ");
  } else {
    printf("\nMD5(%s)  = ", filename);
  }
  for(i= 0; i < 16; ++i) {
    printf("%02x", buf2[i]);
  }
  printf("\n");

  return;

fileerror:

  printf("monit: %s: %s\n", filename, strerror(errno));
  exit(1);
}

/**
 * Open and read the id from the given idfile. If the idfile doesn't exist,
 * generate new id and store it in the id file.
 * @param idfile An idfile with full path
 * @return the id
 */
char *Util_monitId(char *idfile) {
  FILE *file = NULL;

  ASSERT(idfile);

  if(! File_exist(idfile)) {
    char buf[STRLEN];
    unsigned char digest[STRLEN];
    mode_t mask = umask(PRIVATEMASK);
    file = fopen(idfile, "w");
    umask(mask);
    if(! file) {
      LogError("%s: Error opening the idfile '%s' -- %s\n", prog, idfile, STRERROR);
      return NULL;
    }
    /* Generate the unique id */
    srandom(time(NULL) + getpid());
    snprintf(buf, STRLEN, "%lu%d%lu", (unsigned long)time(NULL), getpid(), random());
    md5_buffer(buf, strlen(buf), digest);
    Util_digest2Bytes(digest, 16, Run.id);
    fprintf(file, "%s", Run.id);
    LogInfo("%s: generated unique Monit id %s and stored to '%s'\n", prog, Run.id, idfile);
  } else {
    if(! File_isFile(idfile)) {
      LogError("%s: idfile '%s' is not a regular file\n", prog, idfile);
      return NULL;
    }
    if((file = fopen(idfile,"r")) == (FILE *)NULL) {
      LogError("%s: Error opening the idfile '%s' -- %s\n", prog, idfile, STRERROR);
      return NULL;
    }
    if(fscanf(file, "%256s", Run.id) != 1) {
      LogError("%s: Error reading id from file '%s'\n", prog, idfile);
      fclose(file);
      return NULL;
    }
  }
  fclose(file);

  return Run.id;
}

/**
 * Open and read the pid from the given pidfile.
 * @param pidfile A pidfile with full path
 * @return the pid (TRUE) or FALSE if the pid could
 * not be read from the file
 */
pid_t Util_getPid(char *pidfile) {
  FILE *file= NULL;
  int pid= -1;

  ASSERT(pidfile);

  if(! File_exist(pidfile)) {
    DEBUG("%s: pidfile '%s' does not exist\n",prog, pidfile);
    return FALSE;
  }
  if(! File_isFile(pidfile)) {
    LogError("%s: pidfile '%s' is not a regular file\n",prog, pidfile);
    return FALSE;
  }
  if((file= fopen(pidfile,"r")) == (FILE *)NULL) {
    LogError("%s: Error opening the pidfile '%s' -- %s\n", prog, pidfile, STRERROR);
    return FALSE;
  }
  if(fscanf(file, "%d", &pid) != 1) {
    LogError("%s: Error reading pid from file '%s'\n", prog, pidfile);
    fclose(file);
    return FALSE;
  }
  fclose(file);

  if(pid < 0)
    return(FALSE);
  
  return(pid_t)pid;
  
}


/**
 * @return TRUE (i.e. the running pid id)  if
 * the process is running, otherwise FALSE
 */
int Util_isProcessRunning(Service_T s) {
  
  pid_t  pid;
  
  ASSERT(s);
  
  errno= 0;
  if((pid= Util_getPid(s->path)) >= 0) {
    if( (getpgid(pid) > -1) || (errno == EPERM) )
      return pid;
    DEBUG("'%s' Error testing process id [%d] -- %s\n", s->name, pid, STRERROR);
  }
  Util_resetInfo(s);
  
  return FALSE;
  
}


/**
 * Returns a RFC822 Date string. If the given date is NULL compute the
 * date now. If an error occured the result buffer is set to an empty
 * string. The result buffer should be large enough to hold 33 bytes.
 * @param date seconds since EPOCH
 * @param result The buffer to write the date string to
 * @param len the length of the result buffer
 * @return a pointer to the result buffer
 */
char *Util_getRFC822Date(time_t *date, char *result, int len) {
  
  struct tm *tm_now;
  time_t now = (date && *date > 0) ? *date : time(NULL);
  
  tm_now = localtime(&now);
  if (! tm_now)
    return NULL;
  
  if (strftime(result, len, "%a, %d %b %Y %H:%M:%S %z", tm_now) <= 0) {
    *result= 0;
  }
  return result;
}


/**
 * Compute an uptime for a process based on the ctime
 * from the pidfile.
 * @param pidfile A process pidfile
 * @return an uptime
 */
time_t Util_getProcessUptime(char *pidfile) {

  time_t ctime;

  ASSERT(pidfile);

  if((ctime= File_getTimestamp(pidfile, S_IFREG)) ) {
    time_t now= time(&now);
    time_t since= now-ctime;
    return since;
  }

  return (time_t)-1;

}

  
/**
 * Compute an uptime string based on the delta time in seconds. The
 * caller must free the returned string.
 * @param delta seconds. 
 * @param sep string separator
 * @return an uptime string
 */
char *Util_getUptime(time_t delta, char *sep) {

  static int min = 60;
  static int hour = 3600;
  static int day = 86400;
  long rest_d;
  long rest_h;
  long rest_m;
  char buf[STRLEN];
  char *p = buf;

  *buf = 0;
  if(delta < 0)
    return(xstrdup(""));
  if((rest_d = delta/day)>0) {
    p += snprintf(p, STRLEN-(p-buf), "%ldd%s", rest_d,sep);
    delta -= rest_d*day;
  }
  if((rest_h = delta/hour)>0 || (rest_d > 0)) {
    p += snprintf(p, STRLEN-(p-buf), "%ldh%s", rest_h,sep);
    delta -= rest_h*hour;
  }
  rest_m = delta/min;
  snprintf(p, STRLEN - (p - buf), "%ldm%s", rest_m, sep);
  
  return xstrdup(buf);

}


/**
 * @return a checksum for the given file, or NULL if error.
 */
 char *Util_getChecksum(char *file, int hashtype) {

   int hashlength=16;

   ASSERT(file);

   switch(hashtype) {
     case HASH_MD5:
     hashlength=16;
     break;
     case HASH_SHA1:
     hashlength=20;
     break;
     default:
     return NULL;
   }

   if(File_isFile(file)) {
     FILE *f= fopen(file, "r");
     if(f) {
       MD_T result;
       unsigned char buf[STRLEN];
       int fresult=0;

       *result=0;

       switch(hashtype) {
         case HASH_MD5:
         fresult=md5_stream(f, buf);
         break;
         case HASH_SHA1:
         fresult=sha_stream(f, buf);
         break;
       }

       fclose(f);
       if(fresult) {
         return NULL;
       }

       return (xstrdup(Util_digest2Bytes(buf, hashlength, result)));

     }
   }

   return NULL;

 }


/**
 * Escape an uri string converting unsafe characters to a hex (%xx)
 * representation.  The caller must free the returned string.
 * @param uri an uri string
 * @return the escaped string
 */
char *Util_urlEncode(char *uri) {

  register int x, y;
  unsigned char *str;
  static unsigned char hexchars[]= "0123456789ABCDEF";

  ASSERT(uri);

  str= (unsigned char *)xcalloc(sizeof(unsigned char), 3 * strlen(uri) + 1);

  for(x = 0, y = 0; uri[x]; x++, y++) {
    if(is_url_unsafe((unsigned char*) &uri[x])) {
      str[y++] = '%';
      str[y++] = hexchars[(unsigned char) uri[x] >> 4];
      str[y] = hexchars[(unsigned char) uri[x] & 0xf];
    } else str[y]= (unsigned char)uri[x];
  }

  str[y] = '\0';

  return ((char *) str);

}


/**
 * Unescape an url string and remove redundant slashes. The
 * <code>url</code> parameter is modified by this method.
 * @param url an escaped url string
 * @return A pointer to the unescaped <code>url</code>string
 */
char *Util_urlDecode(char *url) {

  register int x,y;

  if(!(url&&*url)) return url;
  Util_replace(url, '+', ' ');
  for(x=0,y=0;url[y];++x,++y) {
    if((url[x] = url[y]) == '%') {
      url[x]= x2c(&url[y+1]);
      y+=2;
    }
    while(url[x] == '/' && url[y+1] == '/') {
      y++;
    }
  }
  url[x]= 0;
  return url;
}


/**
 * @return a Basic Authentication Authorization string (RFC 2617),
 * with credentials from the Run object, NULL if credentials are not defined.
 */
char *Util_getBasicAuthHeaderMonit() {

  Auth_T c = Run.credentials;

  /* We find the first cleartext credential for authorization */
  while (c != NULL) {
    if (c->digesttype == DIGEST_CLEARTEXT)
      break;
    c = c->next;
  }

  if (c)
    return Util_getBasicAuthHeader(c->uname, c->passwd);

  return NULL;
}


/**
 * @return a Basic Authentication Authorization string (RFC 2617),
 * NULL if username is not defined.
 */
char *Util_getBasicAuthHeader(char *username, char *password) {
  char *auth, *b64;
  char  buf[STRLEN];

  if (!username)
    return NULL;
  
  snprintf(buf, STRLEN, "%s:%s", username, password ? password : "");
  if(! (b64= encode_base64(strlen(buf), (unsigned char *)buf)) ) {
      LogError("Failed to base64 encode authentication header\n");
      return NULL;
  }
  auth= xcalloc(sizeof(char), STRLEN+1);
  snprintf(auth, STRLEN, "Authorization: Basic %s\r\n", b64);
  FREE(b64);
  return auth;
}


/**
 * Creates a new String by merging a formated string and a variable
 * argument list. The caller must free the returned String.
 * @param s A format string
 * @return The new String or NULL if the string could not be created
 */
char *Util_getString(const char *s, ...) {

  long l;
  char *v;
  va_list ap;
  
  ASSERT(s);
  
  if(s==NULL)
    return NULL;
  va_start(ap, s);
  v= Util_formatString(s, ap, &l);
  va_end(ap);

  return v;

}


/**
 * Do printf style format line parsing
 * @param s format string
 * @param ap variable argument list
 * @param len The lenght of the bytes written,
 * may be different from the returned allocated buffer size
 * @return buffer with parsed string
 */
char *Util_formatString(const char *s, va_list ap, long *len) {

  int n;
  int size= STRLEN;
  char *buf= xcalloc(sizeof(char), size);
  
#ifdef HAVE_VA_COPY
  va_list ap_copy;
#endif
  
  ASSERT(s);
  
  while(TRUE) {
#ifdef HAVE_VA_COPY
    va_copy(ap_copy, ap);
    n= vsnprintf(buf, size, s, ap_copy);
    va_end(ap_copy);
#else
    n= vsnprintf(buf, size, s, ap);
#endif
    if(n > -1 && n < size)
      break;
    if(n > -1)
      size= n+1;
    else
      size*= 2;
    buf= xresize(buf, size);
  }
  *len= n;
  
  return buf;

}


/**
 * Redirect the standard file descriptors to /dev/null and route any
 * error messages to the log file.
 */
void Util_redirectStdFds() {
  int i;
  for(i= 0; i < 3; i++) {
    if(close(i) == -1 || open("/dev/null", O_RDWR) != i) {
      LogError("Cannot reopen standard file descriptor (%d) -- %s\n", i, STRERROR);
    }
  }
}


/**
 * Close all filedescriptors except standard. Everything
 * seems to have getdtablesize, so we'll use it here, and back
 * out to use 1024 if getdtablesize not available.
 */
void Util_closeFds() {
  int i;
#ifdef HAVE_UNISTD_H
  int max_descriptors = getdtablesize();
#else
  int max_descriptors = 1024;
#endif
  for(i = 3; i < max_descriptors; i++)
    (void) close(i);
  errno= 0;
}


/**
 * Check if monit does have credentials for this user.  If successful
 * a pointer to the password is returned.
 */
Auth_T Util_getUserCredentials(char *uname) {
  Auth_T c;

  /* check allowed user names */
  for (c = Run.credentials; c; c = c->next)
    if (c->uname && IS(c->uname, uname))
      return c;

#ifdef HAVE_LIBPAM
  /* check allowed group names */
  return(PAMcheckUserGroup(uname));
#else
  return NULL;
#endif
}


#ifdef HAVE_LIBPAM
/**
 * PAM conversation
 */
#ifdef SOLARIS
static int PAMquery(int num_msg, struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
#else
static int PAMquery(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
#endif
  int i;
  struct ad_user *user = (struct ad_user *)appdata_ptr;
  struct pam_response *response;

  /* Sanity checking */
  if (!msg || !resp || !user )
    return PAM_CONV_ERR;

  response = xcalloc(sizeof(struct pam_response), num_msg);

  for (i = 0; i < num_msg; i++) {
    response[i].resp = NULL;
    response[i].resp_retcode = 0;

    switch ((*(msg[i])).msg_style) {
    case PAM_PROMPT_ECHO_ON:
      /* Store the login as the response. This likely never gets called, since login was on pam_start() */
      response[i].resp= appdata_ptr ? xstrdup(user->login) : NULL;
      break;

    case PAM_PROMPT_ECHO_OFF:
      /* Store the password as the response */
      response[i].resp= appdata_ptr ? xstrdup(user->passwd) : NULL;
      break;

    case PAM_TEXT_INFO:
    case PAM_ERROR_MSG:
      /* Shouldn't happen since we have PAM_SILENT set. If it happens anyway, ignore it. */
      break;

    default:
      /* Something strange... */
      if (response != NULL)
        FREE(response);
      return PAM_CONV_ERR;
    }
  }
  /* On success, return the response structure */
  *resp = response;
  return PAM_SUCCESS;
}


/**
 * Validate login/passwd via PAM service "monit"
 */
static int PAMcheckPasswd(const char *login, const char *passwd) {
  int rv;
  pam_handle_t *pamh = NULL;
  struct ad_user user_info = {
    login,
    passwd
  };
  struct pam_conv conv = {
    PAMquery,
    &user_info
  };

  if ((rv = pam_start("monit", login, &conv, &pamh) != PAM_SUCCESS)) {
    DEBUG("PAM authentication start failed -- %d\n", rv);
    return FALSE;
  }

  rv = pam_authenticate(pamh, PAM_SILENT);

  if (pam_end(pamh, rv) != PAM_SUCCESS)
     pamh = NULL;

  return(rv == PAM_SUCCESS ? TRUE : FALSE);
}


/**
 * Check whether the user is member of allowed groups
 */
static Auth_T PAMcheckUserGroup(const char *uname) {
  Auth_T c = Run.credentials;
  struct passwd *pwd = NULL; 
  struct group  *grp = NULL;

  ASSERT(uname);

  if (!(pwd = getpwnam(uname)))
    return NULL;

  if (!(grp = getgrgid(pwd->pw_gid)))
    return NULL;

  while (c) {
    if (c->groupname) {
      struct group *sgrp = NULL;

      /* check for primary group match */
      if (IS(c->groupname, grp->gr_name))
        return c;

      /* check secondary groups match */
      if ((sgrp = getgrnam(c->groupname))) {
        char **g = NULL;

        for (g = sgrp->gr_mem; *g; g++)
          if (IS(*g, uname))
            return c;
      }
    }
    c = c->next;
  }
  return NULL;
}
#endif


/**
 * Check if the given password match the registred password for the
 * given username. 
 * @param uname Username
 * @param outside The password to test
 * @return TRUE if the passwords match for the given uname otherwise
 * FALSE
 */
int Util_checkCredentials(char *uname, char *outside) {
  Auth_T c= Util_getUserCredentials(uname);
  char outside_crypt[STRLEN];
  if(c==NULL) {
    return FALSE;
  }
  switch (c->digesttype) {
    case DIGEST_CLEARTEXT:
      outside_crypt[sizeof(outside_crypt) - 1] = 0;
      strncpy(outside_crypt, outside, sizeof(outside_crypt) - 1); 
      break;
    case DIGEST_MD5:
    {
      char id[STRLEN];
      char salt[STRLEN];
      char *temp;
      /* A password looks like this,
       *   $id$salt$digest
       * the '$' around the id are still part of the id. 
       */
      id[sizeof(id) - 1] = 0;
      strncpy(id, c->passwd, sizeof(id) - 1);
      if(! (temp= strchr(id+1, '$'))) {
        LogError("Password not in MD5 format.\n");
	return FALSE;
      }
      temp += 1;
      *temp= '\0';
      salt[sizeof(salt) - 1] = 0;
      strncpy(salt, c->passwd+strlen(id), sizeof(salt) - 1);
      if(! (temp= strchr(salt, '$'))) {
        LogError("Password not in MD5 format.\n");
	return FALSE;
      }
      *temp= '\0';
      if (md5_crypt(outside, id, salt, outside_crypt, STRLEN) == NULL) {
	LogError("Cannot generate MD5 digest error.\n");
	return FALSE;
      }
      break;
    }
    case DIGEST_CRYPT:
    {
      char salt[3];
      char * temp;
      snprintf(salt, 3, "%c%c", c->passwd[0], c->passwd[1]);
      temp= crypt(outside, salt);
      outside_crypt[sizeof(outside_crypt) - 1] = 0;
      strncpy(outside_crypt, temp, sizeof(outside_crypt) - 1); 
      break;
    }
#ifdef HAVE_LIBPAM
    case DIGEST_PAM:
      return PAMcheckPasswd(uname, outside);
      break;
#endif
    default:
      LogError("Unknown password digestion method.\n");
      return FALSE;
  }

  if (strcmp(outside_crypt,c->passwd)==0) {
    return TRUE;
  }
  return FALSE;
}


/**
 * Compute SHA1 and MD5 message digests simultaneously for bytes read
 * from STREAM (suitable for stdin, which is not always rewindable).
 * The resulting message digest numbers will be written into the first
 * bytes of resblock buffers.
 * @param stream The stream from where the digests are computed
 * @param sha_resblock The buffer to write the SHA1 result to
 * @param md5_resblock The buffer to write the MD5 result to
 */
int Util_getStreamDigests (FILE *stream, void *sha_resblock, void *md5_resblock) {
#define HASHBLOCKSIZE 4096 /* Important: must be a multiple of 64.  */
  struct sha_ctx ctx_sha;
  struct md5_ctx ctx_md5;
  char buffer[HASHBLOCKSIZE + 72];
  size_t sum;
  
  /* Initialize the computation contexts.  */
  sha_init_ctx (&ctx_sha);
  md5_init_ctx (&ctx_md5);
  
  /* Iterate over full file contents.  */
  while (1)  {
    /* We read the file in blocks of HASHBLOCKSIZE bytes.  One call of the
       computation function processes the whole buffer so that with the
       next round of the loop another block can be read.  */
    size_t n;
    sum = 0;
    
    /* Read block.  Take care for partial reads.  */
    while (1) {
      n = fread (buffer + sum, 1, HASHBLOCKSIZE - sum, stream);
      sum += n;
      if (sum == HASHBLOCKSIZE)
	break;
      if (n == 0) {
	/* Check for the error flag IFF N == 0, so that we don't
	   exit the loop after a partial read due to e.g., EAGAIN
	   or EWOULDBLOCK.  */
	if (ferror (stream))
	  return 1;
	goto process_partial_block;
      }
      
      /* We've read at least one byte, so ignore errors.  But always
	 check for EOF, since feof may be true even though N > 0.
	 Otherwise, we could end up calling fread after EOF.  */
      if (feof (stream))
	goto process_partial_block;
    }

    /* Process buffer with HASHBLOCKSIZE bytes.  Note that
       HASHBLOCKSIZE % 64 == 0 */
    sha_process_block (buffer, HASHBLOCKSIZE, &ctx_sha);
    md5_process_block (buffer, HASHBLOCKSIZE, &ctx_md5);
  }

process_partial_block:

  /* Process any remaining bytes.  */
  if (sum > 0) {
    sha_process_bytes (buffer, sum, &ctx_sha);
    md5_process_bytes (buffer, sum, &ctx_md5);
  }
  /* Construct result in desired memory.  */
  sha_finish_ctx (&ctx_sha, sha_resblock);
  md5_finish_ctx (&ctx_md5, md5_resblock);
  return 0;
}


/**
 * Reset the service information structure
 */
void Util_resetInfo(Service_T s) {
  FREE(s->inf->cs_sum);
  memset(s->inf, 0, sizeof *(s->inf));
  s->inf->_pid=        -1;
  s->inf->_ppid=       -1;
  s->inf->_flags=      -1;
  s->inf->pid=         -1;
  s->inf->ppid=        -1;
  s->inf->flags=       -1;
  s->inf->st_ino_prev=  0;
  s->inf->readpos=      0;
}


/**
 * Are service status data available?
 * @param s The service to test
 * @return TRUE if available otherwise FALSE
 */
int Util_hasServiceStatus(Service_T s) {
  return(!((s->monitor!=MONITOR_YES)||
	   (s->error&EVENT_NONEXIST)||
	   (s->error&EVENT_DATA) ));
}


/**
 * Construct a HTTP/1.1 Host header utilizing information from the
 * socket. The returned hostBuf is set to "hostname" or "hostname:port".
 * if port is not equal to the default HTTP port number
 * @param s A connected socket 
 * @param hostBuf the buffer to write the host-header to
 * @param len Length of the hostBuf
 * @return the hostBuffer
 */
char *Util_getHTTPHostHeader(Socket_T s, char *hostBuf, int len) {
  if(socket_get_remote_port(s)==80)
    snprintf(hostBuf, len, "%s", socket_get_remote_host(s));
  else
    snprintf(hostBuf, len, "%s:%d", socket_get_remote_host(s), socket_get_remote_port(s));
  return hostBuf;
}


/**
 * Evaluate a qualification expression. 
 * @param operator The qualification operator
 * @param left Expression lval
 * @param rightExpression rval
 * Returns the boolean value of the expression
 */
int Util_evalQExpression(int operator, long long left, long long right) {

  switch(operator) {
  case OPERATOR_GREATER:
      if(left > right)
	  return TRUE;
      break;
  case OPERATOR_LESS:
      if(left < right)
	  return TRUE;
      break;
  case OPERATOR_EQUAL:
      if(left == right)
	  return TRUE;
      break;
  case OPERATOR_NOTEQUAL:
      if(left != right)
	  return TRUE;
      break;
  default:
      LogError("Unknown comparison operator\n");
      return FALSE;
  }

  return FALSE;
    
}


/*
 * This will enable service monitoring in the case that it was disabled.
 * @param s A Service_T object
 */
void Util_monitorSet(Service_T s) {

  ASSERT(s);

  if(s->monitor == MONITOR_NOT)
  {
    s->monitor= MONITOR_INIT;
    DEBUG("Monitoring enabled -- service %s\n", s->name);
  }
}


/*
 * This will disable service monitoring in the case that it is enabled
 * @param s A Service_T object
 */
void Util_monitorUnset(Service_T s) {

  ASSERT(s);

  if(s->monitor != MONITOR_NOT)
  {
    s->monitor= MONITOR_NOT;
    DEBUG("Monitoring disabled -- service %s\n", s->name);
  }
  s->nstart= 0;
  s->ncycle= 0;
  s->error = EVENT_NULL;
  if(s->eventlist)
    gc_event(&s->eventlist);
  Util_resetInfo(s);
}


/*
 * Retun appropriate action id for string
 * @param action A action string
 * @return the action id
 */
int Util_getAction(const char *action) {

  /* the ACTION_IGNORE has index 0 => we will start on next item */
  int   i = 1;

  ASSERT(action);

  while(strlen(actionnames[i]))
  {
    if(IS(action, actionnames[i]))
    {
      /* supported action found */
      return i;
    }
    i++;
  }
  /* the action was not found */
  return ACTION_IGNORE;
}


/**
 * Print event ratio needed to trigger the action to the buffer
 * @param action A action string
 * @return the action id
 */
char *Util_getEventratio(Action_T action, char *buf) {
  snprintf(buf, STRLEN,
    "%d times within %d cycle(s)",
    action->count, action->cycles);

  return buf;
}


/**
 * Print port type description
 * @param p A port structure
 * @return the socket type description
 */
char *Util_portTypeDescription(Port_T p) {
  switch(p->type) {
    case SOCK_STREAM:
      return p->SSL.use_ssl?"TCPSSL":"TCP";
    case SOCK_DGRAM:
      return "UDP";
    default:
      return "UNKNOWN";
  }
}


/* ----------------------------------------------------------------- Private */


/**
 * Returns the value of the parameter if defined or the String "(not
 * defined)"
 */
static char *is_str_defined(char *s) {
  return ((s&&*s)?s:"(not defined)");
}


/**
 * Returns TRUE if the given char is url unsafe
 * @param c A unsigned char
 * @return TRUE if the char is in the set of unsafe URL Characters
 */
static int is_url_unsafe(unsigned char *c) {
  int i;
  static unsigned char unsafe[]= "<>\"#{}|\\^~[]`";
  
  ASSERT(c);
  
  if(33>*c || *c>176)
    return TRUE;
  if(*c=='%') {
    if( isxdigit(*(c + 1)) && isxdigit(*(c + 2)) ) return FALSE;
    return TRUE;
  }
  for(i=0; unsafe[i]; i++)
    if(*c==unsafe[i]) return TRUE;
  return FALSE;
}


/**
 * Convert a hex char to a char
 */
static char x2c(char *hex) {
  register char digit;
  digit = ((hex[0] >= 'A') ? ((hex[0] & 0xdf) - 'A')+10 : (hex[0] - '0'));
  digit *= 16;
  digit += (hex[1] >= 'A' ? ((hex[1] & 0xdf) - 'A')+10 : (hex[1] - '0'));
  return(digit);
}


/**
 * Print registered events list
 */
static void printevents(unsigned int events) {
  if(events == EVENT_NULL) {
    printf("No events");
  } else if(events == EVENT_ALL) {
    printf("All events");
  } else {
    if(IS_EVENT_SET(events, EVENT_ACTION))
      printf("Action ");
    if(IS_EVENT_SET(events, EVENT_CHECKSUM))
      printf("Checksum ");
    if(IS_EVENT_SET(events, EVENT_CONNECTION))
      printf("Connection ");
    if(IS_EVENT_SET(events, EVENT_CONTENT))
      printf("Content ");
    if(IS_EVENT_SET(events, EVENT_DATA))
      printf("Data ");
    if(IS_EVENT_SET(events, EVENT_EXEC))
      printf("Exec ");
    if(IS_EVENT_SET(events, EVENT_FSFLAG))
      printf("Fsflags ");
    if(IS_EVENT_SET(events, EVENT_GID))
      printf("Gid ");
    if(IS_EVENT_SET(events, EVENT_ICMP))
      printf("Icmp ");
    if(IS_EVENT_SET(events, EVENT_INSTANCE))
      printf("Instance ");
    if(IS_EVENT_SET(events, EVENT_INVALID))
      printf("Invalid ");
    if(IS_EVENT_SET(events, EVENT_NONEXIST))
      printf("Nonexist ");
    if(IS_EVENT_SET(events, EVENT_PERMISSION))
      printf("Permission ");
    if(IS_EVENT_SET(events, EVENT_PID))
      printf("PID ");
    if(IS_EVENT_SET(events, EVENT_PPID))
      printf("PPID ");
    if(IS_EVENT_SET(events, EVENT_RESOURCE))
      printf("Resource ");
    if(IS_EVENT_SET(events, EVENT_SIZE))
      printf("Size ");
    if(IS_EVENT_SET(events, EVENT_TIMEOUT))
      printf("Timeout ");
    if(IS_EVENT_SET(events, EVENT_TIMESTAMP))
    printf("Timestamp ");
    if(IS_EVENT_SET(events, EVENT_UID))
      printf("Uid ");
  }
  printf("\n");
}

