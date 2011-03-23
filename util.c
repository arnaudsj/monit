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

#ifdef HAVE_NETDB_H
#include <netdb.h>
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


/* Unsafe URL characters: <>\"#%{}|\\^[] ` */
static const unsigned char urlunsafe[256] = {
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
        1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 
};


static const unsigned char b2x[][256] = {
        "00", "01", "02", "03", "04", "05", "06", "07", 
        "08", "09", "0A", "0B", "0C", "0D", "0E", "0F", 
        "10", "11", "12", "13", "14", "15", "16", "17", 
        "18", "19", "1A", "1B", "1C", "1D", "1E", "1F", 
        "20", "21", "22", "23", "24", "25", "26", "27", 
        "28", "29", "2A", "2B", "2C", "2D", "2E", "2F", 
        "30", "31", "32", "33", "34", "35", "36", "37", 
        "38", "39", "3A", "3B", "3C", "3D", "3E", "3F", 
        "40", "41", "42", "43", "44", "45", "46", "47", 
        "48", "49", "4A", "4B", "4C", "4D", "4E", "4F", 
        "50", "51", "52", "53", "54", "55", "56", "57", 
        "58", "59", "5A", "5B", "5C", "5D", "5E", "5F", 
        "60", "61", "62", "63", "64", "65", "66", "67", 
        "68", "69", "6A", "6B", "6C", "6D", "6E", "6F", 
        "70", "71", "72", "73", "74", "75", "76", "77", 
        "78", "79", "7A", "7B", "7C", "7D", "7E", "7F",
        "80", "81", "82", "83", "84", "85", "86", "87", 
        "88", "89", "8A", "8B", "8C", "8D", "8E", "8F",
        "90", "91", "92", "93", "94", "95", "96", "97", 
        "98", "99", "9A", "9B", "9C", "9D", "9E", "9F", 
        "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", 
        "A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF", 
        "B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7", 
        "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF", 
        "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7", 
        "C8", "C9", "CA", "CB", "CC", "CD", "CE", "CF",
        "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", 
        "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF", 
        "E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7", 
        "E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF", 
        "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7", 
        "F8", "F9", "FA", "FB", "FC", "FD", "FE", "FF"
};


/**
 *  General purpose utility methods.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author "Martin Pala" <martinp@tildeslash.com>
 *  @author Christian Hopp <chopp@iei.tu-clausthal.de>
 *  @author Michael Amster, <mamster@webeasy.com> 
 *
 *  @file
 */


/* ------------------------------------------------------------------ Public */


char *Util_basename(char* path) {
  char *fname;

  ASSERT(path);

  fname= strrchr(path, '/');
  return(fname ? ++fname : path);
}


char *Util_chomp(char *s) {
  ASSERT(s);
  
  for (; *s; s++) {
    if (('\r' == *s) || ('\n' == *s)) {
      *s= 0; break;
    }
  }
  return s;
}


char *Util_trim(char *s) {
  ASSERT(s);
  
  Util_ltrim(s);
  Util_rtrim(s);
  return s;
}


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


char *Util_rtrim(char *s) {
  char *t= s;

  ASSERT(s);

  while(*s) s++;
  while(*--s==' ' || *s=='\t' || *s=='\r' || *s=='\n') *s= 0;
  return t;
}


void Util_trimQuotes(char *s) {
  char *t= s;
  char tmp=0;

  ASSERT(s);

  if(*t==39 || *t==34 ) {
    tmp=*t;
    t++;
  } else
    return;
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


char *Util_replace(char *s, char old, char new) {
  char *t= s;

  while (s&&*s) { if(*s==old) *s=new; s++; }
  return (t);
}


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


int Util_countWords(char *s, const char *word) {
  int i= 0;
  char *p= s;

  ASSERT(s && word);
  
  while((p= strstr(p, word))) { i++;  p++; }
  return i;
}


int Util_startsWith(const char *a, const char *b) {
  if((!a || !b) || toupper((int)*a)!=toupper((int)*b)) return FALSE;
  while(*a && *b)
    if(toupper((int)*a++) != toupper((int)*b++))
      return FALSE;
  return TRUE;
}


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


int Util_getNumberOfServices() {
  int i= 0;
  Service_T s;
  for(s= servicelist; s; s= s->next) i+=1;
  return i;
}


int Util_existService(const char *name) {
  ASSERT(name);
  return Util_getService(name)?TRUE:FALSE;
}


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
    Mmonit_T c;
    printf(" %-18s = ", "M/Monit(s)");
    for(c= Run.mmonits; c; c= c->next) {
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
    if (! Run.dommonitcredentials)
      printf("\n                      register without credentials");
    printf("\n");
  }

  if(Run.mailservers) {
    MailServer_T mta;
    printf(" %-18s = ", "Mail server(s)");
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


void Util_printService(Service_T s) {
  int sgheader = FALSE;
  Port_T n;
  Icmp_T i;
  Mail_T r;
  Filesystem_T dl;
  Resource_T q;
  Timestamp_T t;
  ActionRate_T ar;
  Size_T sl;
  Match_T ml;
  Dependant_T d;
  ServiceGroup_T sg;
  ServiceGroupMember_T sgm;
  char buf[STRLEN];

  ASSERT(s);
 
  snprintf(buf, sizeof(buf), "%s Name", servicetypes[s->type]);
  printf("%-21s = %s\n", buf, s->name);

  for (sg = servicegrouplist; sg; sg = sg->next) {
    for (sgm = sg->members; sgm; sgm = sgm->next) {
      if (! strcasecmp(sgm->name, s->name)) {
        if (! sgheader) {
          printf(" %-20s = %s", "Group", sg->name);
          sgheader = TRUE;
        } else
          printf(", %s", sg->name);
      }
    }
  }
  if (sgheader)
    printf("\n");

  if(s->type == TYPE_PROCESS) {
    if (s->matchlist)
      printf(" %-20s = %s\n", "Match", s->path);
    else
      printf(" %-20s = %s\n", "Pid file", s->path);
  } else if(s->type != TYPE_HOST && s->type != TYPE_SYSTEM) {
    printf(" %-20s = %s\n", "Path", s->path);
  }
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

  if(s->type != TYPE_SYSTEM) {
    printf(" %-20s = ", "Existence");
    printf("if does not exist %s ", Util_getEventratio(s->action_NONEXIST->failed, buf, sizeof(buf)));
    printf("then %s ", Util_describeAction(s->action_NONEXIST->failed, buf, sizeof(buf)));
    printf("else if succeeded %s ", Util_getEventratio(s->action_NONEXIST->succeeded, buf, sizeof(buf)));
    printf("then %s", Util_describeAction(s->action_NONEXIST->succeeded, buf, sizeof(buf)));
    printf("\n");
  }

  for(d= s->dependantlist; d; d= d->next)
    if(d->dependant != NULL)
      printf(" %-20s = %s\n", "Depends on Service", d->dependant);

  if(s->type == TYPE_PROCESS) {
    printf(" %-20s = ", "Pid");
    printf("if changed %s ", Util_getEventratio(s->action_PID->failed, buf, sizeof(buf)));
    printf("then %s", Util_describeAction(s->action_PID->failed, buf, sizeof(buf)));
    printf("\n");

    printf(" %-20s = ", "Ppid");
    printf("if changed %s ", Util_getEventratio(s->action_PPID->failed, buf, sizeof(buf)));
    printf("then %s", Util_describeAction(s->action_PPID->failed, buf, sizeof(buf)));
    printf("\n");
  }

  if(s->type == TYPE_FILESYSTEM) {
    printf(" %-20s = ", "Filesystem flags");
    printf("if changed %s ", Util_getEventratio(s->action_FSFLAG->failed, buf, sizeof(buf)));
    printf("then %s", Util_describeAction(s->action_FSFLAG->failed, buf, sizeof(buf)));
    printf("\n");
  }

  if(s->checksum && s->checksum->action) {
    Checksum_T cs= s->checksum;
    EventAction_T a= cs->action;
    printf(" %-20s = ", "Checksum");
    if(cs->test_changes) {
      printf("if changed %s %s ", checksumnames[cs->type], Util_getEventratio(a->failed, buf, sizeof(buf)));
      printf("then %s", Util_describeAction(a->failed, buf, sizeof(buf)));
    } else {
      printf("if failed %s(%s) %s ", cs->hash, checksumnames[cs->type], Util_getEventratio(a->failed, buf, sizeof(buf)));
      printf("then %s ", Util_describeAction(a->failed, buf, sizeof(buf)));
      printf("else if succeeded %s ", Util_getEventratio(a->succeeded, buf, sizeof(buf)));
      printf("then %s", Util_describeAction(a->succeeded, buf, sizeof(buf)));
    }
    printf("\n");
  }
  
  if(s->perm && s->perm->action) {
    EventAction_T a= s->perm->action;
    printf(" %-20s = ", "Permission");
    printf("if failed %04o %s ", s->perm->perm, Util_getEventratio(a->failed, buf, sizeof(buf)));
    printf("then %s ", Util_describeAction(a->failed, buf, sizeof(buf)));
    printf("else if succeeded %s ", Util_getEventratio(a->succeeded, buf, sizeof(buf)));
    printf("then %s", Util_describeAction(a->succeeded, buf, sizeof(buf)));
    printf("\n");
  }

  if(s->uid && s->uid->action) {
    EventAction_T a= s->uid->action;
    printf(" %-20s = ", "UID");
    printf("if failed %d %s ", (int)s->uid->uid, Util_getEventratio(a->failed, buf, sizeof(buf)));
    printf("then %s ", Util_describeAction(a->failed, buf, sizeof(buf)));
    printf("else if succeeded %s ", Util_getEventratio(a->succeeded, buf, sizeof(buf)));
    printf("then %s", Util_describeAction(a->succeeded, buf, sizeof(buf)));
    printf("\n");
  }

  if(s->gid && s->gid->action) {
    EventAction_T a= s->gid->action;
    printf(" %-20s = ", "GID");
    printf("if failed %d %s ", (int)s->gid->gid, Util_getEventratio(a->failed, buf, sizeof(buf)));
    printf("then %s ", Util_describeAction(a->failed, buf, sizeof(buf)));
    printf("else if succeeded %s ", Util_getEventratio(a->succeeded, buf, sizeof(buf)));
    printf("then %s", Util_describeAction(a->succeeded, buf, sizeof(buf)));
    printf("\n");
  }

  if(s->icmplist)
    for(i= s->icmplist; i; i= i->next) {
      EventAction_T a= i->action;
      printf(" %-20s = ", "ICMP");
      printf("if failed %s count %d with timeout %d seconds %s ", icmpnames[i->type], i->count, i->timeout, Util_getEventratio(a->failed, buf, sizeof(buf)));
      printf("then %s ", Util_describeAction(a->failed, buf, sizeof(buf)));
      printf("else if succeeded %s ", Util_getEventratio(a->succeeded, buf, sizeof(buf)));
      printf("then %s", Util_describeAction(a->succeeded, buf, sizeof(buf)));
      printf("\n");
    }

  if(s->portlist) {
    for(n= s->portlist; n; n= n->next) {
      EventAction_T a= n->action;
      if(n->family == AF_INET) {
        printf(" %-20s = ", "Port");
        printf("if failed %s:%d%s [%s via %s] with timeout %d seconds %s ", n->hostname, n->port, n->request ? n->request : "", n->protocol->name, Util_portTypeDescription(n), n->timeout, Util_getEventratio(a->failed, buf, sizeof(buf)));
        printf("then %s ", Util_describeAction(a->failed, buf, sizeof(buf)));
        printf("else if succeeded %s ", Util_getEventratio(a->succeeded, buf, sizeof(buf)));
        printf("then %s", Util_describeAction(a->succeeded, buf, sizeof(buf)));
        printf("\n");
        if(n->SSL.certmd5 != NULL)
          printf(" %-20s = %s\n", "Server cert md5 sum", n->SSL.certmd5);
      } else if(n->family == AF_UNIX) {
        printf(" %-20s = ", "Unix Socket");
        printf("if failed %s [protocol %s] with timeout %d seconds %s ", n->pathname, n->protocol->name, n->timeout, Util_getEventratio(a->failed, buf, sizeof(buf)));
        printf("then %s ", Util_describeAction(a->failed, buf, sizeof(buf)));
        printf("else if succeeded %s ", Util_getEventratio(a->succeeded, buf, sizeof(buf)));
        printf("then %s", Util_describeAction(a->succeeded, buf, sizeof(buf)));
        printf("\n");
      }
    }
  }
  
  for(t= s->timestamplist; t; t= t->next) {
    EventAction_T a= t->action;
    printf(" %-20s = ", "Timestamp");
    if(t->test_changes) {
      printf("if changed %s ", Util_getEventratio(a->failed, buf, sizeof(buf)));
      printf("then %s", Util_describeAction(a->failed, buf, sizeof(buf)));
    } else {
      printf("if %s %d second(s) %s ", operatornames[t->operator], t->time, Util_getEventratio(a->failed, buf, sizeof(buf)));
      printf("then %s ", Util_describeAction(a->failed, buf, sizeof(buf)));
      printf("else if succeeded %s ", Util_getEventratio(a->succeeded, buf, sizeof(buf)));
      printf("then %s", Util_describeAction(a->succeeded, buf, sizeof(buf)));
    }
    printf("\n");
  }

  for(sl= s->sizelist; sl; sl= sl->next) {
    EventAction_T a= sl->action;
    printf(" %-20s = ", "Size");
    if(sl->test_changes) {
      printf("if changed %s ", Util_getEventratio(a->failed, buf, sizeof(buf)));
      printf("then %s", Util_describeAction(a->failed, buf, sizeof(buf)));
    } else {
      printf("if %s %llu byte(s) %s ", operatornames[sl->operator], sl->size, Util_getEventratio(a->failed, buf, sizeof(buf)));
      printf("then %s ", Util_describeAction(a->failed, buf, sizeof(buf)));
      printf("else if succeeded %s ", Util_getEventratio(a->succeeded, buf, sizeof(buf)));
      printf("then %s", Util_describeAction(a->succeeded, buf, sizeof(buf)));
    }
    printf("\n");
    
  }

  if (s->type != TYPE_PROCESS) {
    for(ml= s->matchlist; ml; ml= ml->next) {
      EventAction_T a= ml->action;
      printf(" %-20s = ", "Regex");
      printf("if%s match \"%s\" %s ", ml->not ? " not" : "", ml->match_string, Util_getEventratio(a->failed, buf, sizeof(buf)));
      printf("then %s", Util_describeAction(a->failed, buf, sizeof(buf)));
      printf("\n");
    }
  }
  
  for(dl= s->filesystemlist; dl; dl= dl->next) {
    EventAction_T a= dl->action;
    if(dl->resource == RESOURCE_ID_INODE) {
      printf(" %-20s = ", "Inodes usage limit");
      if(dl->limit_absolute > -1) {
        printf("if %s %ld %s ", operatornames[dl->operator], dl->limit_absolute, Util_getEventratio(a->failed, buf, sizeof(buf)));
        printf("then %s ", Util_describeAction(a->failed, buf, sizeof(buf)));
        printf("else if succeeded %s ", Util_getEventratio(a->succeeded, buf, sizeof(buf)));
        printf("then %s", Util_describeAction(a->succeeded, buf, sizeof(buf)));
      } else {
        printf("if %s %.1f%% %s ", operatornames[dl->operator], dl->limit_percent / 10., Util_getEventratio(a->failed, buf, sizeof(buf)));
        printf("then %s ", Util_describeAction(a->failed, buf, sizeof(buf)));
        printf("else if succeeded %s ", Util_getEventratio(a->succeeded, buf, sizeof(buf)));
        printf("then %s", Util_describeAction(a->succeeded, buf, sizeof(buf)));
      }
      printf("\n");
    } else if(dl->resource == RESOURCE_ID_SPACE) {
      printf(" %-20s = ", "Space usage limit");
      if(dl->limit_absolute > -1) {
        printf("if %s %ld blocks %s ", operatornames[dl->operator], dl->limit_absolute, Util_getEventratio(a->failed, buf, sizeof(buf)));
        printf("then %s ", Util_describeAction(a->failed, buf, sizeof(buf)));
        printf("else if succeeded %s ", Util_getEventratio(a->succeeded, buf, sizeof(buf)));
        printf("then %s", Util_describeAction(a->succeeded, buf, sizeof(buf)));
      } else {
        printf("if %s %.1f%% %s ", operatornames[dl->operator], dl->limit_percent / 10., Util_getEventratio(a->failed, buf, sizeof(buf)));
        printf("then %s ", Util_describeAction(a->failed, buf, sizeof(buf)));
        printf("else if succeeded %s ", Util_getEventratio(a->succeeded, buf, sizeof(buf)));
        printf("then %s", Util_describeAction(a->succeeded, buf, sizeof(buf)));
      }
      printf("\n");
    }
  }

  for(q= s->resourcelist; q; q= q->next) {
    EventAction_T a= q->action;
    switch(q->resource_id) {
      case RESOURCE_ID_CPU_PERCENT: 
        printf(" %-20s = ", "CPU usage limit");
        break;

      case RESOURCE_ID_TOTAL_CPU_PERCENT: 
        printf(" %-20s = ", "CPU usage limit (incl. children)");
        break;

      case RESOURCE_ID_CPUUSER: 
        printf(" %-20s = ", "CPU user limit");
        break;

      case RESOURCE_ID_CPUSYSTEM: 
        printf(" %-20s = ", "CPU system limit");
        break;

      case RESOURCE_ID_CPUWAIT: 
        printf(" %-20s = ", "CPU wait limit");
        break;

      case RESOURCE_ID_MEM_PERCENT: 
        printf(" %-20s = ", "Memory usage limit");
        break;

      case RESOURCE_ID_MEM_KBYTE: 
        printf(" %-20s = ", "Memory amount limit");
        break;

      case RESOURCE_ID_SWAP_PERCENT: 
        printf(" %-20s = ", "Swap usage limit");
        break;

      case RESOURCE_ID_SWAP_KBYTE: 
        printf(" %-20s = ", "Swap amount limit");
        break;

      case RESOURCE_ID_LOAD1: 
        printf(" %-20s = ", "Load avg. (1min)");
        break;

      case RESOURCE_ID_LOAD5: 
        printf(" %-20s = ", "Load avg. (5min)");
        break;

      case RESOURCE_ID_LOAD15: 
        printf(" %-20s = ", "Load avg. (15min)");
        break;

      case RESOURCE_ID_CHILDREN:
        printf(" %-20s = ", "Children");
        break;

      case RESOURCE_ID_TOTAL_MEM_KBYTE:
        printf(" %-20s = ", "Memory amount limit (incl. children)");
        break;

      case RESOURCE_ID_TOTAL_MEM_PERCENT:
        printf(" %-20s = ", "Memory usage limit (incl. children)");
        break;
    }
    switch(q->resource_id) {
      case RESOURCE_ID_CPU_PERCENT: 
      case RESOURCE_ID_TOTAL_CPU_PERCENT: 
      case RESOURCE_ID_TOTAL_MEM_PERCENT:
      case RESOURCE_ID_CPUUSER: 
      case RESOURCE_ID_CPUSYSTEM: 
      case RESOURCE_ID_CPUWAIT: 
      case RESOURCE_ID_MEM_PERCENT: 
      case RESOURCE_ID_SWAP_PERCENT: 
        printf("if %s %.1f%% %s ", operatornames[q->operator], q->limit / 10.0, Util_getEventratio(a->failed, buf, sizeof(buf)));
        printf("then %s ", Util_describeAction(a->failed, buf, sizeof(buf)));
        printf("else if succeeded %s ", Util_getEventratio(a->succeeded, buf, sizeof(buf)));
        printf("then %s", Util_describeAction(a->succeeded, buf, sizeof(buf)));
        break;

      case RESOURCE_ID_MEM_KBYTE: 
      case RESOURCE_ID_SWAP_KBYTE: 
        printf("if %s %ldkB %s ", operatornames[q->operator], q->limit, Util_getEventratio(a->failed, buf, sizeof(buf)));
        printf("then %s ", Util_describeAction(a->failed, buf, sizeof(buf)));
        printf("else if succeeded %s ", Util_getEventratio(a->succeeded, buf, sizeof(buf)));
        printf("then %s", Util_describeAction(a->succeeded, buf, sizeof(buf)));
        break;

      case RESOURCE_ID_LOAD1: 
      case RESOURCE_ID_LOAD5: 
      case RESOURCE_ID_LOAD15: 
        printf("if %s %.1f %s ", operatornames[q->operator], q->limit / 10.0, Util_getEventratio(a->failed, buf, sizeof(buf)));
        printf("then %s ", Util_describeAction(a->failed, buf, sizeof(buf)));
        printf("else if succeeded %s ", Util_getEventratio(a->succeeded, buf, sizeof(buf)));
        printf("then %s", Util_describeAction(a->succeeded, buf, sizeof(buf)));
        break;

      case RESOURCE_ID_CHILDREN:
      case RESOURCE_ID_TOTAL_MEM_KBYTE:
        printf("if %s %ld %s ", operatornames[q->operator], q->limit, Util_getEventratio(a->failed, buf, sizeof(buf)));
        printf("then %s ", Util_describeAction(a->failed, buf, sizeof(buf)));
        printf("else if succeeded %s ", Util_getEventratio(a->succeeded, buf, sizeof(buf)));
        printf("then %s", Util_describeAction(a->succeeded, buf, sizeof(buf)));
        break;
    }
    printf("\n");
  }

  if(s->def_every)
    printf(" %-20s = Check service every %d cycles\n", "Every", s->every);
  
  for (ar = s->actionratelist; ar; ar = ar->next)
    printf(" %-20s = If restarted %d times within %d cycle(s) then %s\n", "Timeout", ar->count, ar->cycle, Util_describeAction(ar->action->failed, buf, sizeof(buf)));

  for(r= s->maillist; r; r= r->next) {
    printf(" %-20s = %s\n", "Alert mail to", is_str_defined(r->to));
    printf("   %-18s = ", "Alert on");
    printevents(r->events);
    if(r->reminder)
      printf("   %-18s = %u cycles\n", "Alert reminder", r->reminder);
  }

  printf("\n");
  
}


void Util_printServiceList() {
  Service_T s;
  char ruler[STRLEN];
  
  printf("The service list contains the following entries:\n\n");
  
  for(s= servicelist_conf; s; s= s->next_conf)
    Util_printService(s);

  memset(ruler, '-', STRLEN);
  printf("%-.79s\n", ruler);
}


void Util_printHash(char *filename) {
  unsigned char buf[STRLEN], buf2[STRLEN];
  FILE *fhandle = NULL;
  int i;

  if (! (fhandle = filename ? fopen(filename, "r") : stdin))
    goto fileerror;
  if (Util_getStreamDigests(fhandle, buf, buf2))
    goto fileerror;
  if (filename && fclose(fhandle))
    goto fileerror;

  /* SHA1 */
  printf("SHA1(%s) = ", filename ? filename : "stdin");
  for (i = 0; i < 20; i++)
    printf("%02x", buf[i]);
  printf("\n");

  /* MD5 */
  printf("MD5(%s)  = ", filename ? filename : "stdin");
  for (i = 0; i < 16; i++)
    printf("%02x", buf2[i]);
  printf("\n");

  return;

fileerror:

  printf("monit: %s: %s\n", filename, STRERROR);
  exit(1);
}


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
      if (fclose(file))
        LogError("%s: Error closing file '%s' -- %s\n", prog, idfile, STRERROR);
      return NULL;
    }
  }
  if (fclose(file))
    LogError("%s: Error closing file '%s' -- %s\n", prog, idfile, STRERROR);

  return Run.id;
}


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
  if((file = fopen(pidfile,"r")) == (FILE *)NULL) {
    LogError("%s: Error opening the pidfile '%s' -- %s\n", prog, pidfile, STRERROR);
    return FALSE;
  }
  if(fscanf(file, "%d", &pid) != 1) {
    LogError("%s: Error reading pid from file '%s'\n", prog, pidfile);
    if (fclose(file))
      LogError("%s: Error closing file '%s' -- %s\n", prog, pidfile, STRERROR);
    return FALSE;
  }
  if (fclose(file))
    LogError("%s: Error closing file '%s' -- %s\n", prog, pidfile, STRERROR);

  if(pid < 0)
    return(FALSE);
  
  return(pid_t)pid;
  
}


int Util_isProcessRunning(Service_T s, int refresh) {
  int   i;
  pid_t pid = -1;
  
  ASSERT(s);
  
  errno = 0;

  if (refresh || ! ptree || ! ptreesize)
    initprocesstree(&ptree, &ptreesize, &oldptree, &oldptreesize);

  if (s->matchlist) {
    /* The process table read may sporadically fail during read, because we're using glob on some platforms which may fail if the proc filesystem
     * which it traverses is changed during glob (process stopped). Note that the glob failure is rare and temporary - it will be OK on next cycle.
     * We skip the process matching that cycle however because we don't have process informations - will retry next cycle */
    if (Run.doprocess) {
      for (i = 0; i < ptreesize; i++) {
        int found = FALSE;

        if (ptree[i].cmdline) {
#ifdef HAVE_REGEX_H
          found = regexec(s->matchlist->regex_comp, ptree[i].cmdline, 0, NULL, 0) ? FALSE : TRUE;
#else
          found = strstr(ptree[i].cmdline, s->matchlist->match_string) ? TRUE : FALSE;
#endif
        }
        if (found) {
          pid = ptree[i].pid;
          break;
        }
      }
    } else {
        DEBUG("Process information not available -- skipping service %s process existence check for this cycle\n", s->name);
        /* Return value is NOOP - it is based on existing errors bitmap so we don't generate false recovery/failures */
        return ! (s->error & Event_Nonexist);
    }
  } else {
    pid = Util_getPid(s->path);
  }

  if (pid > 0) {
    if ((getpgid(pid) > -1) || (errno == EPERM))
      return pid;
    DEBUG("'%s' Error testing process id [%d] -- %s\n", s->name, pid, STRERROR);
  }
  Util_resetInfo(s);
  
  return 0;
}


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


int Util_getChecksum(char *file, int hashtype, char *buf, int bufsize) {
  int hashlength = 16;

  ASSERT(file);
  ASSERT(buf);
  ASSERT(bufsize >= sizeof(MD_T));

  switch (hashtype) {
    case HASH_MD5:
      hashlength = 16;
      break;
    case HASH_SHA1:
      hashlength = 20;
      break;
    default:
      LogError("checksum: invalid hash type: 0x%x\n", hashtype);
      return FALSE;
  }

  if (File_isFile(file)) {
    FILE *f = fopen(file, "r");
    if (f) {
      MD_T result;
      unsigned char sum[STRLEN];
      int fresult = 0;

      *result = 0;

      switch (hashtype) {
        case HASH_MD5:
          fresult = md5_stream(f, sum);
          break;
        case HASH_SHA1:
          fresult = sha_stream(f, sum);
          break;
      }

      if (fclose(f))
        LogError("%s: Error closing file '%s' -- %s\n", prog, file, STRERROR);

      if (fresult) {
        LogError("checksum: file %s stream error (0x%x)\n", file, fresult);
        return FALSE;
      }

      Util_digest2Bytes(sum, hashlength, buf);
      return TRUE;

    } else
      LogError("checksum: failed to open file %s -- %s\n", file, STRERROR);
  } else
    LogError("checksum: file %s is not regular file\n", file);
  return FALSE;
}


int Util_isurlsafe(const char *url) {
        int i;
        ASSERT(url && *url);
        for (i = 0; url[i]; i++) 
                if (urlunsafe[(unsigned char)url[i]])
                        return FALSE;
        return TRUE;
}


char *Util_urlEncode(char *url) {
        char *escaped = NULL;
        if (url) {
                char *p;
                int i, n;
                for (n = i = 0; url[i]; i++) 
                        if (urlunsafe[(unsigned char)(url[i])]) 
                                n += 2;
                p = escaped = xmalloc(i + n + 1);
                for (; *url; url++, p++) {
                        if (urlunsafe[(unsigned char)(*p = *url)]) {
                                *p++= '%';
                                *p++= b2x[(unsigned char)(*url)][0];
                                *p = b2x[(unsigned char)(*url)][1];
                        }
                }
                *p = 0;
        }
        return escaped;
}


char *Util_urlDecode(char *url) {
	if (url && *url) {
                register int x, y;
                for (x = 0, y = 0; url[y]; x++, y++) {
                        if ((url[x] = url[y]) == '+')
                                url[x] = ' ';
                        else if (url[x] == '%') {
                                if (! (url[x + 1] && url[x + 2]))
                                        break;
                                url[x] = x2c(url + y + 1);
                                y += 2;
                        }
                }
                url[x] = 0;
        }
	return url;
}


// NOTE: To be used to URL encode service names when ready
char *Util_encodeServiceName(char *name) {
        int i;
        char *s;
        ASSERT(name);
        s = Util_urlEncode(name);
        for (i = 0; s[i]; i++)
                if (s[i] == '/') return Util_replaceString(&s, "/", "%2F");
        return s;
}


char *Util_getBasicAuthHeaderMonit() {
  Auth_T c = Run.credentials;

  /* We find the first cleartext credential for authorization */
  while (c != NULL) {
    if (c->digesttype == DIGEST_CLEARTEXT && ! c->is_readonly)
      break;
    c = c->next;
  }

  if (c)
    return Util_getBasicAuthHeader(c->uname, c->passwd);

  return NULL;
}


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


char *Util_formatString(const char *s, va_list ap, long *len) {
  int n;
#ifdef HAVE_VA_COPY
  va_list ap_copy;
#endif
  int size= STRLEN;
  char *buf= xcalloc(sizeof(char), size);
  
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


void Util_redirectStdFds() {
  int i;
  for(i= 0; i < 3; i++) {
    if(close(i) == -1 || open("/dev/null", O_RDWR) != i) {
      LogError("Cannot reopen standard file descriptor (%d) -- %s\n", i, STRERROR);
    }
  }
}


void Util_closeFds() {
  int i;
#ifdef HAVE_UNISTD_H
  int max_descriptors = getdtablesize();
#else
  int max_descriptors = 1024;
#endif
  for(i = 3; i < max_descriptors; i++)
    close(i);
  errno= 0;
}


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
  memset(s->inf, 0, sizeof *(s->inf));
  switch (s->type) {
    case TYPE_PROCESS:
      s->inf->priv.process._pid  = -1;
      s->inf->priv.process._ppid = -1;
      s->inf->priv.process.pid   = -1;
      s->inf->priv.process.ppid  = -1;
      break;
    case TYPE_FILESYSTEM:
      s->inf->priv.filesystem._flags = -1;
      s->inf->priv.filesystem.flags  = -1;
      break;
  }
}


/**
 * Are service status data available?
 * @param s The service to test
 * @return TRUE if available otherwise FALSE
 */
int Util_hasServiceStatus(Service_T s) {
  return(!((s->monitor!=MONITOR_YES)||
	   (s->error&Event_Nonexist)||
	   (s->error&Event_Data) ));
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
  s->error = Event_Null;
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


char *Util_describeAction(Action_T A, char *buf, int bufsize) {
  #define BUF_CURSOR    (buf + strlen(buf))
  #define BUF_AVAILABLE (bufsize - strlen(buf) - 1)
  snprintf(buf, bufsize, "%s", actionnames[A->id]);
  if (A->id == ACTION_EXEC) {
    int i = 0;
    Command_T C = A->exec;

    while (C->arg[i]) {
      snprintf(BUF_CURSOR, BUF_AVAILABLE, "%s%s", i ? " " : " '", C->arg[i]);
      i++;
    }
    snprintf(BUF_CURSOR, BUF_AVAILABLE, "'");
    if (C->has_uid)
      snprintf(BUF_CURSOR, BUF_AVAILABLE, " as uid %d", C->uid);
    if (C->has_gid)
      snprintf(BUF_CURSOR, BUF_AVAILABLE, " as gid %d", C->gid);
    snprintf(BUF_CURSOR, BUF_AVAILABLE, " timeout %d cycle(s)", C->timeout);
  }
  return buf;
  #undef BUF_CURSOR
  #undef BUF_AVAILABLE
}


char *Util_getEventratio(Action_T action, char *buf, int bufsize) {
  snprintf(buf, bufsize, "%d times within %d cycle(s)", action->count, action->cycles);
  return buf;
}


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


char *Util_portDescription(Port_T p, char *buf, int bufsize) {
  if (p->family == AF_INET)
    snprintf(buf, STRLEN, "INET[%s:%d%s]%s%s", p->hostname, p->port, p->request ? p->request : "", p->family == AF_INET ? " via " : "", p->family == AF_INET ? Util_portTypeDescription(p) : "");
  else if (p->family == AF_UNIX)
    snprintf(buf, STRLEN, "UNIX[%s]", p->pathname);
  else
    *buf = 0;
  return buf;
}


void Util_stringbuffer(Buffer_T *b, const char *m, ...) {
  if (m) {
    va_list  ap;
    char    *buf;
    long     need = 0;
    ssize_t  have = 0;

    va_start(ap, m);
    buf = Util_formatString(m, ap, &need);
    va_end(ap);

    have = (*b).bufsize - (*b).bufused;
    if (have <= need) {
      (*b).bufsize += (need + STRLEN);
      (*b).buf = xresize((*b).buf, (*b).bufsize);
      if (! (*b).bufused)
        memset((*b).buf, 0, (*b).bufsize);
    }
    memcpy(&(*b).buf[(*b).bufused], buf, need);
    (*b).bufused += need;
    (*b).buf[(*b).bufused]= 0;
    FREE(buf);
  }
}


int Util_getfqdnhostname(char *buf, unsigned len) {
  int status;
  char hostname[STRLEN];
  struct addrinfo hints, *info = NULL;

  if (gethostname(hostname, sizeof(hostname))) {
    LogError("%s: Error getting hostname -- %s\n", prog, STRERROR);
    return -1;
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_CANONNAME;
  if ((status = getaddrinfo(hostname, NULL, &hints, &info))) {
    LogError("%s: Cannot translate '%s' to FQDN name -- %s\n", prog, hostname, gai_strerror(status));
    snprintf(buf, len, "%s", hostname); // fallback to gethostname()
  } else
    snprintf(buf, len, "%s", info->ai_canonname);
  if (info)
    freeaddrinfo(info);
  return 0;
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
  if(events == Event_Null) {
    printf("No events");
  } else if(events == Event_All) {
    printf("All events");
  } else {
    if(IS_EVENT_SET(events, Event_Action))
      printf("Action ");
    if(IS_EVENT_SET(events, Event_Checksum))
      printf("Checksum ");
    if(IS_EVENT_SET(events, Event_Connection))
      printf("Connection ");
    if(IS_EVENT_SET(events, Event_Content))
      printf("Content ");
    if(IS_EVENT_SET(events, Event_Data))
      printf("Data ");
    if(IS_EVENT_SET(events, Event_Exec))
      printf("Exec ");
    if(IS_EVENT_SET(events, Event_Fsflag))
      printf("Fsflags ");
    if(IS_EVENT_SET(events, Event_Gid))
      printf("Gid ");
    if(IS_EVENT_SET(events, Event_Icmp))
      printf("Icmp ");
    if(IS_EVENT_SET(events, Event_Instance))
      printf("Instance ");
    if(IS_EVENT_SET(events, Event_Invalid))
      printf("Invalid ");
    if(IS_EVENT_SET(events, Event_Nonexist))
      printf("Nonexist ");
    if(IS_EVENT_SET(events, Event_Permission))
      printf("Permission ");
    if(IS_EVENT_SET(events, Event_Pid))
      printf("PID ");
    if(IS_EVENT_SET(events, Event_PPid))
      printf("PPID ");
    if(IS_EVENT_SET(events, Event_Resource))
      printf("Resource ");
    if(IS_EVENT_SET(events, Event_Size))
      printf("Size ");
    if(IS_EVENT_SET(events, Event_Timeout))
      printf("Timeout ");
    if(IS_EVENT_SET(events, Event_Timestamp))
    printf("Timestamp ");
    if(IS_EVENT_SET(events, Event_Uid))
      printf("Uid ");
  }
  printf("\n");
}

