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

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "protocol.h"

/* Private variables */
static Protocol_T myapache_status= NULL;
static Protocol_T mydefault= NULL;
static Protocol_T mydns= NULL;
static Protocol_T mydwp= NULL;
static Protocol_T myftp= NULL;
static Protocol_T mygeneric= NULL;
static Protocol_T myhttp= NULL;
static Protocol_T myimap= NULL;
static Protocol_T myclamav= NULL;
static Protocol_T myldap2= NULL;
static Protocol_T myldap3= NULL;
static Protocol_T mymysql= NULL;
static Protocol_T mynntp= NULL;
static Protocol_T myntp3= NULL;
static Protocol_T mypostfix_policy= NULL;
static Protocol_T mypop= NULL;
static Protocol_T mysmtp= NULL;
static Protocol_T myssh= NULL;
static Protocol_T mylmtp= NULL;
static Protocol_T myrdate= NULL;
static Protocol_T myrsync= NULL;
static Protocol_T mytns= NULL;
static Protocol_T mypgsql= NULL;
static Protocol_T mysip= NULL;
static Protocol_T mygps= NULL;
static Protocol_T myradius= NULL;
static Protocol_T mymemcache= NULL;


/**
 *  Factory module for vending protocol objects. Using lazy
 *  initialization, and dishing out only one copy of the object.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *
 *  @file
 */


/* ------------------------------------------------------------------ Public */


void gc_protocols() {

  FREE(myapache_status);
  FREE(mydefault);
  FREE(mydns);
  FREE(mydwp);
  FREE(myftp);
  FREE(mygeneric);
  FREE(myhttp);
  FREE(myimap);
  FREE(myclamav);
  FREE(myldap2);
  FREE(myldap3);
  FREE(mymysql);
  FREE(mynntp);
  FREE(myntp3);
  FREE(mypostfix_policy);
  FREE(mypop);
  FREE(mysmtp);
  FREE(myssh);
  FREE(mylmtp);
  FREE(myrdate);
  FREE(myrsync);
  FREE(mytns);
  FREE(mypgsql);
  FREE(mysip);
  FREE(mygps);
  FREE(myradius);
  FREE(mymemcache);

}


void *create_apache_status() {
  if(myapache_status == NULL) {
    NEW(myapache_status);
    myapache_status->name= "APACHESTATUS";
    myapache_status->check= check_apache_status;
  }
  return myapache_status;
}


void *create_default() {
  if(mydefault == NULL) {
    NEW(mydefault);
    mydefault->name= "DEFAULT";
    mydefault->check= check_default;
  }
  return mydefault;
}


void *create_dns() {
  if(mydns == NULL) {
    NEW(mydns);
    mydns->name= "DNS";
    mydns->check= check_dns;
  }
  return mydns;
}


void *create_dwp() {
  if(mydwp == NULL) {
    NEW(mydwp);
    mydwp->name= "DWP";
    mydwp->check= check_dwp;
  }
  return mydwp;
}


void *create_ftp() {
  if(myftp == NULL) {
    NEW(myftp);
    myftp->name= "FTP";
    myftp->check= check_ftp;
  }
  return myftp;
}


void *create_generic() {
  if(mygeneric == NULL) {
    NEW(mygeneric);
    mygeneric->name= "generic";
    mygeneric->check= check_generic;
  }
  return mygeneric;
}


void *create_http() {
  if(myhttp == NULL) {
    NEW(myhttp);
    myhttp->name= "HTTP";
    myhttp->check= check_http;
  }
  return myhttp;
}


void *create_imap() {
  if(myimap == NULL) {
    NEW(myimap);
    myimap->name= "IMAP";
    myimap->check= check_imap;
  }
  return myimap;
}

void *create_clamav() {
  if(myclamav == NULL) {
    NEW(myclamav);
    myclamav->name= "CLAMAV";
    myclamav->check= check_clamav;
  }
  return myclamav;
}

void *create_ldap2() {
  if(myldap2 == NULL) {
    NEW(myldap2);
    myldap2->name= "LDAP2";
    myldap2->check= check_ldap2;
  }
  return myldap2;
}


void *create_ldap3() {
  if(myldap3 == NULL) {
    NEW(myldap3);
    myldap3->name= "LDAP3";
    myldap3->check= check_ldap3;
  }
  return myldap3;
}


void *create_mysql() {
  if(mymysql == NULL) {
    NEW(mymysql);
    mymysql->name= "MYSQL";
    mymysql->check= check_mysql;
  }
  return mymysql;
}


void *create_sip() {
  if(mysip == NULL) {
    NEW(mysip);
    mysip->name= "SIP";
    mysip->check= check_sip;
  }
  return mysip;
}


void *create_nntp() {
  if(mynntp == NULL) {
    NEW(mynntp);
    mynntp->name= "NNTP";
    mynntp->check= check_nntp;
  }
  return mynntp;
}


void *create_ntp3() {
  if(myntp3 == NULL) {
    NEW(myntp3);
    myntp3->name= "NTP3";
    myntp3->check= check_ntp3;
  }
  return myntp3;
}


void *create_postfix_policy() {
  if(mypostfix_policy == NULL) {
    NEW(mypostfix_policy);
    mypostfix_policy->name= "POSTFIX-POLICY";
    mypostfix_policy->check= check_postfix_policy;
  }
  return mypostfix_policy;
}


void *create_pop() {
  if(mypop == NULL) {
    NEW(mypop);
    mypop->name= "POP";
    mypop->check= check_pop;
  }
  return mypop;
}


void *create_smtp() {
  if(mysmtp == NULL) {
    NEW(mysmtp);
    mysmtp->name= "SMTP";
    mysmtp->check= check_smtp;
  }
  return mysmtp;
}

void *create_lmtp() {
  if(mylmtp == NULL) {
    NEW(mylmtp);
    mylmtp->name= "LMTP";
    mylmtp->check= check_lmtp;
  }
  return mylmtp;
}


void *create_ssh() {
  if(myssh == NULL) {
    NEW(myssh);
    myssh->name= "SSH";
    myssh->check= check_ssh;
  }
  return myssh;
}


void *create_rdate() {
  if(myrdate == NULL) {
    NEW(myrdate);
    myrdate->name= "RDATE";
    myrdate->check= check_rdate;
  }
  return myrdate;
}


void *create_rsync() {
  if(myrsync == NULL) {
    NEW(myrsync);
    myrsync->name= "RSYNC";
    myrsync->check= check_rsync;
  }
  return myrsync;
}


void *create_tns() {
  if(mytns == NULL) {
    NEW(mytns);
    mytns->name= "TNS";
    mytns->check= check_tns;
  }
  return mytns;
}


void *create_pgsql() {
  if(mypgsql == NULL) {
    NEW(mypgsql);
    mypgsql->name= "PGSQL";
    mypgsql->check= check_pgsql;
  }
  return mypgsql;
}


void *create_gps() {
  if(mygps == NULL) {
    NEW(mygps);
    mygps->name= "GPS";
    mygps->check= check_gps;
  }
  return mygps;
}

void *create_radius() {
  if(myradius == NULL) {
    NEW(myradius);
    myradius->name= "RADIUS";
    myradius->check= check_radius;
  }
  return myradius;
}

void *create_memcache() {
  if(mymemcache == NULL) {
    NEW(mymemcache);
    mymemcache->name= "MEMCACHE";
    mymemcache->check= check_memcache;
  }
  return mymemcache;
}

