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

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <stdio.h>

#include "monitor.h"
#include "process.h"
#include "process_sysdep.h"

/**
 *  General purpose /proc methods.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Christian Hopp <chopp@iei.tu-clausthal.de>
 *
 *  @version \$Id: process.c,v 1.44 2009/02/13 09:18:09 hauk Exp $
 *
 *  @file
 */


/* ------------------------------------------------------------------ Public */

char actionnames[][STRLEN]=   {"ignore", "alert", "restart", "stop", "exec",
	                       "unmonitor", "start", "monitor", ""};
char modenames[][STRLEN]=     {"active", "passive", "manual"};
char checksumnames[][STRLEN]= {"UNKNOWN", "MD5", "SHA1"};
char operatornames[][STRLEN]= {"greater than", "less than", "equal to",
                               "not equal to"};
char operatorshortnames[][3]= {">", "<", "=", "!="};
char monitornames[][STRLEN]=  {"not monitored", "monitored", "initializing"};
char statusnames[][STRLEN]=   {"accessible", "accessible", "accessible",
                               "running", "online with all services",
                               "running", "accessible"};
char servicetypes[][STRLEN]=  {"Filesystem", "Directory", "File", "Process",
                               "Remote Host", "System", "Fifo"};
char pathnames[][STRLEN]=     {"Path", "Path", "Path", "Pid file", "Path", "",
                               "Path"};
char icmpnames[][STRLEN]=     {"Echo Reply", "", "", "Destination Unreachable",
                               "Source Quench", "Redirect", "", "",
                               "Echo Request", "", "", "Time Exceeded",
                               "Parameter Problem", "Timestamp Request",
                               "Timestamp Reply", "Information Request",
                               "Information Reply", "Address Mask Request",
                               "Address Mask Reply"};
char sslnames[][STRLEN]=      {"auto", "v2", "v3", "tls"};


/**
 * Initialize the proc information code
 * @return TRUE if succeeded otherwise FALSE.
 */
int init_process_info(void) {
  int rv;

  memset(&systeminfo, 0, sizeof(SystemInfo_T));
  gettimeofday(&systeminfo.collected, NULL);
  if((rv = uname(&systeminfo.uname)) < 0) {
    LogError("'%s' resource monitoring initialization error -- uname failed: %s\n", Run.system->name, STRERROR);
    return FALSE;
  }

  systeminfo.total_cpu_user_percent = -10;
  systeminfo.total_cpu_syst_percent = -10;
  systeminfo.total_cpu_wait_percent = -10;

  return (init_process_info_sysdep());

}


/**
 * Get the proc infomation (CPU percentage, MEM in MByte and percent,
 * status), enduser version. 
 * @param p A Service object
 * @param pid The process id
 * @return TRUE if succeeded otherwise FALSE.
 */
int update_process_data(Service_T s, ProcessTree_T *pt, int treesize,
                        pid_t pid) {

  ProcessTree_T *leaf;

  ASSERT(s);
  ASSERT(systeminfo.mem_kbyte_max > 0);

  /* save the previous pid and set actual one */
  s->inf->_pid= s->inf->pid;
  s->inf->pid = pid;

  if ((leaf = findprocess(pid, pt, treesize)) != NULL ) {
 
    /* save the previous ppid and set actual one */
    s->inf->_ppid= s->inf->ppid;
    s->inf->ppid= leaf->ppid;
    s->inf->children=leaf->children_sum;
    s->inf->mem_kbyte=leaf->mem_kbyte;
    s->inf->status_flag=leaf->status_flag;
    s->inf->total_mem_kbyte=leaf->mem_kbyte_sum;
    s->inf->cpu_percent=leaf->cpu_percent;
    s->inf->total_cpu_percent=leaf->cpu_percent_sum;

    if ( systeminfo.mem_kbyte_max == 0 ) {
      
      s->inf->total_mem_percent=0;
      s->inf->mem_percent = 0;
      
    } else {
      
      s->inf->total_mem_percent=
        (int)((double)leaf->mem_kbyte_sum * 1000.0 / systeminfo.mem_kbyte_max);
      s->inf->mem_percent =
        (int)((double)leaf->mem_kbyte * 1000.0 / systeminfo.mem_kbyte_max);
      
    }

  } else {

    s->inf->ppid=0;
    s->inf->children=0;
    s->inf->total_mem_kbyte=0;
    s->inf->total_mem_percent=0;
    s->inf->mem_kbyte=0;
    s->inf->mem_percent=0;
    s->inf->cpu_percent=0;
    s->inf->total_cpu_percent=0;

  }
  
  return TRUE;

}


/**
 * Updates the system wide statistic
 * @return TRUE if successful, otherwise FALSE
 */
int update_system_load(ProcessTree_T *pt, int treesize) {

  if(Run.doprocess)
  {
    ProcessTree_T *leaf;
  
    ASSERT(systeminfo.mem_kbyte_max > 0);

    /** Get load average triplet */
    if(-1 == getloadavg_sysdep(systeminfo.loadavg, 3))
    {
      LogError("'%s' statistic error -- load average gathering failed\n",
        Run.system->name);
      goto error1;
    }

    /** Get real memory usage statistic */
    if(!used_system_memory_sysdep(&systeminfo))
    {
      DEBUG("'%s' statistic -- memory usage gathering method fallback\n",
        Run.system->name);
      /* Update the total real memory usage by monitoring process with PID 1 */
      if((leaf = findprocess(1, pt, treesize)) && leaf->mem_kbyte_sum > 0)
      {
        systeminfo.total_mem_kbyte = leaf->mem_kbyte_sum;
      }
      else
      {
        LogError("'%s' statistic error -- memory usage gathering failed\n",
          Run.system->name);
        goto error2;
      }
    }
    systeminfo.total_mem_percent = (int)(1000 *
      (double)systeminfo.total_mem_kbyte / (double)systeminfo.mem_kbyte_max);

    /** Get CPU usage statistic */
    if(!used_system_cpu_sysdep(&systeminfo))
    {
      DEBUG("'%s' statistic -- cpu usage gathering method fallback\n",
        Run.system->name);
      /* Update the total CPU load by monitoring process with PID 1 */
      if((leaf = findprocess(1, pt, treesize)))
      {
        systeminfo.total_cpu_user_percent = leaf->cpu_percent_sum;
        systeminfo.total_cpu_syst_percent = 0;  
        systeminfo.total_cpu_wait_percent = 0;  
      }
      else
      {
        LogError("'%s' statistic error -- cpu usage gathering failed\n",
          Run.system->name);
        goto error3;
      }
    }

    return TRUE;
  }

  error1:
  systeminfo.loadavg[0] = 0;
  systeminfo.loadavg[1] = 0;
  systeminfo.loadavg[2] = 0;
  error2:
  systeminfo.total_mem_kbyte = 0;
  systeminfo.total_mem_percent = 0;
  error3:
  systeminfo.total_cpu_user_percent = 0;
  systeminfo.total_cpu_syst_percent = 0;  
  systeminfo.total_cpu_wait_percent = 0;  
  return FALSE;
}


/**
 * Initialize the process tree 
 * @return treesize>=0 if succeeded otherwise <0.
 */
int initprocesstree(ProcessTree_T **pt_r,     int *size_r,
                    ProcessTree_T **oldpt_r, int *oldsize_r) {
  
  int i;
  ProcessTree_T *oldentry;
  ProcessTree_T *pt;
  ProcessTree_T *oldpt;
  ProcessTree_T *root;

  if(*pt_r != NULL)
  {  
    *oldpt_r   = *pt_r; 
    *oldsize_r = *size_r; 
  }
  
  if((*size_r = initprocesstree_sysdep(pt_r)) <= 0)
  {
    DEBUG("system statistic error -- cannot initialize the process tree => "
          "process resource monitoring disabled\n");
    Run.doprocess = FALSE;
    return -1;
  }

  pt    = *pt_r;
  oldpt = *oldpt_r;

  if ( pt == NULL ) {
    return 0;
  }

  for(i = 0; i < *size_r; i ++)
  {
    if(oldpt && (oldentry= findprocess(pt[i].pid, oldpt, *oldsize_r)))
    {
      pt[i].cputime_prev = oldentry->cputime;
      pt[i].time_prev    = oldentry->time;
 
      /* The cpu_percent may be set already (for example by HPUX module) */
      if(pt[i].cpu_percent  == 0 &&
         pt[i].cputime_prev != 0 &&
         pt[i].cputime      != 0 &&
         pt[i].cputime      > pt[i].cputime_prev)
      {
        pt[i].cpu_percent = (int)(
          (
            1000 *
            (double)(pt[i].cputime - pt[i].cputime_prev) /
            (pt[i].time - pt[i].time_prev)
          ) / systeminfo.cpus
        );

        /* Just for paranoia! */
        if(pt[i].cpu_percent > 1000 / systeminfo.cpus)
          pt[i].cpu_percent = 1000 / systeminfo.cpus;
      }
    }
    else
    {
      pt[i].cputime_prev = 0;
      pt[i].time_prev    = 0.0;
      pt[i].cpu_percent  = 0;
    }
        
    if(pt[i].ppid == 0)
    {
      continue;
    }

    if(NULL == (pt[i].parent= findprocess(pt[i].ppid, pt, *size_r)))
    {
      /* Inconsitency found, process orphaned most probably by a race
         condition. we might lack accuracy but we remain stable! */
      DEBUG("system statistic error -- orphaned process id %d\n", pt[i].pid);
      pt[i].pid = 0;
      continue;
    }
    
    if(! connectchild(pt[i].parent, &pt[i]))
    {
      /* connection to parent process has failed, this is
	 usually caused in the part above */
      DEBUG(
        "system statistic error -- "
        "cannot connect process id %d to its parent %d\n",
        pt[i].pid, pt[i].ppid);
      pt[i].pid=0;
      continue;
    }

  }

  if(! (root = findprocess(1, pt, *size_r)))
  {
    DEBUG("system statistic error -- cannot find process id 1\n",
      pt[i].pid, pt[i].ppid);
    return -1;
  }

  fillprocesstree(root);

  return *size_r;
}


/**
 * Search a leaf in the processtree
 * @param pid  pid of the process
 * @param pt  processtree
 * @param treesize  size of the processtree
 * @return pointer of the process if succeeded otherwise NULL.
 */
ProcessTree_T *findprocess(int pid, ProcessTree_T *pt, int size) {

  int i;

  ASSERT(pt);

  if(( pid == 0  ) || ( size <= 0 ))
    return NULL;

  for( i = 0; i < size; i ++ ) {

    if( pid == pt[i].pid ) {
      
      return &pt[i];

    }

  }

  return NULL;

}

/**
 * Delete the process tree 
 */
void delprocesstree(ProcessTree_T ** reference, int size) {

  int i;
  ProcessTree_T * pt;

  pt= * reference;

  if( pt == NULL || size <= 0 )
      return;

  for( i = 0; i < size; i ++ ) {

    if( pt[i].children!=NULL ) {

      FREE(pt[i].children);
      pt[i].children=NULL;

    }
    
  }

  FREE(pt);

  *reference=NULL;

  return;

}
