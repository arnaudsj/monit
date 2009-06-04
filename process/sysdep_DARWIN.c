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

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_KVM_H
#include <kvm.h>
#endif

#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif

#ifdef HAVE_SYS_VMMETER_H
#include <sys/vmmeter.h>
#endif

#ifdef HAVE_MACH_MACH_H
#include <mach/mach.h>
#endif

#ifdef HAVE_MACH_HOST_INFO_H
#include <mach/host_info.h>
#endif

#ifdef HAVE_MACH_MACH_HOST_H
#include <mach/mach_host.h>
#endif


#include "monitor.h"
#include "process.h"
#include "process_sysdep.h"

/**
 *  System dependent resource gathering code for MacOS X.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Christian Hopp <chopp@iei.tu-clausthal.de>
 *  @author Rory Toma <rory@digeo.com>
 *  @author Martin Pala <martinp@tildeslash.com>
 *  @author Dave Cheney <dcheney@redbubble.com> (Updated for Tiger)
 *
 *  @version \$Id: sysdep_DARWIN.c,v 1.44 2009/02/13 09:18:16 hauk Exp $
 *
 *  @file
 */


/* ----------------------------------------------------------------- Private */


static int  hz;
static int  pagesize_kbyte;
static long total_old    = 0;
static long cpu_user_old = 0;
static long cpu_syst_old = 0;


/* ------------------------------------------------------------------ Public */


int init_process_info_sysdep(void) {
  int              mib[2];
  size_t           len;
  struct clockinfo clock;
  uint64_t		   memsize;

  mib[0] = CTL_KERN;
  mib[1] = KERN_CLOCKRATE;
  len    = sizeof(clock);
  if(sysctl(mib, 2, &clock, &len, NULL, 0) == -1)
  {
    DEBUG("system statistic error -- cannot get clock rate: %s\n", STRERROR);
    return FALSE;
  }
  hz     = clock.hz;

  mib[0] = CTL_HW;

  mib[1] = HW_NCPU;
  len    = sizeof(systeminfo.cpus);
  if(sysctl(mib, 2, &systeminfo.cpus, &len, NULL, 0) == -1)
  {
    DEBUG("system statistic error -- cannot get cpu count: %s\n", STRERROR);
    return FALSE;
  }

  mib[1] = HW_MEMSIZE;
  len = sizeof(memsize);
  memsize = 0L;
  if(sysctl(mib, 2, &memsize, &len, NULL, 0 ) == -1)
  {
    DEBUG("system statistic error -- cannot get real memory amount: %s\n", STRERROR);
    return FALSE;
  }
  systeminfo.mem_kbyte_max = memsize / 1024;

  mib[1] = HW_PAGESIZE;
  len    = sizeof(pagesize_kbyte);
  if(sysctl(mib, 2, &pagesize_kbyte, &len, NULL, 0) == -1)
  {
    DEBUG("system statistic error -- cannot get memory page size: %s\n", STRERROR);
    return FALSE;
  }
  pagesize_kbyte /= 1024;

  return TRUE;
}


/**
 * Read all processes to initialize the information tree.
 * @param reference  reference of ProcessTree
 * @return treesize>0 if succeeded otherwise =0.
 */
int initprocesstree_sysdep(ProcessTree_T **reference) {
  int                i;
  int                treesize;
  mach_port_t        mytask = mach_task_self();
  struct kinfo_proc *pinfo;
  ProcessTree_T     *pt;
  size_t             bufSize = 0;
  int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };

  if(getuid()!=0) {
    LogError("system statistic error -- permission denied\n");
    return FALSE;
  }

  if(sysctl(mib, 4, NULL, &bufSize, NULL, 0) < 0) {
    LogError("system statistic error -- sysctl failed\n");
    return FALSE;
  }
  pinfo = (struct kinfo_proc *)xcalloc(1, bufSize);

  if(sysctl(mib, 4, pinfo, &bufSize, NULL, 0)) {
    LogError("system statistic error -- sysctl failed\n");
    free(pinfo);
    return FALSE;
  }

  treesize = bufSize / sizeof(struct kinfo_proc);

  pt = xcalloc(sizeof(ProcessTree_T), treesize);

  for(i = 0; i < treesize; i++)
  {
    mach_port_t task;

    pt[i].pid  = pinfo[i].kp_proc.p_pid;
    pt[i].ppid = pinfo[i].kp_eproc.e_ppid;

    if(pinfo[i].kp_proc.p_stat == SZOMB) {
      pt[i].status_flag |= PROCESS_ZOMBIE;
    }
    pt[i].time = get_float_time();

    if(task_for_pid(mytask, pt[i].pid, &task) == KERN_SUCCESS) {
      mach_msg_type_number_t   count;
      task_basic_info_data_t   taskinfo;
      thread_array_t           threadtable;
      unsigned int             threadtable_size;
      thread_basic_info_t      threadinfo;
      thread_basic_info_data_t threadinfo_data;

      count = TASK_BASIC_INFO_COUNT;
      if(task_info(task, TASK_BASIC_INFO, (task_info_t)&taskinfo, &count) == KERN_SUCCESS) {
        pt[i].mem_kbyte = (unsigned long)(taskinfo.resident_size / 1024);
        pt[i].cputime = (long)((taskinfo.user_time.seconds      + taskinfo.system_time.seconds)      * 10     +
                               (taskinfo.user_time.microseconds + taskinfo.system_time.microseconds) / 100000);
        pt[i].cpu_percent = 0;
      }
      if(task_threads(task, &threadtable, &threadtable_size) == KERN_SUCCESS) {
        int j;

        threadinfo = &threadinfo_data;
        for(j = 0; j < threadtable_size; j++) {
          count = THREAD_BASIC_INFO_COUNT;
          if(thread_info(threadtable[j], THREAD_BASIC_INFO, (thread_info_t)threadinfo, &count) == KERN_SUCCESS) {
            if((threadinfo->flags & TH_FLAGS_IDLE) == 0) {
              pt[i].cputime += (long)((threadinfo->user_time.seconds      + threadinfo->system_time.seconds)      * 10     +
                                      (threadinfo->user_time.microseconds + threadinfo->system_time.microseconds) / 100000);
              pt[i].cpu_percent = 0;
            }
          }
          mach_port_deallocate(mytask, threadtable[j]);
        }
		vm_deallocate(mytask, (vm_address_t)threadtable,threadtable_size * sizeof(thread_act_t));
      }
      mach_port_deallocate(mytask, task); 	
    }
  }

  *reference = pt;
  free(pinfo);

  return treesize;
}


/**
 * This routine returns 'nelem' double precision floats containing
 * the load averages in 'loadv'; at most 3 values will be returned.
 * @param loadv destination of the load averages
 * @param nelem number of averages
 * @return: 0 if successful, -1 if failed (and all load averages are 0).
 */
int getloadavg_sysdep (double *loadv, int nelem) {
  return getloadavg(loadv, nelem);
}


/**
 * This routine returns kbyte of real memory in use.
 * @return: TRUE if successful, FALSE if failed (or not available)
 */
int used_system_memory_sysdep(SystemInfo_T *si) {
  kern_return_t          kret;
  vm_statistics_data_t   page_info;
  mach_msg_type_number_t count;

  count = HOST_VM_INFO_COUNT;
  kret  = host_statistics(
            mach_host_self(), HOST_VM_INFO, (host_info_t)&page_info, &count
          );
  if(kret == KERN_SUCCESS)
  {
    unsigned int pw, pa, pi;

    pw = page_info.wire_count * pagesize_kbyte;
    pa = page_info.active_count * pagesize_kbyte;
    pi = page_info.inactive_count * pagesize_kbyte;

    si->total_mem_kbyte = pw+pa+pi;

    return TRUE;
  }
  return FALSE;
}


/**
 * This routine returns system/user CPU time in use.
 * @return: TRUE if successful, FALSE if failed
 */
int used_system_cpu_sysdep(SystemInfo_T *si) {
  int                       i;
  long                      total;
  long                      total_new = 0;
  kern_return_t             kret;
  host_cpu_load_info_data_t cpu_info;
  mach_msg_type_number_t    count;

  count = HOST_CPU_LOAD_INFO_COUNT;
  kret  = host_statistics(
            mach_host_self(), HOST_CPU_LOAD_INFO, (host_info_t)&cpu_info, &count
          );
  if(kret == KERN_SUCCESS)
  {
    for(i = 0; i < CPU_STATE_MAX; i++)
    {
      total_new += cpu_info.cpu_ticks[i];
    }
    total     = total_new - total_old;
    total_old = total_new;

    si->total_cpu_user_percent =
      (total > 0)?(int)(1000 * (double)(cpu_info.cpu_ticks[CPU_STATE_USER] - cpu_user_old) / total):-10;
    si->total_cpu_syst_percent =
      (total > 0)?(int)(1000 * (double)(cpu_info.cpu_ticks[CPU_STATE_SYSTEM] - cpu_syst_old) / total):-10;
    si->total_cpu_wait_percent =
      0; /* there is no wait statistic available */

    cpu_user_old = cpu_info.cpu_ticks[CPU_STATE_USER];
    cpu_syst_old = cpu_info.cpu_ticks[CPU_STATE_SYSTEM];

    return TRUE;
  }
  return FALSE;
}

