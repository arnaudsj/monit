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

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_PROC_H
#include <sys/proc.h>
#endif

#ifdef HAVE_KVM_H
#include <kvm.h>
#endif

#ifdef HAVE_UVM_UVM_H
#include <uvm/uvm.h>
#endif

#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif

#ifdef HAVE_SYS_DKSTAT_H
#include <sys/dkstat.h>
#endif

#include "monitor.h"
#include "process.h"
#include "process_sysdep.h"

/**
 *  System dependent resource gathering code for OpenBSD.
 *
 *  @author Margarida Sequeira <margarida@openbsd.org>
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Christian Hopp <chopp@iei.tu-clausthal.de>
 *  @author Rory Toma <rory@digeo.com>
 *  @author Martin Pala <martinp@tildeslash.com>
 *
 *  @file
 */


/* ----------------------------------------------------------------- Private */


static int      hz;
static int      pagesize_kbyte;
static long     total_old    = 0;
static long     cpu_user_old = 0;
static long     cpu_syst_old = 0;
static unsigned maxslp;



/* ------------------------------------------------------------------ Public */


int init_process_info_sysdep(void) {
  int              mib[2];
  size_t           len;
  struct clockinfo clock;

  mib[0] = CTL_KERN;
  mib[1] = KERN_CLOCKRATE;
  len    = sizeof(clock);
  if (sysctl(mib, 2, &clock, &len, NULL, 0) == -1) {
    DEBUG("system statistic error -- cannot get clock rate: %s\n", STRERROR);
    return FALSE;
  }
  hz     = clock.hz;

  mib[0] = CTL_HW;
  mib[1] = HW_NCPU;
  len    = sizeof(systeminfo.cpus);
  if (sysctl(mib, 2, &systeminfo.cpus, &len, NULL, 0) == -1) {
    DEBUG("system statistic error -- cannot get cpu count: %s\n", STRERROR);
    return FALSE;
  }

  mib[1] = HW_PHYSMEM;
  len    = sizeof(systeminfo.mem_kbyte_max);
  if (sysctl(mib, 2, &systeminfo.mem_kbyte_max, &len, NULL, 0) == -1) {
    DEBUG("system statistic error -- cannot get real memory amount: %s\n", STRERROR);
    return FALSE;
  }
  systeminfo.mem_kbyte_max /= 1024;

  mib[1] = HW_PAGESIZE;
  len    = sizeof(pagesize_kbyte);
  if (sysctl(mib, 2, &pagesize_kbyte, &len, NULL, 0) == -1) {
    DEBUG("system statistic error -- cannot get memory page size: %s\n", STRERROR);
    return FALSE;
  }
  pagesize_kbyte /= 1024;

  return TRUE;
}


/**
 * Read all processes to initialize the information tree.
 * @param reference  reference of ProcessTree
 * @return treesize > 0 if succeeded otherwise = 0.
 */
int initprocesstree_sysdep(ProcessTree_T **reference) {
  int                        i;
  int                        treesize;
  char                       buf[_POSIX2_LINE_MAX];
  size_t                     size = sizeof(maxslp);
  int                        mib_proc2[6] = {CTL_KERN, KERN_PROC2, KERN_PROC_KTHREAD, 0, sizeof(struct kinfo_proc2), 0};
  static int                 mib_maxslp[] = {CTL_VM, VM_MAXSLP};
  ProcessTree_T             *pt;
  kvm_t                     *kvm_handle;
  static struct kinfo_proc2 *pinfo;

  if (sysctl(mib_maxslp, 2, &maxslp, &size, NULL, 0) < 0) {
    LogError("system statistic error -- vm.maxslp failed");
    return FALSE;
  }

  if (sysctl(mib_proc2, 6, NULL, &size, NULL, 0) == -1) {
    LogError("system statistic error -- kern.proc2 #1 failed");
    return FALSE;
  }

  size *= 2; // Add reserve for new processes which were created between calls of sysctl
  pinfo = xcalloc(1, size);
  mib_proc2[5] = (int)(size / sizeof(struct kinfo_proc2));
  if (sysctl(mib_proc2, 6, pinfo, &size, NULL, 0) == -1) {
    FREE(pinfo);
    LogError("system statistic error -- kern.proc2 #2 failed");
    return FALSE;
  }

  treesize = (int)(size / sizeof(struct kinfo_proc2));

  pt = xcalloc(sizeof(ProcessTree_T), treesize);

  if (! (kvm_handle = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, buf))) {
    LogError("system statistic error -- kvm_openfiles failed: %s", buf);
    return FALSE;
  }

  for (i = 0; i < treesize; i++) {
    int        j;
    char     **args;
    Buffer_T   cmdline;

    pt[i].pid         = pinfo[i].p_pid;
    pt[i].ppid        = pinfo[i].p_ppid;
    pt[i].starttime   = pinfo[i].p_ustart_sec;
    pt[i].cputime     = (long)((pinfo[i].p_rtime_sec * 10) + (pinfo[i].p_rtime_usec / 100000));
    pt[i].cpu_percent = 0;
    pt[i].mem_kbyte   = (unsigned long)(pinfo[i].p_vm_rssize * pagesize_kbyte);
    if (pinfo[i].p_stat == SZOMB)
      pt[i].status_flag |= PROCESS_ZOMBIE; //FIXME: save system service flag too (kernel threads)
    pt[i].time = get_float_time();

    memset(&cmdline, 0, sizeof(Buffer_T));
    if ((args = kvm_getargv2(kvm_handle, &pinfo[i], 0))) {
      for (j = 0; args[j]; j++)
        Util_stringbuffer(&cmdline, args[j + 1] ? "%s " : "%s", args[j]);
      pt[i].cmdline = cmdline.buf;
    }
    if (! pt[i].cmdline || ! *pt[i].cmdline)
      pt[i].cmdline = xstrdup(pinfo[i].p_comm);
  }
  FREE(pinfo);
  kvm_close(kvm_handle);

  *reference = pt;

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
  int            mib[2];
  size_t         len;
  struct vmtotal vm;
  struct uvmexp  vmexp;

  /* Memory */
  mib[0] = CTL_VM;
  mib[1] = VM_METER;
  len    = sizeof(struct vmtotal);
  if (sysctl(mib, 2, &vm, &len, NULL, 0) == -1) {
    LogError("system statistic error -- cannot get real memory usage: %s\n", STRERROR);
    return FALSE;
  }
  si->total_mem_kbyte = (unsigned long)(vm.t_arm * pagesize_kbyte);

  /* Swap */
  mib[1] = VM_UVMEXP;
  len = sizeof(vmexp);
  if (sysctl(mib, 2, &vmexp, &len, NULL, 0) == -1) {
    LogError("system statistic error -- cannot get swap usage: %s\n", STRERROR);
    si->swap_kbyte_max = 0;
    return FALSE;
  }
  si->swap_kbyte_max   = (unsigned long)((double)vmexp.swpages   * ((double)vmexp.pagesize / 1024.));
  si->total_swap_kbyte = (unsigned long)((double)vmexp.swpginuse * ((double)vmexp.pagesize / 1024.));

  return TRUE;
}


/**
 * This routine returns system/user CPU time in use.
 * @return: TRUE if successful, FALSE if failed
 */
int used_system_cpu_sysdep(SystemInfo_T *si) {
  int    i;
  int    mib[] = {CTL_KERN, KERN_CPTIME};
  long   cp_time[CPUSTATES];
  long   total_new = 0;
  long   total;
  size_t len;

  len = sizeof(cp_time);
  if (sysctl(mib, 2, &cp_time, &len, NULL, 0) == -1) {
    LogError("system statistic error -- cannot get cpu time: %s\n", STRERROR);
    return FALSE;
  }

  for (i = 0; i < CPUSTATES; i++)
    total_new += cp_time[i];
  total     = total_new - total_old;
  total_old = total_new;

  si->total_cpu_user_percent = (total > 0)?(int)(1000 * (double)(cp_time[CP_USER] - cpu_user_old) / total):-10;
  si->total_cpu_syst_percent = (total > 0)?(int)(1000 * (double)(cp_time[CP_SYS] - cpu_syst_old) / total):-10;
  si->total_cpu_wait_percent = 0; /* there is no wait statistic available */

  cpu_user_old = cp_time[CP_USER];
  cpu_syst_old = cp_time[CP_SYS];

  return TRUE;  
}

