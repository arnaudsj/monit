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

/**
 *  System independent /proc & kvm methods.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Christian Hopp <chopp@iei.tu-clausthal.de>
 *
 *  @version \$Id: process_common.c,v 1.12 2009/02/13 09:18:15 hauk Exp $
 *
 *  @file
 */

#include <config.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_LOADAVG_H
#include <sys/loadavg.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "monitor.h"
#include "process.h"
#include "process_sysdep.h"


/**
 * Reads an process dependent entry or the proc files system
 * @param buf buffer to write to
 * @param buf_size size of buffer "buf"
 * @param name name of proc service
 * @param pid pid number of the process / or <0 if main directory
 * @return TRUE if succeeded otherwise FALSE.
 */
int read_proc_file(char *buf, int buf_size, char * name, int pid) {

  int fd;
  char filename[STRLEN];
  int bytes;

  ASSERT(buf);
  ASSERT(name);

  if ( pid < 0 ) {

    snprintf(filename, STRLEN, "/proc/%s", name);

  } else {

    snprintf(filename, STRLEN, "/proc/%d/%s", pid, name);

  }
    
  if ( (fd = open(filename, O_RDONLY)) < 0 ) {

    DEBUG("cannot open file %s -- %s\n", filename, STRERROR);

    return FALSE;

  }

  if ( (bytes = read(fd, buf, buf_size-1)) < 0 ) {

    close(fd);

    DEBUG("cannot read file %s -- %s\n", filename, STRERROR);

    return FALSE;

  }
       
  /* In case it is a string we have to 0 terminate it our self */
  buf[bytes]='\0';

  close(fd);

  return TRUE;
  
}

/**
 * Get the actual time as a floating point number
 * @return time in seconds
 */
double get_float_time(void) {    

  struct timeval t;

  gettimeofday(&t, NULL);
  return (double) t.tv_sec * 10 + (double) t.tv_usec / 100000.0;

}


/**
 * Connects child and parent in a process treee
 * @param parent pointer to parents process tree entry
 * @param child pointer to childs process tree entry
 * @return TRUE if succeeded otherwise FALSE.
 */
int connectchild(ProcessTree_T * parent, ProcessTree_T * child) {

  ProcessTree_T ** tmp;

  ASSERT(child);
  ASSERT(parent);

  if ( parent->pid == 0 || child->pid == 0 ) {

    return FALSE;
    
  }

  parent->children_num++;

  tmp = xcalloc(sizeof(ProcessTree_T *), parent->children_num);

  if ( parent->children != NULL ) {

    memcpy(tmp, parent->children,
	   sizeof(ProcessTree_T *) * (parent->children_num - 1));
    FREE(parent->children);

  }

  parent->children = tmp;
  parent->children[parent->children_num - 1] = child;

  return TRUE;

}


/**
 * Fill data in the process tree by recusively walking through it
 * @param pt process tree
 * @return TRUE if succeeded otherwise FALSE.
 */
void fillprocesstree(ProcessTree_T * pt) {

  int i;
  ProcessTree_T  *parent_pt;

  ASSERT(pt);

  if (( pt->pid==0 ) || ( pt->visited == 1 )) {
    
    return;
    
  }

  pt->visited= 1;
  pt->children_sum= pt->children_num;
  pt->mem_kbyte_sum= pt->mem_kbyte;
  pt->cpu_percent_sum= pt->cpu_percent;

  for( i = 0; i < pt->children_num; i++) {

    fillprocesstree(pt->children[i]);

  }

  if ( pt->parent != NULL ) {
    
    parent_pt=pt->parent;
    parent_pt->children_sum+=pt->children_sum;
    parent_pt->mem_kbyte_sum+=pt->mem_kbyte_sum;
    parent_pt->cpu_percent_sum+=pt->cpu_percent_sum;
    /* Numerical inaccuracy force us to limit the cpu load to 100%*/
    parent_pt->cpu_percent_sum=(pt->cpu_percent_sum>1000?1000:
                                parent_pt->cpu_percent_sum);
    
  } 
}

