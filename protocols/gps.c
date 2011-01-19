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
#include <string.h>

#include "protocol.h"

/**
 *  Check gpsd status.
 *  There is a project site for gpsd at <http://gpsd.berlios.de/>.
 *
 *  @author Sébastien Debrard, <sebastien.debrard@gmail.com>
 *
 *  @file
 */
int check_gps(Socket_T s) {
	char buf[STRLEN];
	const char *ok_gps_device="GPSD,G=GPS";
	const char *ok_rtcm104_device="GPSD,G=RTCM104";
	const char *ok_rtcm104v2_device="GPSD,G=RTCM104v2";

	ASSERT(s);

	if(socket_print(s, "G\r\n") < 0) {
		LogError("GPS: error sending data -- %s\n", STRERROR);
		return FALSE;
	}

	if(!socket_readln(s, buf, sizeof(buf))) {
		LogError("GPS: error receiving data -- %s\n", STRERROR);
		return FALSE;
	}

	Util_chomp(buf);
	if(strncasecmp(buf, ok_gps_device, strlen(ok_gps_device)) != 0) {
		if(strncasecmp(buf, ok_rtcm104v2_device, strlen(ok_rtcm104v2_device)) != 0) {
			if(strncasecmp(buf, ok_rtcm104_device, strlen(ok_rtcm104_device)) != 0) {
				LogError("GPS error (no device): %s\n", buf);
				return FALSE;
			}
		}
	}
	
	return TRUE;
}

