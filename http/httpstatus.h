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


#ifndef HTTPSTATUS_H
#define HTTPSTATUS_H

/* HTTP Status Codes */
#define SC_CONTINUE                      100
#define SC_SWITCHING_PROTOCOLS           101
#define SC_PROCESSING                    102
#define SC_OK                            200
#define SC_CREATED                       201
#define SC_ACCEPTED                      202
#define SC_NON_AUTHORITATIVE             203
#define SC_NO_CONTENT                    204
#define SC_RESET_CONTENT                 205
#define SC_PARTIAL_CONTENT               206
#define SC_MULTI_STATUS                  207
#define SC_MULTIPLE_CHOICES              300
#define SC_MOVED_PERMANENTLY             301
#define SC_MOVED_TEMPORARILY             302
#define SC_SEE_OTHER                     303
#define SC_NOT_MODIFIED                  304
#define SC_USE_PROXY                     305
#define SC_TEMPORARY_REDIRECT            307
#define SC_BAD_REQUEST                   400
#define SC_UNAUTHORIZED                  401
#define SC_PAYMENT_REQUIRED              402
#define SC_FORBIDDEN                     403
#define SC_NOT_FOUND                     404
#define SC_METHOD_NOT_ALLOWED            405
#define SC_NOT_ACCEPTABLE                406
#define SC_PROXY_AUTHENTICATION_REQUIRED 407
#define SC_REQUEST_TIMEOUT               408
#define SC_CONFLICT                      409
#define SC_GONE                          410
#define SC_LENGTH_REQUIRED               411
#define SC_PRECONDITION_FAILED           412
#define SC_REQUEST_ENTITY_TOO_LARGE      413
#define SC_REQUEST_URI_TOO_LARGE         414
#define SC_UNSUPPORTED_MEDIA_TYPE        415
#define SC_RANGE_NOT_SATISFIABLE         416
#define SC_EXPECTATION_FAILED            417
#define SC_UNPROCESSABLE_ENTITY          422
#define SC_LOCKED                        423
#define SC_FAILED_DEPENDENCY             424
#define SC_INTERNAL_SERVER_ERROR         500
#define SC_NOT_IMPLEMENTED               501
#define SC_BAD_GATEWAY                   502
#define SC_SERVICE_UNAVAILABLE           503
#define SC_GATEWAY_TIMEOUT               504
#define SC_VERSION_NOT_SUPPORTED         505
#define SC_VARIANT_ALSO_VARIES           506
#define SC_INSUFFICIENT_STORAGE          507
#define SC_NOT_EXTENDED                  510

#endif
