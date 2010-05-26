/* Copyright (c) 2010 UNINETT AS
 *
 * This file is a part of SipADE engine.
 *
 * SipADE is a free software, You can copy, redistribute or modify this
 * Program under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * SipADE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/*
 * File:   util-log.h
 * Author: Gurvinder Singh <gurvinder.singh@uninett.no>
 *
 * Created on April 12, 2010, 9:35 PM
 */

#ifndef _UTIL_LOG_H
#define	_UTIL_LOG_H

#include <stdarg.h>

#define SIP_LOG_LOCATION    __FILE__,__LINE__

#define SIP_LOG_DEBUG   1
#define SIP_LOG_INFO    2
#define SIP_LOG_ERROR   3

void SipInitLog();
void SipLog(int , char *, int , const char *, ...);

#endif	/* _UTIL_LOG_H */

