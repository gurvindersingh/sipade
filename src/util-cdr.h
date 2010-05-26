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
 * File:   util-cdr.h
 * Author: Gurvinder Singh <gurvinder.singh@uninett.no>
 *
 * Created on April 6, 2010, 2:43 PM
 */

#ifndef _UTIL_CDR_H
#define	_UTIL_CDR_H

PGconn *SipInitCdr();
PGconn *SipConnectDB(char *);
PGresult *SipGetCdr(PGconn *, const char *);

#endif	/* _UTIL_CDR_H */

