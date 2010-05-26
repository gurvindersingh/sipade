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
 * File:   util-alert.h
 * Author: Gurvinder Singh <gurvinder.singh@uninett.no>
 */

#ifndef _UTIL_ALERT_H
#define	_UTIL_ALERT_H

#include <syslog.h>

#define SIP_ALERT_IFACE_SYSLOG  0x01
#define SIP_ALERT_IFACE_HOBBIT  0x02

typedef struct SipAlertCtx_ {
    char *filename;
    uint8_t iface;
    FILE *file_descr;
}SipAlertCtx;

int SipAlertInitNotification();
void SipAlertNotification(char *, PGresult **);
void SipAlertDeInitCtx();
int SipLogAlertDB(PGresult *);

#endif	/* _UTIL_ALERT_H */

