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
 * File:   sip-anomaly-detection.h
 * Author: Gurvinder Singh <gurvinder.singh@uninett.no>
 */

#ifndef _SIPADE_H
#define	_SIPADE_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/time.h>
#include <postgresql/libpq-fe.h>

#define TRUE    1
#define FALSE   0

#define SIP_ERROR                   -1
#define SIP_OK                      0
#define SIP_DONE                    2

#define SIP_THRESHOLD_RESTORE       3
#define SIP_THRESHOLD_NOT_RESTORE   4

#define SIP_STATUS_OK       "OK"
#define SIP_STATUS_ALERT    "FATAL"

#define SIP_RUN_MODE_OFFLINE        0x01
#define SIP_RUN_MODE_ONLINE         0x02

#define SIP_CONF_FILE_PATH  "/usr/local/etc/sipad/sipad.yaml"

#endif	/* _SIPADE_H */

