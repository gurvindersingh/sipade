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
 * File:   util-detection.h
 * Author: Gurvinder Singh <gurvinder.singh@uninett.no>
 */

#ifndef _UTIL_DETECTION_H
#define	_UTIL_DETECTION_H

#include <math.h>
#include <netinet/in.h>
#include <inttypes.h>


#define CALLTYPE_INACTIVE       0x00
#define CALLTYPE_ACTIVE         0x01

#define DEFAULT_CALLTYPE_LEN    75

#define THRESHOLD_RESTORED      0x01

#define CLEAR_HD(hd) { \
        (hd)->num_total = 0; \
        (hd)->dur_total = 0; \
        (hd)->distance_value = 0.0; \
        (hd)->mean_deviation = 0.0; \
        (hd)->threshold = 0.0; \
        uint8_t i; \
        for(i = 0; i < MAX_CALLTYPE; i++) { \
            (hd)->call[i].name = NULL; \
            (hd)->call[i].p_freq = 0.0; \
            (hd)->call[i].p_dur = 0.0; \
            (hd)->call[i].num = 0; \
            (hd)->call[i].dur = 0; \
            (hd)->call[i].flag = CALLTYPE_INACTIVE; \
        } \
    }

enum {
    INTERNATIONAL = 0,
    MOBILE,
    PREMIUM,
    SERVICE,
    DOMESTIC,
    EMERGENCY,

    MAX_CALLTYPE,    /* Keep it last always */
};

typedef struct CallType_{
    char *name;
    double p_freq;
    uint32_t num;
    double p_dur;
    uint32_t dur;
    uint8_t flag;
}CallType;

typedef struct HellingerDistance {
    CallType call[MAX_CALLTYPE];
    uint64_t num_total;
    uint64_t dur_total;
    double distance_value;
    double mean_deviation;
    double threshold;
    uint8_t flags;
}Hd;

int SipInitAnomalyDetection();
int SipAnomalyDetection(PGconn *, PGresult **);
int SipTrainingAnomalyDetection(PGconn *);
void SipDeinitAnomalyDetection();
char *SipGetTimeStamp();
int SipTrainingInitThreshold(PGconn *);
int SipAnomalyStoreThreshold();

#endif	/* _UTIL_DETECTION_H */

