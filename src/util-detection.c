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
 * File:   util-detection.c
 * Author: Gurvinder Singh <gurvinder.singh@uninett.no>
 * 
 * This file is used to detect the anomaly in the SIP calls. The Hellinger
 * distance algorithm has been used to calculate the dynamic threshold.
 *
 * Reference: -
 *
 * Sengar, Hemant and Wang, Haining and Wijesekera, Duminda and Jajodia, Sushil:
 * Detecting VoIP Floods Using the Hellinger Distance,
 * IEEE Trans. Parallel Distrib. Syst., 2008.
 *
 */

#include <ctype.h>
#include <time.h>
#include "sipade.h"
#include "util-detection.h"
#include "util-log.h"
#include "util-cdr.h"
#include "util-alert.h"
#include "util-conf.h"

#define DEFAULT_TIME_INTERVAL               10
#define DEFAULT_SENSTIVITY_VALUE            1.2
#define DEFAULT_ADAPTABILITY_VALUE          0.5

#define DEFAULT_INTERNATIONAL_DURATION      2400
#define DEFAULT_MOBILE_DURATION             3600
#define DEFAULT_PREMIUM_DURATION            3600

#define DEFAULT_START_TIME                  8
#define DEFAULT_END_TIME                    16

#define DEFAULT_QUERY_SIZE                  400

/* For the variable values check the reference article in the source file */
static float g = 0.125; /* g = 1/pow(2,3) */
static float h = 0.25;  /* h = 1/pow(2,2) */
static double senstivity = 0.0;
static double adaptability = 0.0;
static int interval = 0;
static int int_dur = 0;
static int mob_dur = 0;
static int prem_dur = 0;
static int start_time = 0;
static int end_time = 0;
static Hd hd_detection;
static struct tm current_time = {0,0,0,0,0,0,0,0,0};
static time_t complete_time = 0;
static char *table = NULL;
static char *last_transaction_ts = NULL;
static PGconn *threshold_conn = NULL;
static char *threshold_table = NULL;
static char previous_ts[25];
static char *accountcode = NULL;
static char *thresh_restore = NULL;
static char *detect_start_ts = NULL;
static char *calltype = NULL;
static int call_freq = 0;
static int call_dur = 0;

/**
 * \brief   Function to update the timestamp with the given time interval. This
 *          is used in feteching the data from the cdr database.
 *
 * @param interval  value of the interval which will be added to the timestamp
 *
 * @return returns SIP_OK upon success and SIP_DONE upon completion, when
 *                 running in offline mode
 */
int SipUpdateTimeStamp(uint32_t interval)
{
    extern uint8_t run_mode;

    if (run_mode & SIP_RUN_MODE_OFFLINE) {
        if (mktime(&current_time) > complete_time)
            return SIP_DONE;
    }

    current_time.tm_min += interval;
    mktime(&current_time);

    strncpy(previous_ts, last_transaction_ts, 24);

    strftime(last_transaction_ts, 25, "%F %H:%M:%S", &current_time);

    SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION, "interval is %d\n",interval);
    return SIP_OK;
}

/**
 * \brief   Function to update the timestamp with the detection timestamp. This
 *          is used when we are restoring the engine and the restored timestamp
 *          value is less than compared to the restored timestamp.
 *
 * @param curent_tm  pointer to the current time stamp value
 * @param detect_ts  pointer to the detection time stamp value
 */
void SipSetTimeStamp(struct tm *curent_tm, char *detect_ts)
{
    time_t c_tm = 0;
    time_t d_tm = 0;
    struct tm det_tm = {0,0,0,0,0,0,0,0,0};

    strptime(detect_ts, "%F %H:%M:%S" ,&det_tm);
    c_tm = mktime(curent_tm);
    d_tm = mktime(&det_tm);
    if (d_tm > c_tm) {
        strncpy(last_transaction_ts, detect_start_ts,
                strlen(last_transaction_ts));
        detect_start_ts = NULL;
        strptime(last_transaction_ts, "%F %H:%M:%S" ,&current_time);
    }
}

/**
 * \brief   Function to return the timestamp value of the last interval, which
 *          will be used in the logging to the log file
 * @return returns the pointer to the timestamp value
 */
char *SipGetTimeStamp()
{
    return previous_ts;
}

void SipSetCallTypeString()
{
    int i = 0;
    int siz = 0;
    calltype = (char *)calloc(1, DEFAULT_CALLTYPE_LEN);
    char *orig_pos = calltype;
    while (i < MAX_CALLTYPE) {
        if (hd_detection.call[i].flag & CALLTYPE_ACTIVE) {
            siz = strlen(hd_detection.call[i].name);
            *calltype = '\'';
            calltype++;
            memcpy(calltype, hd_detection.call[i].name, siz);
            calltype += siz;
            *calltype = '\'';
            calltype++;
            *calltype = ',';
            calltype++;
        }
        i++;
    }
    calltype--;
    *calltype = '\0';
    calltype = orig_pos;
    SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION, "Calltype string is %s", calltype);
}

/**
 * \brief   Function to make the query string for the given interval
 *
 * @param query     pointer to the query string in which the final string will
 *                  be stored
 * @param timestamp pointer to the timestamp value from which the data will be
 *                  feteched
 * @param interval  pointer to the interval vallue which will be added to the
 *                  timestamp to fetch the data
 */
void SipGetQuery(char *query, char *timestamp, int interval)
{
    snprintf(query, DEFAULT_QUERY_SIZE, "select id,calldate,src,dst,billsec,"
            "calltype,accountcode from %s where calldate between '%s'::timestamp"
            " and '%s'::timestamp + interval '%d minute'and calltype in (%s)"
            " and accountcode='%s'", table, timestamp,
            timestamp,interval, calltype,accountcode);
}

/**
 * \brief   Function to fetch the data rekated to different calltypes and their
 *          duration.
 * @param hd        pointer to the struct in which the result will be stored
 * @param result    pointer to the result feteched from the cdr database for
 *                  given interval
 */
void SipGetCallData(Hd *hd, PGresult *result)
{
    char *calltype = NULL;
    char *billsec = NULL;
    int i_billsec = 0;
    uint32_t row = 0;
    uint32_t row_cnt = 0;
    uint8_t cnt = 0;

    row_cnt = PQntuples(result);

    /* Get the data for various call types */
    for (row = 0; row < row_cnt; row++) {
        calltype = PQgetvalue(result, row, 5);
        /* Get data for INTERNATIONAL call type */
        if (strncmp(calltype, "INTERNATIONAL", 13) == 0) {
            hd->call[INTERNATIONAL].num++;
            billsec = PQgetvalue(result, row, 4);
            i_billsec = strtoul(billsec,NULL,10);
            hd->call[INTERNATIONAL].dur += i_billsec;
        /* Get data for MOBILE call type */
        } else if (strncmp(calltype, "MOBILE", 6) == 0) {
            hd->call[MOBILE].num++;
            billsec = PQgetvalue(result, row, 4);
            i_billsec = strtoul(billsec,NULL,10);
            hd->call[MOBILE].dur += i_billsec;
        /* Get data for PREMIUM call type */
        } else if (strncmp(calltype, "PREMIUM", 7) == 0) {
            hd->call[PREMIUM].num++;
            billsec = PQgetvalue(result, row, 4);
            i_billsec = strtoul(billsec,NULL,10);
            hd->call[PREMIUM].dur += i_billsec;
        /* Get data for DOMESTIC call type */
        } else if (strncmp(calltype, "DOMESTIC", 8) == 0) {
            hd->call[DOMESTIC].num++;
            billsec = PQgetvalue(result, row, 4);
            i_billsec = strtoul(billsec,NULL,10);
            hd->call[DOMESTIC].dur += i_billsec;
        /* Get data for SERVICE call type */
        } else if (strncmp(calltype, "SERVICE", 7) == 0) {
            hd->call[SERVICE].num++;
            billsec = PQgetvalue(result, row, 4);
            i_billsec = strtoul(billsec,NULL,10);
            hd->call[SERVICE].dur += i_billsec;
        /* Get data for EMERGENCY call type */
        } else if (strncmp(calltype, "EMERGENCY", 9) == 0) {
            hd->call[EMERGENCY].num++;
            billsec = PQgetvalue(result, row, 4);
            i_billsec = strtoul(billsec,NULL,10);
            hd->call[EMERGENCY].dur += i_billsec;
        }
    }

    /* Get the total data of the all the fetched call types */
    for (cnt = 0; cnt < MAX_CALLTYPE; cnt++) {
        /* Get the total number of all the fetched call types */
        hd->num_total += hd->call[cnt].num;
        /* Get the total duration of the all the fetched call types */
        hd->dur_total += hd->call[cnt].dur;
    }

    SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION, "International calls %d and"
            " duration %d, Mobile calls %d and duration %d, Premium calls %d and"
            "duration %d, Domestic calls %d and duration %d, Service calls %d"
            " and duration %d Emergency calls %d and duration %d Total calls "
            "%"PRIu64" and duration %"PRIu64", timestamp %s",
            hd->call[INTERNATIONAL].num, hd->call[INTERNATIONAL].dur,
            hd->call[MOBILE].num, hd->call[MOBILE].dur, hd->call[PREMIUM].num,
            hd->call[PREMIUM].dur, hd->call[DOMESTIC].num,
            hd->call[DOMESTIC].dur, hd->call[SERVICE].num, hd->call[SERVICE].dur,
            hd->call[EMERGENCY].num, hd->call[EMERGENCY].dur, hd->num_total,
            hd->dur_total, last_transaction_ts);

}

/**
 * \brief   Function to calculate the probability of the number of different
 *          calltypes and their duration. The probabality will be calculated
 *          for the given interval, only if the call frequency is higher than
 *          specified number or specified duration
 *
 * @param hd pointer to the threshold struct of which probablity will be
 *           calculated
 */
void SipCalcHDProbabilities(Hd *hd)
{
    uint8_t cnt = 0;

    if (hd->num_total > call_freq || hd->dur_total > call_dur) {
        for (cnt = 0; cnt < MAX_CALLTYPE  &&
            (hd_detection.call[cnt].flag & CALLTYPE_ACTIVE); cnt++)
        {
             hd->call[cnt].p_freq = (double)hd->call[cnt].num/
                    (double)(hd->num_total + hd->dur_total);
             SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION, "prob of Number of Call"
                     " Type %d: %f", cnt, hd->call[cnt].p_freq);

             hd->call[cnt].p_dur = (double)hd->call[cnt].dur/
                    (double)(hd->num_total + hd->dur_total);
             SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION, "prob of Duration of Call"
                     " Type %d: %f", cnt, hd->call[cnt].p_dur);
        }
    }
    
    SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION, "Total Number of all Calls:"
            " %"PRIu64"\n", hd->num_total);
    SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION, "Duration of Total Calls:"
            " %"PRIu64"\n", hd->dur_total);
}

/**
 * \brief Function to calculate the training distance value for the current period
 *        against the given detection struct. This distance value will be used
 *        in calculating the threshold value at later stage. During the
 *        detection period, we are more sensitive to the international and
 *        premium service calls
 *
 * @param hd_detection pointer to the detection struct against which distance
 *                     value is calculated
 * @param hd_testing   pointer to the values of the current testing period,
 *                     which will be used to calculate the distance
 */
void SipCalcHellingerDistance (Hd *hd_detection, Hd *hd_testing)
{
    double fcall[MAX_CALLTYPE] = { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };
    double dcall[MAX_CALLTYPE] = { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };;
    uint8_t cnt = 0;
    
    for (cnt = 0; cnt < MAX_CALLTYPE  &&
            (hd_detection->call[cnt].flag & CALLTYPE_ACTIVE); cnt++)
    {
        if (hd_testing->call[cnt].p_freq != 0) {
            fcall[cnt] = (pow((sqrt(hd_detection->call[cnt].p_freq) -
                            sqrt(hd_testing->call[cnt].p_freq)), 2));
        }

        if (hd_testing->call[cnt].p_dur != 0) {
            dcall[cnt] = (pow((sqrt(hd_detection->call[cnt].p_dur) -
                            sqrt(hd_testing->call[cnt].p_dur)), 2));
        }

        /* calculate the hellinger distance */
        hd_testing->distance_value += fcall[cnt] + dcall[cnt];
    }

    SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION, "Distance Value %f",
            hd_testing->distance_value);
}

/**
 * \brief   Function to update the threshold value from the current calculted
 *          value, so that the engine will adapt to the changes in the behavior
 *
 * @param hd_detection   poiner the threshold struct, which will be updated
 * @param hd_testing    pointer to the threshold struct from which value will
 *                      be updated
 */
void SipUpdateHDThreshold(Hd *hd_detection, Hd *hd_testing)
{

    double error = 0.0;
    uint8_t cnt = 0;

    SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION,"test distance is %f training"
            " distance is %f\n", hd_testing->distance_value,
            hd_detection->distance_value);
    error = hd_testing->distance_value - hd_detection->distance_value;
    if ((error < adaptability && error > -adaptability)
            || (hd_detection->distance_value == 0.0))
    {
    SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION,"error is %f\n", error);
    hd_detection->distance_value = hd_detection->distance_value + (g * error);
    /* get the absolute value of error */
    error = fabs(error);
    SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION,"new training distance is %f"
            " old mean %f\n", hd_detection->distance_value,
            hd_detection->mean_deviation);
    hd_detection->mean_deviation = hd_detection->mean_deviation +
                                 (h*(error - hd_detection->mean_deviation));


    hd_detection->threshold = (senstivity * hd_detection->distance_value) +
                            (adaptability * hd_detection->mean_deviation);

    for (cnt = 0; cnt < MAX_CALLTYPE &&
            (hd_detection->call[cnt].flag & CALLTYPE_ACTIVE); cnt++)
    {
        hd_detection->call[cnt].p_freq = hd_testing->call[cnt].p_freq;
        hd_detection->call[cnt].p_dur = hd_testing->call[cnt].p_dur;
        
        hd_detection->call[cnt].num = hd_testing->call[cnt].num;
        hd_detection->call[cnt].dur = hd_testing->call[cnt].dur;
    }
        SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION, "threshold value is %f"
                " hd_distance %f mean %f error %f", hd_detection->threshold,
                hd_detection->distance_value, hd_detection->mean_deviation, error);
    }
    
}

/**
 * \brief   Function to print the given threshold struct with all other
 *          parameters to file provided.
 *
 * @param hd pointer to the threshold struct to be printed
 * @param fp pointer to the file descriptor where the value should written
 * 
 */
void SipPrintHD(Hd *hd, FILE *fp)
{
    fprintf(fp, "\n*****Hellinger Distance (%p) Field values are*****\n",hd);
    fprintf(fp, "Number of Mobile Calls: %d\n", hd->call[MOBILE].num);
    fprintf(fp, "Number of International Calls: %d\n", hd->call[INTERNATIONAL].num);
    fprintf(fp, "Number of Premium Calls: %d\n", hd->call[PREMIUM].num);
    fprintf(fp, "Number of Domestic Calls: %d\n", hd->call[DOMESTIC].num);
    fprintf(fp, "Number of Service Calls: %d\n", hd->call[SERVICE].num);
    fprintf(fp, "Number of Emergency Calls: %d\n", hd->call[EMERGENCY].num);
    fprintf(fp, "Total Number of all Calls: %"PRIu64"\n", hd->num_total);
    fprintf(fp, "Prob. of number of mobile calls: %f\n"
            ,hd->call[MOBILE].p_freq);
    fprintf(fp, "Prob. of Number of International Calls: %f\n"
            ,hd->call[INTERNATIONAL].p_freq);
    fprintf(fp, "Prob. of Number of Premium Calls: %f\n"
            ,hd->call[PREMIUM].p_freq);
    fprintf(fp, "Prob. of Number of Domestic Calls: %f\n"
            ,hd->call[DOMESTIC].p_freq);
    fprintf(fp, "Prob. of Number of Service Calls: %f\n"
            ,hd->call[SERVICE].p_freq);
    fprintf(fp, "Prob. of Number of Emergency Calls: %f\n"
            ,hd->call[EMERGENCY].p_freq);
    fprintf(fp, "Duration of Mobile Calls: %d\n", hd->call[MOBILE].dur);
    fprintf(fp, "Duration of International Calls: %d\n"
            ,hd->call[INTERNATIONAL].dur);
    fprintf(fp, "Duration of Premium Calls: %d\n", hd->call[PREMIUM].dur);
    fprintf(fp, "Duration of Domestic Calls: %d\n", hd->call[DOMESTIC].dur);
    fprintf(fp, "Duration of Service Calls: %d\n", hd->call[SERVICE].dur);
    fprintf(fp, "Duration of Emergency Calls: %d\n", hd->call[EMERGENCY].dur);
    fprintf(fp, "Duration of Total Calls: %"PRIu64"\n", hd->dur_total);
    fprintf(fp, "Prob. of Duration of mobile calls: %f\n"
            ,hd->call[MOBILE].p_dur);
    fprintf(fp, "Prob. of Duration of International Calls: %f\n"
            ,hd->call[INTERNATIONAL].p_dur);
    fprintf(fp, "Prob. of Duration of Premium Calls: %f\n"
            ,hd->call[PREMIUM].p_dur);
    fprintf(fp, "Prob. of Duration of Domestic Calls: %f\n"
            ,hd->call[DOMESTIC].p_dur);
    fprintf(fp, "Prob. of Duration of Service Calls: %f\n"
            ,hd->call[SERVICE].p_dur);
    fprintf(fp, "Prob. of Duration of Emergency Calls: %f\n"
            ,hd->call[EMERGENCY].p_dur);
    fprintf(fp, "Distance Value %f\n", hd->distance_value);
    fprintf(fp, "Mean Deviation Value %f\n", hd->mean_deviation);
    fprintf(fp, "Threshold Value %f\n", hd->threshold);
    fprintf(fp, "********************************************************\n");
}

/**
 * \brief   Function to fetch the config values related to the detection algo
 *          and traning engine.
 *
 * @return returns SIP_OK upon success and SIP_ERROR on failure
 */
int SipAnomalyInitConfValues()
{
    char *senstivity_s = NULL;
    char *interval_s = NULL;
    char *adaptability_s = NULL;
    char *int_dur_s = NULL;
    char *mob_dur_s = NULL;
    char *prem_dur_s = NULL;
    char *start_time_s = NULL;
    char *end_time_s = NULL;
    char *call_fs = NULL;
    char *call_ds = NULL;
    extern uint8_t run_mode;
    char *ending_s = NULL;
    char *calltype_s = NULL;

    /* Get the table name from the database connection information given in
     * the configuration file */
    if (SipConfGet("cdr-database.table", &table) != 1) {
        table = calloc(1, sizeof("cdr"));
        table = "cdr";
    }

    if (SipConfGet("ad-algo.sensitivity", &senstivity_s) == 1) {
        senstivity = atof(senstivity_s);
    } else {
        senstivity = DEFAULT_SENSTIVITY_VALUE;
    }

    if (SipConfGet("ad-algo.adaptability", &adaptability_s) == 1) {
        adaptability = atof(adaptability_s);
    } else {
        adaptability = DEFAULT_ADAPTABILITY_VALUE;
    }

    if (SipConfGet("ad-algo.interval", &interval_s) == 1) {
        interval = atoi(interval_s);
    } else {
        interval = DEFAULT_TIME_INTERVAL;
    }

    if (SipConfGet("call-duration.mobile", &mob_dur_s) == 1) {
        mob_dur = atoi(mob_dur_s) * 60;
    } else {
        mob_dur = DEFAULT_MOBILE_DURATION;
    }

    if (SipConfGet("call-duration.international", &int_dur_s) == 1) {
        int_dur = atoi(int_dur_s) * 60;
    } else {
        int_dur = DEFAULT_INTERNATIONAL_DURATION;
    }

    if (SipConfGet("call-duration.premium", &prem_dur_s) == 1) {
        prem_dur = atoi(prem_dur_s) * 60;
    } else {
        prem_dur = DEFAULT_PREMIUM_DURATION;
    }

    if (SipConfGet("office-time.start_time", &start_time_s) == 1) {
        start_time = atoi(start_time_s);
        start_time -= 1; /* struct tm has hour values from 0-23 */
    } else {
        start_time = DEFAULT_START_TIME;
    }

    if (SipConfGet("office-time.end_time", &end_time_s) == 1) {
        end_time = atoi(end_time_s);
    } else {
        end_time = DEFAULT_END_TIME;
    }

    if (SipConfGet("institution", &accountcode) != 1) {
        SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Institution code has"
        " not been provided in the configuration file. Please provide the code"
        " to start the engine :-)");
        return SIP_ERROR;
    }

    if (SipConfGet("ad-algo.threshold-restore", &thresh_restore) != 1) {
        thresh_restore = calloc(1, 4*sizeof(char));
        thresh_restore = "yes";
    }

    if (SipConfGet("detection-start-ts", &detect_start_ts) != 1) {
        detect_start_ts = NULL;
    }

    if (SipConfGet("ad-algo.call-freq", &call_fs) == 1) {
        call_freq = atoi(call_fs);
    }

    if (SipConfGet("ad-algo.call-duration", &call_ds) == 1) {
        call_dur = atoi(call_ds) * 60;
    }

    if (SipConfGet("ending-date", &ending_s) == 1) {
        struct tm ending_time = {0,0,0,0,0,0,0,0,0};
        strptime(ending_s, "%F %H:%M:%S" ,&ending_time);
        complete_time = mktime(&ending_time);
    } else {
        if (run_mode & SIP_RUN_MODE_OFFLINE) {
            SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "please mention the"
                    " ending time while running in offline mode.");
            return SIP_ERROR;
        }
    }

     if (SipConfGet("call-type", &calltype_s) == 1) {
         char *call_t = strtok(calltype_s, ",");
         while( call_t != NULL ) {

             /* remove the spaces */
             while(isspace(*call_t)) {
                 call_t++;
             }

             if (strncasecmp(call_t, "All", 3) == 0) {
                 hd_detection.call[INTERNATIONAL].flag |= CALLTYPE_ACTIVE;
                 hd_detection.call[INTERNATIONAL].name = "INTERNATIONAL";
                 hd_detection.call[MOBILE].flag |= CALLTYPE_ACTIVE;
                 hd_detection.call[MOBILE].name = "MOBILE";
                 hd_detection.call[PREMIUM].flag |= CALLTYPE_ACTIVE;
                 hd_detection.call[PREMIUM].name = "PREMIUM";
                 hd_detection.call[DOMESTIC].flag |= CALLTYPE_ACTIVE;
                 hd_detection.call[DOMESTIC].name = "DOMESTIC";
                 hd_detection.call[EMERGENCY].flag |= CALLTYPE_ACTIVE;
                 hd_detection.call[EMERGENCY].name = "EMERGENCY";
                 hd_detection.call[SERVICE].flag |= CALLTYPE_ACTIVE;
                 hd_detection.call[SERVICE].name = "SERVICE";
                 break;
             } else if (strncasecmp(call_t, "International", 13) == 0) {
                 hd_detection.call[INTERNATIONAL].flag |= CALLTYPE_ACTIVE;
                 hd_detection.call[INTERNATIONAL].name = "INTERNATIONAL";
             } else if (strncasecmp(call_t, "Mobile", 6) == 0) {
                 hd_detection.call[MOBILE].flag |= CALLTYPE_ACTIVE;
                 hd_detection.call[MOBILE].name = "MOBILE";
             } else if (strncasecmp(call_t, "Premium", 7) == 0) {
                 hd_detection.call[PREMIUM].flag |= CALLTYPE_ACTIVE;
                 hd_detection.call[PREMIUM].name = "PREMIUM";
             } else if (strncasecmp(call_t, "Domestic", 8) == 0) {
                 hd_detection.call[DOMESTIC].flag |= CALLTYPE_ACTIVE;
                 hd_detection.call[DOMESTIC].name = "DOMESTIC";
             } else if (strncasecmp(call_t, "Emergency", 9) == 0) {
                 hd_detection.call[EMERGENCY].flag |= CALLTYPE_ACTIVE;
                 hd_detection.call[EMERGENCY].name = "EMERGENCY";
             } else if (strncasecmp(call_t, "Service", 7) == 0) {
                 hd_detection.call[SERVICE].flag |= CALLTYPE_ACTIVE;
                 hd_detection.call[SERVICE].name = "SERVICE";
             }

             call_t = strtok(NULL, ",");
        }
        SipSetCallTypeString();
    } else {
         SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "please mention atleast one "
                    "calltype for which you want to run the detection engine.");
            return SIP_ERROR;
    }
    return SIP_OK;
}

/**
 * \brief   Function to initialize the detection modeule. It tries to restore
 *          the threshold value from the stored threshold values, if restoration
 *          has been enabled in the config file.
 *
 * @return SIP_THRESHOLD_NOT_RESTORE if threshold has not been restored and
 *         SIP_THRESHOLD_RESTORE if threshold has been restored. Or return
 *         SIP_ERROR if an error has occured
 */
int SipInitAnomalyDetection()
{
    CLEAR_HD(&hd_detection);

    /* Get the default values of configuration parameter from config file */
    if (SipAnomalyInitConfValues() != SIP_OK)
        return SIP_ERROR;

    /* connect to the data base with the provided connection information */
    threshold_conn = SipConnectDB("threshold-database");
    if(PQstatus(threshold_conn) == CONNECTION_BAD) {
        SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed in "
                        "connecting to threshold-database");
        return SIP_ERROR;
    }

    if (SipConfGet("threshold-database.table", &threshold_table) != 1) {
        threshold_table = calloc(1, sizeof("threshold"));
        threshold_table = "threshold";
    }

    char *ts = NULL;
    if (SipConfGet("initial-timestamp", &ts) == 1) {
        last_transaction_ts = strdup(ts);
    }

    if (strncmp(thresh_restore, "no", 2) == 0) {
        return SIP_THRESHOLD_NOT_RESTORE;
    }

    char query[75];
    char *thresh_id = NULL;
    uint64_t threshold_id = 0;

    snprintf(query, sizeof(query), "select max(threshold_id) from %s",
                threshold_table);
    PGresult *res = SipGetCdr(threshold_conn, query);
    if (res == NULL) {
        SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed in making the"
                " given query \"%s\"", query);
        return SIP_THRESHOLD_NOT_RESTORE;
    }

    thresh_id = PQgetvalue(res, 0, 0);
    threshold_id = strtoul(thresh_id, NULL, 10);
    PQclear(res);

    if (threshold_id > 0) {
        if (last_transaction_ts == NULL) {
            last_transaction_ts = (char *) calloc(1, (25 * sizeof (char)));
            if (last_transaction_ts == NULL) {
                SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "failed in "
                        "allocating memory");
                return SIP_ERROR;
            }
        }

        snprintf(query, 75, "select * from %s where threshold_id='%"PRIu64"'",
                threshold_table, threshold_id);
        res = SipGetCdr(threshold_conn, query);
        if (res == NULL) {
            SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed in making "
                    "the given query \"%s\"", query);
            return SIP_THRESHOLD_NOT_RESTORE;
        }

        /* Restore the threshold values from the threshold database with the
         * last threshold values stored in the database */
        char *temp = NULL;
        uint8_t cnt = 0;
        uint8_t col_cnt = 1;
        for (cnt = 0; cnt < MAX_CALLTYPE; cnt++) {
            temp = PQgetvalue(res, 0, col_cnt);
            hd_detection.call[cnt].num = atoi(temp);
            col_cnt++;
            temp = PQgetvalue(res, 0, col_cnt);
            hd_detection.call[cnt].dur = atoi(temp);
            col_cnt++;
            temp = PQgetvalue(res, 0, col_cnt);
            hd_detection.call[cnt].p_freq = atof(temp);
            col_cnt++;
            temp = PQgetvalue(res, 0, col_cnt);
            hd_detection.call[cnt].p_dur = atof(temp);
            col_cnt++;
        }
        temp = PQgetvalue(res, 0, col_cnt);
        hd_detection.num_total = atol(temp);
        col_cnt++;
        temp = PQgetvalue(res, 0, col_cnt);
        hd_detection.dur_total = atol(temp);
        col_cnt++;
        temp = PQgetvalue(res, 0, col_cnt);
        hd_detection.distance_value = atof(temp);
        col_cnt++;
        temp = PQgetvalue(res, 0, col_cnt);
        hd_detection.mean_deviation = atof(temp);
        col_cnt++;
        temp = PQgetvalue(res, 0, col_cnt);
        hd_detection.threshold = atof(temp);
        col_cnt++;
        temp = PQgetvalue(res, 0, col_cnt);
        strncpy(last_transaction_ts, temp, strlen(temp));
        PQclear(res);

        /* Initialize the current_time struct, which will be used for interval
         * advancement */
        strptime(last_transaction_ts, "%F %H:%M:%S" ,&current_time);

        if (detect_start_ts != NULL) {
            SipSetTimeStamp(&current_time, detect_start_ts);
        }
        SipLog(SIP_LOG_INFO, SIP_LOG_LOCATION, "Engine has been"
                " restored from the timestamp %s", last_transaction_ts);
        hd_detection.flags |= THRESHOLD_RESTORED;
        return SIP_THRESHOLD_RESTORE;
    }

    return SIP_THRESHOLD_NOT_RESTORE;
}

/**
 * \brief Function to store the current threshold value in the threshold databse
 *        which will be used for restoring the detection engine upon failure or
 *        restart.
 *
 * @return returns SIP_OK upon success and SIP_ERROR on failure
 */
int SipAnomalyStoreThreshold()
{
    char query[1000];

    snprintf(query, sizeof (query), "insert into %s(num_int,dur_int,p_fint,"
            "p_dint,num_mob,dur_mob,p_fmob,p_dmob,num_prem,dur_prem,p_fprem,"
            "p_dprem,num_ser,dur_ser,p_fser,p_dser,num_dom,dur_dom,p_fdom,"
            "p_ddom,num_emr,dur_emr,p_femr,p_demr,num_total,dur_total,"
            "dist_value, mean_dev,threshold, last_ts) "
            "values ('%"PRIu32"','%"PRIu32"','%f','%f',"
            "'%"PRIu32"','%"PRIu32"','%f','%f','%"PRIu32"','%"PRIu32"','%f','%f',"
            "'%"PRIu32"','%"PRIu32"','%f','%f','%"PRIu32"','%"PRIu32"','%f','%f',"
            "'%"PRIu32"','%"PRIu32"','%f','%f','%"PRIu64"','%"PRIu64"','%f','%f',"
            "'%f','%s')", threshold_table, hd_detection.call[INTERNATIONAL].num,
            hd_detection.call[INTERNATIONAL].dur,
            hd_detection.call[INTERNATIONAL].p_freq,
            hd_detection.call[INTERNATIONAL].p_dur,hd_detection.call[MOBILE].num,
            hd_detection.call[MOBILE].dur, hd_detection.call[MOBILE].p_freq,
            hd_detection.call[MOBILE].p_dur,hd_detection.call[PREMIUM].num,
            hd_detection.call[PREMIUM].dur, hd_detection.call[PREMIUM].p_freq,
            hd_detection.call[PREMIUM].p_dur,hd_detection.call[SERVICE].num,
            hd_detection.call[SERVICE].dur, hd_detection.call[SERVICE].p_freq,
            hd_detection.call[SERVICE].p_dur,hd_detection.call[DOMESTIC].num,
            hd_detection.call[DOMESTIC].dur, hd_detection.call[DOMESTIC].p_freq,
            hd_detection.call[DOMESTIC].p_dur,hd_detection.call[EMERGENCY].num,
            hd_detection.call[EMERGENCY].dur, hd_detection.call[EMERGENCY].p_freq,
            hd_detection.call[EMERGENCY].p_dur,hd_detection.num_total,
            hd_detection.dur_total, hd_detection.distance_value,
            hd_detection.mean_deviation, hd_detection.threshold,
            last_transaction_ts);

    PGresult *res = PQexec(threshold_conn, query);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed in inserting"
                " the given values \"%s\"", query);
        PQclear(res);
        return SIP_ERROR;
    }

    PQclear(res);
    return SIP_OK;
}
/**
 * \brief   Function to initialize the threshold value. It fetches the first
 *          two cdr records for the given time interval and initialize the engine
 * 
 * @param conn  Pointer to the CDR database
 * @return returns SIP_OK upon success and SIP_ERROR on failure
 */
int SipTrainingInitThreshold(PGconn *conn)
{
    PGresult *result = NULL;
    Hd hd_train_init;
    char query[DEFAULT_QUERY_SIZE];

    CLEAR_HD(&hd_train_init);

    if (last_transaction_ts == NULL) {
        snprintf(query, DEFAULT_QUERY_SIZE, "select extract(epoch from "
                "calldate) from %s order by id limit 2", table);

        last_transaction_ts = (char *) calloc(1, (25 * sizeof (char)));
        if (last_transaction_ts == NULL) {
            SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "failed in "
                    "allocating memory");
            return SIP_ERROR;
        }

        /* Fetch the initial timestamp data from the cdr database with the given
         * query */
        result = (PGresult *) SipGetCdr(conn, query);
        if (result == NULL) {
            SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed in making "
                    "the given query \"%s\"", query);
            return SIP_ERROR;
        }

        strncpy(last_transaction_ts, PQgetvalue(result, 1, 0),
                strlen(PQgetvalue(result, 1, 0)));

        /* Convert to timetsamp value */
        strptime(last_transaction_ts, "%s" ,&current_time);
        SipUpdateTimeStamp(0);
        PQclear(result);
    } else {
        strptime(last_transaction_ts, "%F %H:%M:%S" ,&current_time);
    }

    //printf("ts is %s\n", last_transaction_ts);
    /* Initialize the initial hellinger distance value */
    SipGetQuery(query, last_transaction_ts, interval);
    result = (PGresult *)SipGetCdr(conn, query);
    if (result == NULL) {
        SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed in making the"
                " given query \"%s\"", query);
        return SIP_ERROR;
    }

    /* Get different call type data */
    SipGetCallData(&hd_train_init, result);

    /* Calculate the probablity for each call type */
    SipCalcHDProbabilities(&hd_train_init);

    PQclear(result);

    SipUpdateTimeStamp(interval);
    SipGetQuery(query, last_transaction_ts, interval);
    result = (PGresult *)SipGetCdr(conn, query);
    if (result == NULL) {
        SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed in making the"
                " given query \"%s\"", query);
        return SIP_ERROR;
    }

    /* Get different call type data */
    SipGetCallData(&hd_detection, result);
    PQclear(result);

    /* Calculate the probablity for each call type */
    SipCalcHDProbabilities(&hd_detection);

    /* Calculate the initial hellinger distance value to be stored in
     * hd_detection */
    SipCalcHellingerDistance(&hd_train_init, &hd_detection);

    /* Initialize the threshold values*/
    SipUpdateHDThreshold(&hd_detection, &hd_train_init);

    /* Update the timestamp to fetch date for next time interval. The increment
     * is equal to 10 minutes */
    SipUpdateTimeStamp(interval);

    return SIP_OK;
}

/**
 * \brief   Function to train the detection module. It trains the anomaly
 *          detection algorithm over the training dataset and initializes the
 *          threshold value.
 *
 * @param conn  Pointer to the CDR database
 * @return returns SIP_OK upon success and SIP_ERROR on failure
 */
int SipTrainingAnomalyDetection(PGconn *conn)
{
    PGresult *result = NULL;
    Hd hd_train;
    char query[DEFAULT_QUERY_SIZE];

    /* Fetch the required data from the cdr database with the given query for
     * next interval */
    SipGetQuery(query, last_transaction_ts, interval);
    result = (PGresult *)SipGetCdr(conn, query);
    if (result == NULL) {
        SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed in making the"
                " given query \"%s\"", query);
        return SIP_ERROR;
    }

    CLEAR_HD(&hd_train);

    /* Get different call type data */
    SipGetCallData(&hd_train, result);
    PQclear(result);

    /* Calculate the probablity for each call type */
    SipCalcHDProbabilities(&hd_train);

    /* Calculate the initial hellinger distance value to be stored in
     * hd_detection */
    SipCalcHellingerDistance(&hd_detection, &hd_train);

    /* Initialize the threshold values*/
    if (hd_train.distance_value > 0)
        SipUpdateHDThreshold(&hd_detection, &hd_train);

    /* Update the timestamp to fetch date for next time interval. The increment
     * is equal to 10 minutes */
    SipUpdateTimeStamp(interval);

    //SipPrintHD(&hd_train, stdout);
    return SIP_OK;
}

/**
 * \brief   Function to detect the anomaly using the trained hellinger
 *          distance algorithm over the testing period. After initialization
 *          new threshold value will be calculated which will reflect the
 *          current traffic bahavior of the institute.
 *
 * @param conn      Pointer to the CDR database
 * @param result    pointer to the result which will contains the call data
 * 
 * @return returns TRUE upon anomaly detection and FALSE upon normal behavior
 */
int SipAnomalyDetection(PGconn *conn, PGresult **result)
{
    Hd hd_testing;
    int ret_value = FALSE;
    char query[DEFAULT_QUERY_SIZE];

    /* Initialize the timestamp to start detection from the given detection
     * start time in the config file */
    if (detect_start_ts != NULL && !(hd_detection.flags & THRESHOLD_RESTORED)) {
        strncpy(last_transaction_ts, detect_start_ts,
                strlen(last_transaction_ts));
        detect_start_ts = NULL;
        strptime(last_transaction_ts, "%F %H:%M:%S" ,&current_time);
    }

    /* Fetch the required data from the cdr database with the given query for
     * next interval */
    SipGetQuery(query, last_transaction_ts, interval);
    *result = (PGresult *)SipGetCdr(conn, query);
    if (*result == NULL) {
        SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed in making the"
                " given query \"%s\"", query);
        return SIP_ERROR;
    }

    CLEAR_HD(&hd_testing);

    /* Get different call type data */
    SipGetCallData(&hd_testing, *result);

    /* Calculate the probablity for each call type */
    SipCalcHDProbabilities(&hd_testing);

    /* Calculate the initial hellinger distance value to be stored in
     * hd_detection */
    SipCalcHellingerDistance(&hd_detection, &hd_testing);

    if (hd_testing.distance_value > hd_detection.threshold)
    {
        if ((current_time.tm_hour > start_time) &&
                (current_time.tm_hour < end_time))
        {
            if (hd_testing.call[MOBILE].dur > mob_dur ||
                    (hd_testing.call[INTERNATIONAL].dur > int_dur) ||
                    (hd_testing.call[PREMIUM].dur > prem_dur) ||
                    ((hd_testing.call[INTERNATIONAL].num >
                        senstivity*hd_detection.call[INTERNATIONAL].num) &&
                    (hd_detection.call[INTERNATIONAL].num > 0)) ||
                    ((hd_testing.call[PREMIUM].num >
                        senstivity*hd_detection.call[PREMIUM].num) &&
                    (hd_detection.call[PREMIUM].num > 0)))
            {
                ret_value = TRUE;
            } else if ((hd_testing.call[DOMESTIC].flag & CALLTYPE_ACTIVE) ||
                        (hd_testing.call[SERVICE].flag & CALLTYPE_ACTIVE) ||
                        (hd_testing.call[EMERGENCY].flag & CALLTYPE_ACTIVE))
            {
                ret_value = TRUE;
            }
        } else if (hd_testing.call[MOBILE].dur > mob_dur ||
                    (hd_testing.call[INTERNATIONAL].num >
                        (hd_testing.num_total/senstivity)) ||
                    (hd_testing.call[PREMIUM].num > (hd_testing.num_total/senstivity)))
        {
            ret_value = TRUE;
        } else if ((hd_testing.call[DOMESTIC].flag & CALLTYPE_ACTIVE) ||
                        (hd_testing.call[SERVICE].flag & CALLTYPE_ACTIVE) ||
                        (hd_testing.call[EMERGENCY].flag & CALLTYPE_ACTIVE))
            {
                ret_value = TRUE;
            }
    } else if (hd_testing.distance_value > 0) {
        SipUpdateHDThreshold(&hd_detection, &hd_testing);
    }

    /* Update the timestamp to fetch date for next time interval. The increment
     * is equal to given interval minutes */
    if (SipUpdateTimeStamp(interval) == SIP_DONE)
        return SIP_DONE;

    return ret_value;
}

/**
 * \brief   Function to clear the memory and close the connection to threshold
 *          database, while shutting down the engine.
 */
void SipDeinitAnomalyDetection()
{
    if (last_transaction_ts != NULL) {
        free (last_transaction_ts);
    }

    if (threshold_conn != NULL) {
        PQfinish(threshold_conn);
    }

    if (calltype != NULL) {
        free (calltype);
    }

}