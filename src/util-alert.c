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

#include "sipade.h"
#include "util-alert.h"
#include "util-log.h"
#include "util-detection.h"
#include "util-cdr.h"
#include "util-conf.h"

static SipAlertCtx *iface_ctx = NULL;
static PGconn *alert_conn = NULL;
static char *alert_table = NULL;
static uintmax_t alert_id = 0;
static char *institution = NULL;


/**
 * \brief   Initializes the default alerting context, which will contains the
 *          information to the alert interface.
 */
int SipAlertInitCtx()
{
    iface_ctx = calloc(1, sizeof (SipAlertCtx));
    if (iface_ctx == NULL) {
        SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "error in allocating"
                " the memroy");
        return SIP_ERROR;
    }
    return SIP_OK;
}

/**
 * \brief   Funtion to initialize the Syslog alert interface, it opens a
 *          conneciton to the syslog file to which we will later log the
 *          status messages.
 */
void SipAlertInitSyslogIface()
{
    iface_ctx->iface |= SIP_ALERT_IFACE_SYSLOG;
    openlog(NULL, LOG_NDELAY, LOG_USER);

    SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION, "syslog interface is "
            "initialized");
}

/**
 * \brief   Funtion to initialize the Hobbit alert interface, it opens the
 *          file to which we will later log the status messages. The hobbit
 *          client is reading the file and sending the status to the hobbit
 *          server, which interpretes the status and act accordingly.
 */
int SipAlertInitHobbitIface()
{
    char *filename;

    /* Set the alert interface as hobbit */
    iface_ctx->iface |= SIP_ALERT_IFACE_HOBBIT;
    /* Ge the filename from the config file, to which we will write the alert */
    if (SipConfGet("alert-file", &filename) != 1) {
        iface_ctx->filename = calloc(1, sizeof("/home/ica/stud/guri/"
                                               "sip_alert.txt"));
        iface_ctx->filename = "/home/ica/stud/guri/sip_alert.txt";
    } else {
        iface_ctx->filename = strdup(filename);
    }

    /* Open the given file, so that we can write the alerts to it */
    iface_ctx->file_descr = fopen(iface_ctx->filename, "w");
    if (iface_ctx->file_descr == NULL) {
        SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed in opening the"
                " \"%s\" file. Check the permission for destination"
                " directory!!", iface_ctx->filename);
        return SIP_ERROR;
    }

    if (SipConfGet("institution", &institution) != 1) {
        SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Institution code has"
        " not been provided in the configuration file. Please provide the code"
        " to start the engine :-)");

        return SIP_ERROR;
    }

    SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION, "Hobbit interface is "
            "initialized");
    return SIP_OK;
}

/**
 * \brief   Funtion to initialize the alert module to which we will later log
 *          the status messages.
 */
int SipAlertInitNotification()
{
    char *alert_mode;
    char conn_info[200];

    /*Initialize the Sip Alert Context */
    SipAlertInitCtx();

    /* Get the alert mode from the configuration file and intialize the
     *  corresponding mode to use fot alerting for anomalies */
    if (SipConfGet("alert-mode", &alert_mode) == 1) {

        if (strcmp(alert_mode, "syslog") == 0) {
            SipAlertInitSyslogIface();
        } else if (strcmp(alert_mode, "hobbit") == 0) {
            if (SipAlertInitHobbitIface() != SIP_OK)
                return SIP_ERROR;
        } else if (strcmp(alert_mode, "both") == 0) {
            SipAlertInitSyslogIface();
            if (SipAlertInitHobbitIface() != SIP_OK)
                return SIP_ERROR;
        }
    /*Default is syslog mode*/
    } else {
        SipAlertInitSyslogIface();
    }

    /* connect to the data base with the provided connection information */
    alert_conn = SipConnectDB("alert-database");
    if(PQstatus(alert_conn) == CONNECTION_BAD) {
        SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed in "
                        "connection to database: %s", conn_info);
        return SIP_ERROR;
    }

    if (SipConfGet("alert-database.table", &alert_table) != 1) {
        alert_table = calloc(1, sizeof("cdr_alert"));
        alert_table = "cdr_alert";
    }

    return SIP_OK;
}

/**
 * \brief   Function to log the transactions related to the interval, in which
 *          anomaly has been detected. It will log all the calls in that interval
 *          which are of international, mobile or permium type.
 *
 * @param result        pointer to the result which contains the call data
 *
 * @return  on success it returns SIP_OK and on failure SIP_ERROR
 */
int SipAlertLogDB(PGresult *result)
{
    PGresult *res = NULL;
    uint32_t row = 0;
    uint32_t row_cnt = 0;
    char query [500];
    char *id = NULL;
    char *calldate = NULL;
    char *src = NULL;
    char *dst = NULL;
    char *billsec = NULL;
    char *calltype = NULL;
    char *accountcode = NULL;
    char query_id[] = "select max(alert_id) from cdr_alert";
    char *alert = NULL;

    res = PQexec(alert_conn, query_id);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed in making the"
                " given query \"%s\"", query);
        PQclear(res);
        return SIP_ERROR;
    }

    alert = PQgetvalue(res, 0, 0);
    alert_id = strtoumax(alert, NULL, 10);
    alert_id++;
    PQclear(res);

    row_cnt = PQntuples(result);

    for (row = 0; row < row_cnt; row++) {
        id = PQgetvalue(result,row,0);
        calldate = PQgetvalue(result,row,1);
        src = PQgetvalue(result,row,2);
        dst = PQgetvalue(result,row,3);
        billsec = PQgetvalue(result,row,4);
        calltype = PQgetvalue(result,row,5);
        accountcode = PQgetvalue(result, 0, 6);
        snprintf(query, sizeof(query), "insert into %s(alert_id, cdr_id,"
                "calldate,src,dst,billsec,calltype,accountcode) values "
                "('%"PRIuMAX"','%s','%s','%s','%s','%s','%s','%s')",
                alert_table, alert_id, id, calldate, src, dst, billsec,
                calltype, accountcode);

        res = PQexec(alert_conn, query);
        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed in inserting"
                    " the given values \"%s\"", query);
            PQclear(res);
            return SIP_ERROR;
        }
        PQclear(res);
    }

    return SIP_OK;
}

/**
 * \brief   Function to log the status alerts to the alert file. The file
 *          is monitored by xymon, which on alert will send the alerts to
 *          responsible person at the target institution in given method
 *          such as email, sms etc.
 *
 * @param status        Status of the SIP system to be logged in to the file
 * @param result        pointer to the result which contains the call data
 * 
 */
void SipAlertNotification(char *status, PGresult **result)
{
    char status_msg[100];

    /* If the status is OK and we are in syslog mode, then no need to log it to
     * the syslog */
    if ((strncmp(status, SIP_STATUS_OK, 2) == 0) &&
            iface_ctx->iface == SIP_ALERT_IFACE_SYSLOG)
    {
        return;
    }

    if (strncmp(status, SIP_STATUS_ALERT, 5) == 0) {
        if (SipAlertLogDB(*result) != SIP_OK) {
            SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed in logging"
                    " alerts to alert_database");
            return;
        }

        snprintf(status_msg, 100, "[%s]    %s  %s  %"PRIuMAX"\n",
                SipGetTimeStamp(), status, institution, alert_id);
    } else {
        snprintf(status_msg, 100, "[%s]    %s     %s\n", SipGetTimeStamp(),
                status, institution);
    }

    /* write to the corresponding alert module as provided in the configuration
     * file */
    switch (iface_ctx->iface) {
        case SIP_ALERT_IFACE_HOBBIT:
            if (fwrite(status_msg, 1, strlen(status_msg), iface_ctx->file_descr)
                    == 0)
            {
                SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed in "
                        "writing to the file: %s", iface_ctx->filename);
            }
            break;
        case SIP_ALERT_IFACE_SYSLOG:
            if (strcmp(status, "OK") == 0) {
                syslog(LOG_INFO, "%s", status_msg);
            } else {
                syslog(LOG_ALERT, "%s", status_msg);
            }
            break;
        case SIP_ALERT_IFACE_HOBBIT | SIP_ALERT_IFACE_SYSLOG:
            if (fwrite(status_msg, 1, strlen(status_msg), iface_ctx->file_descr)
                    == 0)
            {
                SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed in "
                        "writing to the file: %s", iface_ctx->filename);
            }

            if (strcmp(status, "OK") == 0) {
                syslog(LOG_INFO, "%s", status_msg);
            } else {
                syslog(LOG_ALERT, "%s", status_msg);
            }
            break;
        default:
            SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "invalid alert"
                    " mode");
            break;
    }

}

/**
 * \brief   Function to de-init the alert module and clears the memory allocated
 *          to the alert module. It closes the alert connection to the database
 *          and also the open descriptor the alert mode.
 */
void SipAlertDeInitCtx()
{
    if (iface_ctx != NULL) {
        switch (iface_ctx->iface) {
            case SIP_ALERT_IFACE_HOBBIT:
                if (iface_ctx->file_descr != NULL)
                    fclose(iface_ctx->file_descr);
                if (iface_ctx->filename != NULL)
                    free(iface_ctx->filename);
                break;
            case SIP_ALERT_IFACE_SYSLOG:
                closelog();
                break;
            case SIP_ALERT_IFACE_HOBBIT | SIP_ALERT_IFACE_SYSLOG:
                if (iface_ctx->file_descr != NULL)
                    fclose(iface_ctx->file_descr);
                if (iface_ctx->filename != NULL)
                    free(iface_ctx->filename);
                closelog();
                break;
            default:
                SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "invalid alert"
                        " mode");
                break;
        }
        free(iface_ctx);
    }
    PQfinish(alert_conn);
    SipLog(SIP_LOG_INFO, SIP_LOG_LOCATION, "Alert module has been "
            "de-initialized");
}