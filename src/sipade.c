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

/* File:   sip-anomaly-detection.c
 * Author: Gurvinder Singh <gurvinder.singh@uninett.no>
 *
 * The SipAD is an anomaly detection system for SIP protocol. It feteches the
 * data from given CDR database and use the Hellinger Distance algorithm for
 * detection. Upon detection of an anomaly it raises an alert, which can be logged
 * in to sip_alert.log file or syslog. The file is later sent to the xymon server
 * which interpret the alert and send the alerts to the target institute via
 * given method such as email, SMS.
 */

#include "sipade.h"
#include "util-cdr.h"
#include "util-detection.h"
#include "util-alert.h"
#include "util-conf.h"
#include "util-log.h"


/********* Global Variables **********/
static PGconn *conn = NULL;    /* Pointer to connect to the CDR databse */
static PGresult *result = NULL;
static uint64_t train_period = 0;
static uint32_t interval = 0;
uint8_t run_mode;


/**
 * \brief   Function to be called, when engine has recieved the Quit, Terminate
 *          or Interrupt signal has been received. It closes the connection to
 *          database and then exit the program.
 */
void SipDone()
{
    SipLog(SIP_LOG_INFO, SIP_LOG_LOCATION, "Shuting down the "
            "engine....");
    PQfinish(conn);
    if (result != NULL) PQclear(result);
    SipConfDeInit();
    SipDeinitAnomalyDetection();
    SipAlertDeInitCtx();
    SipLog(SIP_LOG_INFO, SIP_LOG_LOCATION, "Engine down, Bye !!");
    exit(EXIT_SUCCESS);
}

/**
 *\brief    Function to fetch the config parameter values from the config file
 */
void SipInitConf()
{
    char *tr_period = NULL;
    char *interval_s = NULL;
    char *run_mode_s = NULL;

    if (SipConfGet("training-period", &tr_period) == 1) {
        train_period = strtoul(tr_period, NULL, 10);
    } else {
        train_period = 10080;
    }

    if (SipConfGet("ad-algo.interval", &interval_s) == 1) {
        interval = strtoul(interval_s, NULL, 10);
    } else {
        interval = 10;
    }

    if (SipConfGet("run-mode", &run_mode_s) == 1) {
        if (strncmp(run_mode_s, "online", 6) == 0) {
            run_mode = SIP_RUN_MODE_ONLINE;
        } else {
            run_mode = SIP_RUN_MODE_OFFLINE;
        }
    } else {
        run_mode = SIP_RUN_MODE_OFFLINE;
    }
}
/**
 * \brief   The main entry function for the detection system. It initializes the
 *          all module of the system and calls the detection module to
 *          detect the anomaly. If anomaly detected it asks the alert
 *          notification module to log the status.
 * 
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char** argv)
{
    signal(SIGTERM, SipDone);
    signal(SIGINT, SipDone);
    signal(SIGQUIT, SipDone);
    char *conf_filename = NULL;
    char training_complete = FALSE;
    uint64_t sleep_t = 0;
    int ret = 0;
    char run_detection = TRUE;

    /* Get the config file path name */
    if (argc > 2 && (strcmp("-c", argv[1]) == 0)) {
        conf_filename = argv[2];
    } else {
        conf_filename = (char *)calloc(1, sizeof(SIP_CONF_FILE_PATH));
        if (conf_filename == NULL) {
            SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Usage: ./sipad -c <path"
                    " to config file>");
            exit(EXIT_FAILURE);
        }
        conf_filename = SIP_CONF_FILE_PATH;
    }

    /* Initialize the config module */
    if (SipConfInit(conf_filename) != SIP_OK)
        SipDone();

    /* Initilize the logging module */
    SipInitLog();

    /* Initialize the CDR databse module and make a connection to the database */
    conn = (PGconn *)SipInitCdr();
    if (PQstatus(conn) == CONNECTION_BAD)
        SipDone();

    /* Initialize the Alert notification module */
    if (SipAlertInitNotification() != SIP_OK)
        SipDone();

    /* Get the default values to be used here in main() from the config file */
    SipInitConf();

    /* Check if we have previous threshold value */
    ret = SipInitAnomalyDetection();
    if (ret == SIP_ERROR) {
        SipDone();
    } else if (ret != SIP_THRESHOLD_RESTORE) {
        SipLog(SIP_LOG_INFO, SIP_LOG_LOCATION, "Training the engine for"
                " detection of anomalous behavior...");
        /*Initialize the Anomaly detection module */
        if (SipTrainingInitThreshold(conn) != SIP_OK)
            SipDone();

        while (training_complete == FALSE) {
            sleep_t += interval;
            /* Train for one week (10080 minutes) with increment of given
             * interval */
            if (sleep_t >= train_period) {
                training_complete = TRUE;
                sleep_t = 1;
            }

            /* pass the connection pointer to the anomaly detection function to
             * train the hellinger distance algorithm over the correct data
             * without any attack in it */
            if (SipTrainingAnomalyDetection(conn) == SIP_ERROR) {
                SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed in "
                        "training the engine..");
                SipDone();
            }

            usleep(1);
        }
    }

    /* Store the threshold obtained from the training and timestamp value in to
     * the database */
    if (SipAnomalyStoreThreshold() != SIP_OK)
        SipDone();

    SipLog(SIP_LOG_INFO, SIP_LOG_LOCATION, "SIP Anomaly Detection "
                "Engine has been started successfully...");

    while (1) {
        if (run_detection == TRUE) {
            /* pass the connection pointer to the anomaly detection function to
             * detect the anomalies by fetching the required data from CDR
             * database */
            ret = SipAnomalyDetection(conn, &result);
            if (ret == SIP_ERROR) {
                SipDone();
            } else if (ret == SIP_DONE) {
                break;
            } else if (ret == TRUE) {
                SipAlertNotification(SIP_STATUS_ALERT, &result);
            } else {
                //SipAlertNotification(SIP_STATUS_OK, &result);
                /* Store the recent threshold and timestamp value in to the
                 * database */
                if (SipAnomalyStoreThreshold() != SIP_OK)
                    SipDone();
            }

            PQclear(result);
            result = NULL;
        }

        if (run_mode & SIP_RUN_MODE_OFFLINE) {
            usleep(1);
            run_detection = TRUE;
        } else {
            sleep(1);
            sleep_t += 1;
            if (sleep_t > (interval * 60)) {
                run_detection = TRUE;
                sleep_t = 1;
            } else {
                run_detection = FALSE;
            }
        }
    }
    SipDone();
    return (EXIT_SUCCESS);
}

