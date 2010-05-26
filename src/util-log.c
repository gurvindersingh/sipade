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
 * File:   util-log.c
 * Author: Gurvinder Singh <gurvinder.singh@uninett.no>
 */

#include <time.h>
#include "sipade.h"
#include "util-log.h"
#include "util-conf.h"

int log_level = SIP_LOG_ERROR;

/**
 * \brief   Function intialize the log level from the config file
 */
void SipInitLog()
{
    char *mode = NULL;
    if ((SipConfGet("logging-mode", &mode)) == 1) {
        /* check the logging mode given in the config file */
        if (strcmp(mode, "error") == 0) {
            log_level = SIP_LOG_ERROR;
        } else if (strcmp(mode, "info") == 0) {
            log_level = SIP_LOG_INFO;
        } else {
            log_level = SIP_LOG_DEBUG;
        }
    }
}

/**
 * \brief   Function to log the given message with the privded log level to the
 *          given file
 *
 * @param level     log level to which the given message belongs
 * @param filename  pointer to the filename from which the message is going
 *                  to be logged
 * @param line      line number in the given file, from where the message has
 *                  originated
 * @param fmt       pointer format string to print the given message
 */
void SipLog(int level, char *filename, int line, const char *fmt, ...)
{
    if ((log_level > level) || (log_level == 0))
        return;

    char buf[1024];
    va_list args;
    struct timeval tval;
    struct tm *tms = NULL;
    gettimeofday(&tval, NULL);
    tms = localtime(&tval.tv_sec);
    char temp[30];
    snprintf(temp, 30, "%d/%d/%04d -- %02d:%02d:%02d",tms->tm_mday, tms->tm_mon
            + 1, tms->tm_year + 1900, tms->tm_hour, tms->tm_min, tms->tm_sec);

    va_start(args, fmt);

    int r = vsnprintf(buf, 1023, fmt, args);

    if (r < 0) {
        snprintf(buf, 1024, "[vnsprintf returned error %d]", r);
    }

    /* Indicate overflow with a '+' at the end */
    if (r > 1023) {
        buf[1022] = '+';
        buf[1023] = '\0';
    }

    switch(level) {
        case SIP_LOG_INFO:
            fprintf(stdout, "[%s] <INFO> %s\n", temp, buf);
            break;
        case SIP_LOG_DEBUG:
            fprintf(stdout, "[%s] <DEBUG> [%s:%d] %s\n", temp, filename, line,
                    buf);
            break;
        case SIP_LOG_ERROR:
            fprintf(stderr, "[%s] <ERROR> [%s:%d] %s\n", temp, filename, line,
                    buf);
            break;
    }

    va_end(args);
}
