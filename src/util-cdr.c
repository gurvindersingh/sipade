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
 * File:   util-cdr.c
 * Author: Gurvinder Singh <gurvinder.singh@uninett.no>
 */

#include "sipade.h"
#include "util-cdr.h"
#include "util-log.h"
#include "util-conf.h"

/**
 * \brief Function to make the connection to the cdr database.
 *
 * @return upon success, it returns pointer to the connection of cdr database,
 *         upon failure it returns NULL
 */
PGconn *SipInitCdr()
{
    PGconn *conn = SipConnectDB("cdr-database");
    if (conn == NULL) {
        return NULL;
    }

    return conn;
}
/**
 * \brief Function used to connect to the given data base with the provided
 *        credentials. It fecthes the credentials from the config file for the
 *        given database.
 *
 * @param conn_dbname   pointer to the database name to which connection has to
 *                      be made.
 *
 * @return  on success it returns the PGconn object, on failure programs will
 *          exit as it is a fatal error.
 */
PGconn *SipConnectDB(char *conn_dbname)
{
    char *host;
    char *dbname;
    char *user;
    char * password;
    char *port;
    char conn_info[200];
    PGconn *conn = NULL;
    char node_name[50];

    /* Get the database connection information from the configuration file */
    snprintf(node_name, sizeof(node_name), "%s.host",conn_dbname);
    if (SipConfGet(node_name, &host) != 1) {
        host = calloc(1, sizeof("localhost"));
        host = "localhost";
    }

    snprintf(node_name, sizeof(node_name), "%s.username",conn_dbname);
    if (SipConfGet(node_name, &user) != 1) {
        user = calloc(1, sizeof("postgres"));
        user = "postgres";
    }

    snprintf(node_name, sizeof(node_name), "%s.password",conn_dbname);
    if (SipConfGet(node_name, &password) != 1) {
        password = NULL;
    }

    snprintf(node_name, sizeof(node_name), "%s.database-name",conn_dbname);
    if (SipConfGet(node_name, &dbname) != 1) {
        dbname = calloc(1, sizeof("mydb"));
        dbname = "mydb";
    }

    snprintf(node_name, sizeof(node_name), "%s.port",conn_dbname);
    if (SipConfGet(node_name, &port) != 1) {
        port = calloc(1, sizeof("5432"));
        port = "5432";
    }

    if (password != NULL) {
        sprintf(conn_info, "dbname=%s host=%s port=%s user=%s password=%s "
                "sslmode=disable",  dbname, host, port, user, password);
    } else {
        sprintf(conn_info, "dbname=%s host=%s port=%s user=%s "
                "sslmode=disable",  dbname, host, port, user);
    }

    /* connect to the data base with the provided connection information */
    conn = PQconnectdb(conn_info);
    if(PQstatus(conn) == CONNECTION_BAD) {
        SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed in making the"
                " connection \"%s\"", conn_info);
    }

    /* we don't need to keep password in the memory any longer */
    if (password != NULL)
        memset(password, 0, strlen(password));

    return conn;
}

/**
 * \brief   Function to make the given query to the databse connected to the
 *          conn object
 *
 * @param conn  Connection to the provided data base
 * @param query Query string which tells that what data is required
 *
 * @return On failure function returns null pointer, otherwise the function
 *         returns the Pgresult object which points to the required data
 * 
 */
PGresult *SipGetCdr(PGconn *conn, const char *query)
{
    PGresult *result = NULL;

    /* Get the required data from the data base connected to the given
     * connection */
    result = PQexec(conn, query);
    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed in making the"
                " given query \"%s\"", query);
        PQclear(result);
        return NULL;
    }

    return result;
}