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
 * File:   util-conf.h
 * Author: Gurvinder Singh <gurvinder.singh@uninett.no>
 */

#ifndef _UTIL_CONF_H
#define	_UTIL_CONF_H

#include <yaml.h>
#include <errno.h>
#include "queue.h"

/* YAML library version */
#define YAML_MAJOR_VER  1
#define YAML_MINOR_VER  1

/* Configuration parsing state */
#define CONF_STATE_KEY      0
#define CONF_STATE_VALUE    1

/* Default name length for nodes in the configuration file */
#define DEFAULT_NODE_NAME_LEN   24

/**
 * Structure of a configuration parameter.
 */
typedef struct SipConfNode_ {
    char *name;
    char *val;

    int is_seq;
    int allow_override;

    struct SipConfNode_ *parent;
    TAILQ_HEAD(, SipConfNode_) head;
    TAILQ_ENTRY(SipConfNode_) next;
} SipConfNode;

int SipConfYamlLoadFile(const char *);
int SipConfInit(const char *);
const char *SipConfNodeLookupChildValue(SipConfNode *, const char *);
SipConfNode *SipConfGetNode(char *);
void SipConfDeInit(void);
int SipConfGet(char *, char **);

#endif	/* _UTIL_CONF_H */

