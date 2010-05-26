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
 *
 * Reference: - configuration file parser from Suricata IDPS project.
 *              (Thanks to jason ish)
 */

#include "sipade.h"
#include "util-conf.h"
#include "util-log.h"

static SipConfNode *root = NULL;

/**
 * \brief Allocate a new configuration node.
 *
 * @retval An allocated configuration node on success, NULL on failure.
 */
SipConfNode *SipConfNodeNew(void)
{
    SipConfNode *new;

    new = calloc(1, sizeof(*new));
    if (new == NULL) {
        SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Error allocating "
                "memory for new configuration node");
        exit(EXIT_FAILURE);
    }
    /* By default we allow an override. */
    new->allow_override = 1;
    TAILQ_INIT(&new->head);

    return new;
}

/**
 * \brief Initialize the configuration system.
 *
 * @retval 0 on success, -1 on failure.
 */
int SipConfInit(const char *conf_filename)
{
    if (root != NULL) {
        SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION, "already initialized");
        return SIP_OK;
    }
    root = SipConfNodeNew();
    if (root == NULL) {
        SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "ERROR: Failed to allocate"
                " memory for root configuration node, aborting.");
        exit(EXIT_FAILURE);
    }
    SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION, "configuration module"
            " initialized");

    if (SipConfYamlLoadFile(conf_filename) != 0)
        return SIP_ERROR;

    return SIP_OK;
}

/**
 * \brief Lookup a child configuration node by name.
 *
 * Given a ConfNode this function will lookup an immediate child
 * ConfNode by name and return the child ConfNode.
 *
 * @param node The parent configuration node.
 * @param name The name of the child node to lookup.
 *
 * @retval A pointer the child ConfNode if found otherwise NULL.
 */
SipConfNode *SipConfNodeLookupChild(SipConfNode *node, const char *name)
{
    SipConfNode *child;

    TAILQ_FOREACH(child, &node->head, next) {
        if (strcmp(child->name, name) == 0)
            return child;
    }

    return NULL;
}

/**
 * \brief Get the root configuration node.
 */
SipConfNode *SipConfGetRootNode(void)
{
    return root;
}

/**
 * \brief Get a SipConfNode by name.
 *
 * @param key The full name of the configuration node to lookup.
 *
 * @retval A pointer to SipConfNode is found or NULL if the configuration
 *    node does not exist.
 */
SipConfNode *SipConfGetNode(char *key)
{
    SipConfNode *node = root;
    char *saveptr = NULL;
    char *token;

    /* Need to dup the key for tokenization... */
    char *tokstr = strdup(key);

    token = strtok_r(tokstr, ".", &saveptr);
    for (;;) {
        node = SipConfNodeLookupChild(node, token);
        if (node == NULL)
            break;
        token = strtok_r(NULL, ".", &saveptr);
        if (token == NULL)
            break;
    }
    free(tokstr);
    return node;
}

/**
 * \brief Retrieve the value of a configuration node.
 *
 * This function will return the value for a configuration node based
 * on the full name of the node.  It is possible that the value
 * returned could be NULL, this could happen if the requested node
 * does exist but is not a node that contains a value, but contains
 * children ConfNodes instead.
 *
 * @param name Name of configuration parameter to get.
 * @param vptr Pointer that will be set to the configuration value parameter.
 *   Note that this is just a reference to the actual value, not a copy.
 *
 * @retval 1 will be returned if the name is found, otherwise 0 will
 *   be returned.
 */
int SipConfGet(char *name, char **vptr)
{
    SipConfNode *node = SipConfGetNode(name);
    if (node == NULL) {
        SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION, "failed to lookup "
                "configuration parameter '%s'", name);
        return 0;
    }
    else {
        *vptr = node->val;
        return 1;
    }
}

/**
 * \brief Free a ConfNode and all of its children.
 *
 * @param node The configuration node to free.
 */
void SipConfNodeFree(SipConfNode *node)
{
    SipConfNode *tmp;

    while ((tmp = TAILQ_FIRST(&node->head))) {
        TAILQ_REMOVE(&node->head, tmp, next);
        SipConfNodeFree(tmp);
    }

    if (node->name != NULL)
        free(node->name);
    if (node->val != NULL)
        free(node->val);
    free(node);
}

/**
 * \brief De-initializes the configuration system.
 */
void SipConfDeInit(void)
{
    if (root != NULL)
        SipConfNodeFree(root);

    SipLog(SIP_LOG_INFO, SIP_LOG_LOCATION, "Configuration module"
            " has been de-initialized");
}

/********************** Load & Parse the config File *******************/

/**
 * \brief Parse a YAML layer.
 *
 * @param parser A pointer to an active yaml_parser_t.
 * @param parent The parent configuration node.
 *
 * @retval SIP_OK on success, SIP_ERROR on failure.
 */
static int SipConfYamlParse(yaml_parser_t *parser, SipConfNode *parent,
        int inseq)
{
    SipConfNode *node = parent;
    yaml_event_t event;
    int done = 0;
    int state = 0;
    int seq_idx = 0;

    while (!done) {
        if (!yaml_parser_parse(parser, &event)) {
            SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed to parse"
                    " configuration file: %s", parser->problem);
            return SIP_ERROR;
        }

        if (event.type == YAML_DOCUMENT_START_EVENT) {
            /* Verify YAML version - its more likely to be a valid
             * configuration file if the version is correct. */
            yaml_version_directive_t *ver =
                event.data.document_start.version_directive;
            if (ver == NULL) {
                SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "ERROR: Invalid"
                        " configuration file.\n");
                SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "The configuration"
                        " file must begin with the following two lines:\n");
                SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "%%YAML 1.1\n---");
                goto fail;
            }
            int major = event.data.document_start.version_directive->major;
            int minor = event.data.document_start.version_directive->minor;
            if (!(major == YAML_MAJOR_VER && minor == YAML_MINOR_VER)) {
                SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "ERROR: Invalid "
                        "YAML version. Must be 1.1");
                goto fail;
            }
        }
        else if (event.type == YAML_SCALAR_EVENT) {
            char *value = (char *)event.data.scalar.value;
            SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION, "event.type = "
                    "YAML_SCALAR_EVENT (%s) inseq=%d", value, inseq);
            if (inseq) {
                SipConfNode *seq_node = SipConfNodeNew();
                seq_node->name = calloc(1, DEFAULT_NODE_NAME_LEN);
                snprintf(seq_node->name, DEFAULT_NODE_NAME_LEN, "%d", seq_idx++);
                seq_node->val = strdup(value);
                TAILQ_INSERT_TAIL(&parent->head, seq_node, next);
            }
            else {
                if (state == CONF_STATE_KEY) {
                    if (parent->is_seq) {
                        if (parent->val == NULL) {
                            parent->val = strdup(value);
                        }
                    }
                    SipConfNode *n0 = SipConfNodeLookupChild(parent, value);
                    if (n0 != NULL) {
                        node = n0;
                    }
                    else {
                        node = SipConfNodeNew();
                        node->name = strdup(value);
                        TAILQ_INSERT_TAIL(&parent->head, node, next);
                    }
                    state = CONF_STATE_VALUE;
                }
                else {
                    if (node->allow_override) {
                        if (node->val != NULL)
                            free(node->val);
                        node->val = strdup(value);
                    }
                    state = CONF_STATE_KEY;
                }
            }
        }
        else if (event.type == YAML_SEQUENCE_START_EVENT) {
            SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION, "event.type = "
                    "YAML_SEQUENCE_START_EVENT");
            if (SipConfYamlParse(parser, node, 1) != 0)
                goto fail;
            state = CONF_STATE_KEY;
        }
        else if (event.type == YAML_SEQUENCE_END_EVENT) {
            SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION, "event.type ="
                    " YAML_SEQUENCE_END_EVENT");
            return SIP_OK;
        }
        else if (event.type == YAML_MAPPING_START_EVENT) {
            SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION, "event.type = "
                    "YAML_MAPPING_START_EVENT");
            if (inseq) {
                SipConfNode *seq_node = SipConfNodeNew();
                seq_node->is_seq = 1;
                seq_node->name = calloc(1, DEFAULT_NODE_NAME_LEN);
                snprintf(seq_node->name, DEFAULT_NODE_NAME_LEN, "%d", seq_idx++);
                TAILQ_INSERT_TAIL(&node->head, seq_node, next);
                SipConfYamlParse(parser, seq_node, 0);
            }
            else {
                SipConfYamlParse(parser, node, inseq);
            }
            state = CONF_STATE_KEY;
        }
        else if (event.type == YAML_MAPPING_END_EVENT) {
            SipLog(SIP_LOG_DEBUG, SIP_LOG_LOCATION, "event.type ="
                    " YAML_MAPPING_END_EVENT");
            done = 1;
        }
        else if (event.type == YAML_STREAM_END_EVENT) {
            done = 1;
        }

        yaml_event_delete(&event);
        continue;

    fail:
        yaml_event_delete(&event);
        return SIP_ERROR;
    }

    return SIP_OK;
}

/**
 * \brief Load configuration from a YAML file.
 *
 * This function will load a configuration file.  On failure -1 will
 * be returned and it is suggested that the program then exit.  Any
 * errors while loading the configuration file will have already been
 * logged.
 *
 * @param filename Filename of configuration file to load.
 *
 * @retval SIP_OK on success, SIP_ERROR on failure.
 */
int SipConfYamlLoadFile(const char *filename)
{
    FILE *infile;
    yaml_parser_t parser;
    int ret;
    SipConfNode *root = SipConfGetRootNode();

    if (yaml_parser_initialize(&parser) != 1) {
        SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed to initialize"
                " yaml parser.\n");
        return SIP_ERROR;
    }

    infile = fopen(filename, "r");
    if (infile == NULL) {
        SipLog(SIP_LOG_ERROR, SIP_LOG_LOCATION, "Failed to open file:"
                " %s: %s\n", filename, strerror(errno));
        yaml_parser_delete(&parser);
        return SIP_ERROR;
    }
    yaml_parser_set_input_file(&parser, infile);
    ret = SipConfYamlParse(&parser, root, 0);
    yaml_parser_delete(&parser);
    fclose(infile);

    return ret;
}