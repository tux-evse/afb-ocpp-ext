/*
 * Copyright (C) 2015-2023 IoT.bzh Company
 * Author: José Bollo <jose.bollo@iot.bzh>
 *
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <argp.h>

#include <json-c/json.h>

#include <libafb/afb-extension.h>
#include <libafb/afb-http.h>
#include <libafb/afb-misc.h>
#include <libafb/afb-wsj1.h>
#include <libafb/utils/websock.h>
#include <stdio.h>

#define OCPP_PROTOCOL      "ocpp1.6"
#define OCPP_REC           "OCPP-REC"
#define OCPP_SND           "OCPP-SND"
#define OCPP_BKAPI         "OCPP-BACK-API"
#define OCPP_BKAPI_PATTERN "x-OCPP-%u"

/* predeclaration of structures */
struct ocpp_item;
struct ocpp_ws;
struct ocpp_req;
typedef struct ocpp_item ocpp_item_t;

/* predeclaration of ocpp_item the ocpp manager */
static int ocpp_config(ocpp_item_t **items, struct json_object *config);
static int ocpp_declare(ocpp_item_t *items, struct afb_apiset *declare_set, struct afb_apiset *call_set);
static int ocpp_http(ocpp_item_t *items, struct afb_hsrv *hsrv);
static int ocpp_serve(ocpp_item_t *items, struct afb_apiset *call_set);
static int ocpp_exit(ocpp_item_t *items, struct afb_apiset *declare_set);

/* predeclaration of ocpp_ws the websocket link instances */
static struct ocpp_ws *ocpp_ws_create_cb(ocpp_item_t *closure, int fd, int autoclose,
		struct afb_apiset *apiset, struct afb_session *session, struct afb_token *token,
		void (*cleanup)(void*), void *cleanup_closure);
static int ocpp_client_create(ocpp_item_t *item);

/*************************************************************/
/*************************************************************/
/** AFB-EXTENSION interface                                 **/
/*************************************************************/
/*************************************************************/

AFB_EXTENSION("OCPP")

const struct argp_option AfbExtensionOptionsV1[] = {
	{ .name="ocpp-client",      .key='c',   .arg="URI", .doc="connect to an OCPP service as API 'OCPP'" },
	{ .name="ocpp-server",      .key='s',   .arg=0, .doc="Adds an 'OCPP' server" },
	{ .name="ocpp-pwd-base64",  .key='p',   .arg="PWD-U64-ENCODE", .doc="Base64 encoded password" },
	{ .name=0, .key=0, .doc=0 }
};

int AfbExtensionConfigV1(void **data, struct json_object *config, const char *uid)
{
	LIBAFB_NOTICE("Extension %s got config %s", AfbExtensionManifest.name, json_object_get_string(config));
	return ocpp_config((ocpp_item_t**)data, config);
}

int AfbExtensionDeclareV1(void *data, struct afb_apiset *declare_set, struct afb_apiset *call_set)
{
	LIBAFB_NOTICE("Extension %s successfully registered", AfbExtensionManifest.name);
	return ocpp_declare((ocpp_item_t*)data, declare_set, call_set);
}

int AfbExtensionHTTPV1(void *data, struct afb_hsrv *hsrv)
{
	LIBAFB_NOTICE("Extension %s got HTTP", AfbExtensionManifest.name);
	return ocpp_http((ocpp_item_t*)data, hsrv);
}

int AfbExtensionServeV1(void *data, struct afb_apiset *call_set)
{
	LIBAFB_NOTICE("Extension %s ready to serve", AfbExtensionManifest.name);
	return ocpp_serve((ocpp_item_t*)data, call_set);
}

int AfbExtensionExitV1(void *data, struct afb_apiset *declare_set)
{
	LIBAFB_NOTICE("Extension %s got to exit", AfbExtensionManifest.name);
	return ocpp_exit((ocpp_item_t*)data, declare_set);
}

/*************************************************************/
/*************************************************************/
/** OCPP manager interface                                  **/
/*************************************************************/
/*************************************************************/

/**
 * managing structure for OCPP
 */
struct ocpp_item
{
	/** is it a server ? */
	int server;

	/** is it a client ? */
	json_object *uri;

	/** a key for connecting the client */
	json_object *sha256pwd;

	/** the declare set */
	struct afb_apiset *declare_set;

	/** the call set */
	struct afb_apiset *call_set;
};

/** release OCPP manager */
static void ocpp_free(ocpp_item_t *items)
{
	if (items) {
		afb_apiset_unref(items->declare_set);
		afb_apiset_unref(items->call_set);
		json_object_put(items->uri);
		free(items);
	}
}

/** creates the OCPP manager object from the JSON-C config */
static int ocpp_config(ocpp_item_t **items, struct json_object *config)
{
	ocpp_item_t *item = NULL;
	json_object *server = NULL, *uri = NULL, *sha256pwd=NULL;
	int nbr, idx, rc = 0;

	/* client URI */
	if (!json_object_object_get_ex(config, "ocpp-client", &uri)
	 || !json_object_is_type(uri, json_type_string))
		uri = NULL;

	/* is server ? */
	if (!json_object_object_get_ex(config, "ocpp-server", &server))
		server = NULL;

	/* password */
	if (!json_object_object_get_ex(config, "ocpp-pwd-base64", &sha256pwd))
		sha256pwd = NULL;

	/* create a manager only if there is some thing in */
	if (uri != NULL || server != NULL || sha256pwd != NULL) {
		item = calloc(1, sizeof *item);
		if (item == NULL)
			rc = -ENOMEM;
		else {
			/* record the extracted data */
			item->server = server != NULL;
			item->sha256pwd = uri == NULL ? NULL : json_object_get(sha256pwd);
			item->uri = uri == NULL ? NULL : json_object_get(uri);
		}
	}
	*items = item;
	return rc;
}

/** declares the OCPP APIs */
static int ocpp_declare(ocpp_item_t *items, struct afb_apiset *declare_set, struct afb_apiset *call_set)
{
	int rc = 0;
	if (items) {
		/* TODO make record of public/private subset parametric */
		//struct afb_apiset *ds = afb_apiset_subset_find(declare_set, "monitor") ?: declare_set;
		struct afb_apiset *ds = declare_set; /* to the private scope for avoiding call to info by uidevtool */
		items->declare_set = afb_apiset_addref(ds);
		items->call_set = afb_apiset_addref(call_set);
		if (items->uri != NULL) {
			/* when client */
			rc = ocpp_client_create(items);
		}
	}
	return rc;
}

/** declare server http */
static int ocpp_http(ocpp_item_t *items, struct afb_hsrv *hsrv)
{
	int rc = 0;
	if (items && items->server) {
		rc = afb_hsrv_add_ws_protocol(hsrv, OCPP_PROTOCOL, (wscreator_t)ocpp_ws_create_cb, items);
	}
	return rc;
}

static int ocpp_serve(ocpp_item_t *items, struct afb_apiset *call_set)
{
	return 0;
}

/** clean up at exiting */
static int ocpp_exit(ocpp_item_t *items, struct afb_apiset *declare_set)
{
	ocpp_free(items);
	return 0;
}

/*********************************************************************************************/
/*********************************************************************************************/
/*********************************************************************************************/
/*********************************************************************************************/
/*********************************************************************************************/
/*********************************************************************************************/
/*********************************************************************************************/
/*********************************************************************************************/
/*********************************************************************************************/
/*********************************************************************************************/
/*********************************************************************************************/
/*********************************************************************************************/

/* predeclaration of websocket callbacks */
static void ows_on_hangup_cb(void *closure, struct afb_wsj1 *wsj1);
static void ows_on_call_cb(void *closure, const char *api, const char *verb, struct afb_wsj1_msg *msg);
static void ows_on_process(void *closure, struct afb_req_common *req);

/* predeclaration of wsreq callbacks */
static void wsreq_destroy(struct afb_req_common *comreq);
static void wsreq_reply(struct afb_req_common *comreq, int status, unsigned nparams, struct afb_data * const params[]);
static int  wsreq_interface(struct afb_req_common *req, int id, const char *name, void **result);

/* predeclaration of reconnection */
static int ocpp_client_reconnect(struct ocpp_ws *ows);

/**
 * declaration of websocket structure
 */
struct ocpp_ws
{
	/** counter of reference */
	int refcount;

	/** type of connection */
	int is_server;

	/** function for cleaning up */
	void (*cleanup)(void*);

	/** closure for function for cleaning up */
	void *cleanup_closure;

	/** session of the connexion */
	struct afb_session *session;

	/** token for the connection */
	struct afb_token *token;

	/** the websocket of the connection */
	struct afb_wsj1 *wsj1;

	/** the call apiset */
	struct afb_apiset *apiset;

#if WITH_CRED
	/** credentials of the connection */
	struct afb_cred *cred;
#endif
	/** link to the OCPP manager */
	ocpp_item_t *ocpp;

	/** name of the API handling the connection */
	char backapi[];
};

/**
 * declaration of ocpp_req, the structure for managing OCPP requests
 */
struct ocpp_req
{
	/** the common request MUST BE FIRST */
	struct afb_req_common comreq;

	/** link for hangup */
	struct ocpp_req *next;

	/** the handling OCPP connection */
	struct ocpp_ws *ows;

	/** the received message */
	struct afb_wsj1_msg *msgj1;
};

/* interface for ocpp_ws / afb_wsj1 */
static struct afb_wsj1_itf wsj1_itf = {
	.on_hangup = ows_on_hangup_cb,
	.on_call = ows_on_call_cb
};

/* interface for comreq */
const struct afb_req_common_query_itf ocpp_ws_req_common_itf = {
	.reply = wsreq_reply,
	.unref = wsreq_destroy,
	.interface = wsreq_interface
};

/* back call api */
static struct afb_api_itf bkapitf = {
	.process = ows_on_process
};

/***************************************************************
****************************************************************
**
**  functions of ocpp_ws / afb_wsj1
**
****************************************************************
***************************************************************/

static
struct ocpp_ws *
ocpp_ws_create(
	ocpp_item_t *ocpp,
	int is_server,
	struct afb_apiset *apiset,
	struct afb_session *session,
	struct afb_token *token,
	void (*cleanup)(void*),
	void *cleanup_closure,
	const char *name
) {
	struct ocpp_ws *result;
	struct afb_api_item aai;

	result = malloc(sizeof * result + 1 + strlen(name));
	if (result == NULL)
		goto error;

	result->refcount = 1;
	result->is_server = is_server;
	result->cleanup = cleanup;
	result->cleanup_closure = cleanup_closure;
	result->session = afb_session_addref(session);
	result->token = afb_token_addref(token);
	result->ocpp = ocpp;
	result->wsj1 = NULL;
#if WITH_CRED
	result->cred = NULL;
#endif
	strcpy(result->backapi, name);
	if (result->session == NULL)
		goto error2;

	aai.closure = result;
	aai.itf = &bkapitf;
	aai.group = result;
	if (afb_apiset_add(ocpp->declare_set, result->backapi, aai) < 0)
		goto error3;

	result->apiset = afb_apiset_addref(apiset);
	return result;

error3:
	afb_session_unref(result->session);
	afb_token_unref(result->token);
error2:
	free(result);
error:
	return NULL;
}

struct ocpp_ws *ocpp_ws_addref(struct ocpp_ws *ws)
{
	__atomic_add_fetch(&ws->refcount, 1, __ATOMIC_RELAXED);
	return ws;
}

void ocpp_ws_unref(struct ocpp_ws *ws)
{
	if (!__atomic_sub_fetch(&ws->refcount, 1, __ATOMIC_RELAXED)) {
		afb_apiset_del(ws->ocpp->declare_set, ws->backapi);
		afb_wsj1_unref(ws->wsj1);
		if (ws->cleanup != NULL)
			ws->cleanup(ws->cleanup_closure);
		afb_token_unref(ws->token);
		afb_session_unref(ws->session);
#if WITH_CRED
		afb_cred_unref(ws->cred);
#endif
		afb_apiset_unref(ws->apiset);
		free(ws);
	}
}

static void ows_on_hangup_cb(void *closure, struct afb_wsj1 *wsj1)
{
	struct ocpp_ws *ows = closure;
	ows->wsj1 = NULL;
	afb_monitor_api_disconnected(ows->backapi);
	afb_wsj1_unref(wsj1);
	if (ows->is_server)
		ocpp_ws_unref(ows);
}

static int ocpp_ws_connect(struct ocpp_ws *ows, int fd, int autoclose)
{
	ows->wsj1 = afb_wsj1_create(fd, autoclose, &wsj1_itf, ows);
	if (ows->wsj1 == NULL)
		return -1;
	afb_wsj1_set_masking(ows->wsj1, 1);
#if WITH_CRED
	afb_cred_create_for_socket(&ows->cred, fd);
#endif
	return 0;
}

static void ows_on_call_cb(void *closure, const char *api, const char *verb, struct afb_wsj1_msg *msg)
{
	struct ocpp_ws *ws = closure;
	struct ocpp_req *wsreq;
	const char *tok;
	const char *object;
	struct afb_data *arg;
	size_t len;
	int rc;

	/* check api is not NULL */
	object = afb_wsj1_msg_object_s(msg, &len);
	if (api != NULL) {
		LIBAFB_ERROR("received websocket request with non NULL api %s/%s: %s", api, verb, object);
		afb_wsj1_close(ws->wsj1, WEBSOCKET_CODE_POLICY_VIOLATION, NULL);
		return;
	}
	LIBAFB_DEBUG("received OCPP backend request for %s/%s: %s", OCPP_REC, verb, object);

	/* make params */
	afb_wsj1_msg_addref(msg);
	rc = afb_data_create_raw(&arg, &afb_type_predefined_json, object, 1+len,
					(void*)afb_wsj1_msg_unref, msg);
	if (rc < 0) {
		afb_wsj1_close(ws->wsj1, WEBSOCKET_CODE_POLICY_VIOLATION, NULL);
		return;
	}

	/* allocate */
	wsreq = calloc(1, sizeof *wsreq);
	if (wsreq == NULL) {
		afb_data_unref(arg);
		afb_wsj1_close(ws->wsj1, WEBSOCKET_CODE_POLICY_VIOLATION, NULL);
		return;
	}

	/* init the context */
	afb_req_common_init(&wsreq->comreq, &ocpp_ws_req_common_itf, OCPP_REC, verb, 1, &arg);
	afb_req_common_set_session(&wsreq->comreq, ws->session);
	afb_req_common_set_token(&wsreq->comreq, ws->token);
#if WITH_CRED
	afb_req_common_set_cred(&wsreq->comreq, ws->cred);
#endif

	/* fill and record the request */
	afb_wsj1_msg_addref(msg);
	wsreq->msgj1 = msg;
	wsreq->ows = ocpp_ws_addref(ws);

	/* emits the call */
	afb_req_common_process(&wsreq->comreq, ws->apiset);
}

static void ows_on_reply(void *closure, struct afb_wsj1_msg *msg)
{
	int sts, rc;
	struct afb_req_common *req = closure;
	struct afb_data *data;
	size_t size;
	const char *object = afb_wsj1_msg_object_s(msg, &size);

	afb_wsj1_msg_addref(msg);
	rc = afb_data_create_raw(&data,  &afb_type_predefined_json, object, 1+size,
					(void*)afb_wsj1_msg_unref, msg);
	sts = afb_wsj1_msg_is_reply_ok(msg) ? 0 : -1;
	afb_req_common_reply_hookable(req, sts, 1, &data);
	afb_req_common_unref(req);
}

static void ows_send_call(void *closure1, const char *object, const void *closure2)
{
	struct afb_req_common *req = closure1;
	struct ocpp_ws *ows = (void*)closure2;
	int rc;
	if (ows->wsj1 == NULL) {
		if (ows->is_server || ocpp_client_reconnect(ows) < 0) {
			afb_req_common_reply_hookable(req, AFB_ERRNO_DISCONNECTED, 0, NULL);
			return;
		}
	}
	afb_req_common_addref(req);
	rc = afb_wsj1_call_s(ows->wsj1, NULL, req->verbname, object, ows_on_reply, req);
}

static void ows_on_process(void *closure, struct afb_req_common *req)
{
	int rc = afb_json_legacy_do2_single_json_string(
			req->params.ndata, req->params.data, ows_send_call, req, closure);
}

/***************************************************************
****************************************************************
**
**  functions of wsreq / afb_req
**
****************************************************************
***************************************************************/

static void wsreq_destroy(struct afb_req_common *comreq)
{
	struct ocpp_req *wsreq = containerof(struct ocpp_req, comreq, comreq);

	afb_req_common_cleanup(comreq);
	afb_wsj1_msg_unref(wsreq->msgj1);
	ocpp_ws_unref(wsreq->ows);
	free(wsreq);
}

static void wsreq_send_reply(void *closure1, const char *object, const void *closure2)
{
	struct ocpp_req *wsreq = closure1;
	int rc = afb_wsj1_reply_s(wsreq->msgj1, object, NULL, closure2 != NULL);
	if (rc < 0)
		LIBAFB_ERROR("Can't send reply: %m");
}


static void wsreq_reply(struct afb_req_common *comreq, int status, unsigned nparams, struct afb_data * const params[])
{
	struct ocpp_req *wsreq = containerof(struct ocpp_req, comreq, comreq);
	int rc = afb_json_legacy_do2_single_json_string(nparams, params, wsreq_send_reply, wsreq, status >= 0 ? NULL : wsreq);
	if (rc < 0)
		LIBAFB_ERROR("Can't send reply: %m");
}

static int wsreq_interface(struct afb_req_common *comreq, int id, const char *name, void **result)
{
	int rc = -1;
	struct ocpp_req *wsreq = containerof(struct ocpp_req, comreq, comreq);

	if (name != NULL && !strcmp(name, OCPP_BKAPI)) {
		rc = 0;
		if (result) {
			*result = strdup(wsreq->ows->backapi);
			if (*result == NULL)
				rc = -1;
		}
	}
	return rc;
}

/***************************************************************
****************************************************************
**
**  server part
**
****************************************************************
***************************************************************/

/** for creating api names */
static unsigned bkapinum = 0;

static
struct ocpp_ws *
ocpp_ws_create_cb(
	ocpp_item_t *ocpp,
	int fd,
	int autoclose,
	struct afb_apiset *apiset,
	struct afb_session *session,
	struct afb_token *token,
	void (*cleanup)(void*),
	void *cleanup_closure
) {
	struct ocpp_ws *ows;
	char backapi[50];

	sprintf(backapi, OCPP_BKAPI_PATTERN, ++bkapinum);
	ows = ocpp_ws_create(ocpp, 1, apiset, session, token,
			cleanup, cleanup_closure, backapi);
	if (ows == NULL) {
		if (autoclose)
			close(fd);
	}
	else {
		if (ocpp_ws_connect(ows, fd, autoclose) < 0) {
			ocpp_ws_unref(ows);
			ows = NULL;
		}
	}
	return ows;
}

/***************************************************************
****************************************************************
**
**  client part
**
****************************************************************
***************************************************************/

static int ocpp_client_reconnect(struct ocpp_ws *ows)
{
	ocpp_item_t *ocpp = ows->ocpp;
	char *headers[2]= {NULL,NULL};
	int rc;
	const char *protos[2] = { OCPP_PROTOCOL, NULL };
	const char *uri = json_object_get_string(ocpp->uri);
	struct ev_mgr *mgr = afb_ev_mgr_get_for_me();

	if (ocpp->sha256pwd) {
		rc= asprintf (&headers[0], "authorization: Basic %s",
				json_object_get_string(ocpp->sha256pwd));
		if (rc < 0)
			headers[0] = NULL;
	}
	rc = afb_ws_connect(mgr, uri, protos, NULL, (const char**) headers);
	free(headers[0]);
	if (rc >= 0)
		rc = ocpp_ws_connect(ows, rc, 1);
	return rc;
}

static int ocpp_client_create(ocpp_item_t *ocpp)
{
	struct ocpp_ws *ows;
	int rc;
	struct afb_session *session;

	session = afb_api_common_get_common_session();
	ows = ocpp_ws_create(ocpp, 0, ocpp->call_set,
					session, NULL, NULL, NULL,
					OCPP_SND);
	if (ows == NULL)
		rc = -ENOMEM;
	else {
		rc = ocpp_client_reconnect(ows);
		if (rc < 0)
			ocpp_ws_unref(ows);
	}
	return rc;
}

