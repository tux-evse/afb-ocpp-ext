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
#include <stdio.h>

#define OCPP_PROTOCOL      "ocpp1.6"
#define OCPP_API           "OCPP"
#define OCPP_API_CLIENT    "OCPP-C"
#define OCPP_BKAPI         "OCPP-BACK-API"
#define OCPP_BKAPI_PATTERN "x-OCPP-%u"


AFB_EXTENSION("OCPP")

typedef struct ocpp_item ocpp_item_t;
static int ocpp_config(ocpp_item_t **items, struct json_object *config);
static int ocpp_declare(ocpp_item_t *items, struct afb_apiset *declare_set, struct afb_apiset *call_set);
static int ocpp_http(ocpp_item_t *items, struct afb_hsrv *hsrv);
static int ocpp_serve(ocpp_item_t *items, struct afb_apiset *call_set);
static int ocpp_exit(ocpp_item_t *items, struct afb_apiset *declare_set);

struct ocpp_ws;
static struct ocpp_ws *ocpp_ws_create_cb(ocpp_item_t *closure, int fd, int autoclose,
		struct afb_apiset *apiset, struct afb_session *session, struct afb_token *token,
		void (*cleanup)(void*), void *cleanup_closure);
static int ocpp_connect(ocpp_item_t *item);

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
	LIBAFB_NOTICE("Extension %s got to declare", AfbExtensionManifest.name);
	return ocpp_declare((ocpp_item_t*)data, declare_set, call_set);
}

int AfbExtensionHTTPV1(void *data, struct afb_hsrv *hsrv)
{
	LIBAFB_NOTICE("Extension %s got HTTP", AfbExtensionManifest.name);
	return ocpp_http((ocpp_item_t*)data, hsrv);
}

int AfbExtensionServeV1(void *data, struct afb_apiset *call_set)
{
	LIBAFB_NOTICE("Extension %s got to serve", AfbExtensionManifest.name);
	return ocpp_serve((ocpp_item_t*)data, call_set);
}

int AfbExtensionExitV1(void *data, struct afb_apiset *declare_set)
{
	LIBAFB_NOTICE("Extension %s got to exit", AfbExtensionManifest.name);
	return ocpp_exit((ocpp_item_t*)data, declare_set);
}


struct ocpp_item
{
	int server;
	json_object *uri;
	json_object *sha256pwd;
	struct afb_apiset *declare_set;
	struct afb_apiset *call_set;
};

static void ocpp_free(ocpp_item_t *items)
{
	if (items) {
		afb_apiset_unref(items->declare_set);
		afb_apiset_unref(items->call_set);
		json_object_put(items->uri);
		free(items);
	}
}

static int ocpp_config(ocpp_item_t **items, struct json_object *config)
{
	ocpp_item_t *item = NULL;
	json_object *server = NULL, *uri = NULL, *sha256pwd=NULL;
	int nbr, idx, rc = 0;

	if (!json_object_object_get_ex(config, "ocpp-client", &uri)
	 || !json_object_is_type(uri, json_type_string))
		uri = NULL;

	if (!json_object_object_get_ex(config, "ocpp-server", &server))
		server = NULL;

	if (!json_object_object_get_ex(config, "ocpp-pwd-base64", &sha256pwd))
		sha256pwd = NULL;

	if (uri != NULL || server != NULL || sha256pwd != NULL) {
		item = calloc(1, sizeof *item);
		if (item == NULL)
			rc = -ENOMEM;
		else {
			item->server = server != NULL;
			item->sha256pwd = uri == NULL ? NULL : json_object_get(sha256pwd);
			item->uri = uri == NULL ? NULL : json_object_get(uri);
		}
	}
	*items = item;
	return rc;
}

static int ocpp_declare(ocpp_item_t *items, struct afb_apiset *declare_set, struct afb_apiset *call_set)
{
	int rc = 0;
	if (items) {
		struct afb_apiset *ds = afb_apiset_subset_find(declare_set, "public") ?: declare_set;
		items->declare_set = afb_apiset_addref(ds);
		items->call_set = afb_apiset_addref(call_set);
		if (items->uri != NULL) {
			rc = ocpp_connect(items);
		}
	}
	return rc;
}

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

/* predeclaration of structures */
struct ocpp_ws;
struct ocpp_req;

/* predeclaration of websocket callbacks */
static void ows_on_hangup_cb(void *closure, struct afb_wsj1 *wsj1);
static void ows_on_call_cb(void *closure, const char *api, const char *verb, struct afb_wsj1_msg *msg);
static void ows_on_process(void *closure, struct afb_req_common *req);

/* predeclaration of wsreq callbacks */
static void wsreq_destroy(struct afb_req_common *comreq);
static void wsreq_reply(struct afb_req_common *comreq, int status, unsigned nparams, struct afb_data * const params[]);
static int  wsreq_interface(struct afb_req_common *req, int id, const char *name, void **result);

/* declaration of websocket structure */
struct ocpp_ws
{
	int refcount;
	void (*cleanup)(void*);
	void *cleanup_closure;
	struct afb_session *session;
	struct afb_token *token;
	struct afb_wsj1 *wsj1;
	struct afb_apiset *apiset;
#if WITH_CRED
	struct afb_cred *cred;
#endif
	ocpp_item_t *ocpp;
	char backapi[];
};

/* declaration of wsreq structure */
struct ocpp_req
{
	struct afb_req_common comreq;
	struct ocpp_ws *ows;
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

static unsigned bkapinum = 0;

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
	int fd,
	int autoclose,
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
	result->cleanup = cleanup;
	result->cleanup_closure = cleanup_closure;
	result->session = afb_session_addref(session);
	result->token = afb_token_addref(token);
	result->ocpp = ocpp;
	strcpy(result->backapi, name);
	if (result->session == NULL)
		goto error2;

	result->wsj1 = afb_wsj1_create(fd, autoclose, &wsj1_itf, result);
	autoclose = 0;
	if (result->wsj1 == NULL)
		goto error3;

	aai.closure = result;
	aai.itf = &bkapitf;
	aai.group = result;
	if (afb_apiset_add(ocpp->declare_set, result->backapi, aai) < 0)
		goto error4;

#if WITH_CRED
	afb_cred_create_for_socket(&result->cred, fd);
#endif
	result->apiset = afb_apiset_addref(apiset);
	return result;

error4:
	afb_wsj1_unref(result->wsj1);
error3:
	afb_session_unref(result->session);
	afb_token_unref(result->token);
error2:
	free(result);
error:
	if (autoclose)
		close(fd);
	return NULL;
}

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
	char backapi[50];
	sprintf(backapi, OCPP_BKAPI_PATTERN, ++bkapinum);
	return ocpp_ws_create(ocpp, fd, autoclose, apiset, session, token, cleanup, cleanup_closure, backapi);
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
	struct ocpp_ws *ws = closure;
	ocpp_ws_unref(ws);
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
		afb_wsj1_close(ws->wsj1, 1008, NULL);
		return;
	}
	LIBAFB_DEBUG("received websocket request for %s/%s: %s", api, verb, object);

	/* make params */
	afb_wsj1_msg_addref(msg);
	rc = afb_data_create_raw(&arg, &afb_type_predefined_json, object, 1+len,
					(void*)afb_wsj1_msg_unref, msg);
	if (rc < 0) {
		afb_wsj1_close(ws->wsj1, 1008, NULL);
		return;
	}

	/* allocate */
	wsreq = calloc(1, sizeof *wsreq);
	if (wsreq == NULL) {
		afb_data_unref(arg);
		afb_wsj1_close(ws->wsj1, 1008, NULL);
		return;
	}

	/* init the context */
	afb_req_common_init(&wsreq->comreq, &ocpp_ws_req_common_itf, OCPP_API, verb, 1, &arg);
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
	const struct ocpp_ws *ws = closure2;
	int rc;
	afb_req_common_addref(req);
	rc = afb_wsj1_call_s(ws->wsj1, NULL, req->verbname, object, ows_on_reply, req);
}

static void ows_on_process(void *closure, struct afb_req_common *req)
{
	int rc = afb_json_legacy_do2_single_json_string(req->params.ndata, req->params.data, ows_send_call, req, closure);
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
**  functions of wsreq / afb_req
**
****************************************************************
***************************************************************/

static int ocpp_connect(ocpp_item_t *ocpp)
{
	struct ocpp_ws *ows;
	char *headers[2]= {NULL,NULL};
	int rc, fd;
	const char *protos[2] = { OCPP_PROTOCOL, NULL };
	struct afb_session *session;
	const char *uri = json_object_get_string(ocpp->uri);
	struct ev_mgr *mgr = afb_ev_mgr_get_for_me();

	if (ocpp->sha256pwd) {
		rc= asprintf (&headers[0], "authorization: Basic %s", json_object_get_string(ocpp->sha256pwd));
		if (rc < 0)
			headers[0] = NULL;
	}
	rc = afb_ws_connect(mgr, uri, protos, NULL, (const char**) headers);
	free(headers[0]);
	if (rc >= 0) {
		fd = rc;
		session = afb_api_common_get_common_session();
		if (session == NULL)
			rc = X_ENOMEM;
		else {
			ows = ocpp_ws_create(ocpp, fd, 1, ocpp->call_set, session, NULL, NULL, NULL, OCPP_API_CLIENT);
			if (ows != NULL)
				return 0;
		}
		close(fd);
	}
	return rc;
}

