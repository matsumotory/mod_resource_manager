#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "http_log.h"
#include "apr_strings.h"

#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/compile.h>

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#define MODULE_NAME           "mod_resource_manager"
#define MODULE_VERSION        "0.0.1"

#define CGROUP_APACHE_ROOT    "/sys/fs/cgroup/cpu/apache"

typedef struct dir_config {

    char *mruby_code;
    const char *host;
    long cpurate;
    
} mrm_config_t;

module AP_MODULE_DECLARE_DATA resource_manager_module;

static char *manage_dir                     = NULL;
static char *manage_file                    = NULL;
static char *manage_cpu                     = NULL;
static apr_file_t *manage_fp                = NULL;
static request_rec *mrm_request_rec_state   = NULL;

static int resource_manager_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *server)
{

    ap_log_perror(APLOG_MARK
        , APLOG_NOTICE
        , 0
        , p
        , "%s %s: %s / %s mechanism enabled."
        , MODULE_NAME
        , __func__
        , MODULE_NAME
        , MODULE_VERSION
    );

    return OK;
}

static void *resource_manager_create_config(apr_pool_t *p, server_rec *s)
{
    mrm_config_t *conf = (mrm_config_t *)apr_pcalloc(p, sizeof (*conf));

    conf->mruby_code    = NULL;
    conf->host          = NULL;
    conf->cpurate       = 100000; //100ms 100%

    return conf;
}

static int ap_mrb_push_request(request_rec *r)
{
    mrm_request_rec_state = r;
    return OK;
}

static request_rec *ap_mrb_get_request()
{
    return mrm_request_rec_state;
}

mrb_value ap_mrb_set_cpurate(mrb_state *mrb, mrb_value str)
{

    mrb_int ret;
    request_rec *r = ap_mrb_get_request();
    mrm_config_t *conf = ap_get_module_config(r->server->module_config, &resource_manager_module);
    mrb_get_args(mrb, "i", &ret);
    conf->cpurate = (int)ret;

    return str;
}

mrb_value ap_mrb_get_cpurate(mrb_state *mrb, mrb_value str)
{
    request_rec *r = ap_mrb_get_request();
    mrm_config_t *conf = ap_get_module_config(r->server->module_config, &resource_manager_module);
    return mrb_fixnum_value(conf->cpurate);
}

static int ap_mruby_class_init(mrb_state *mrb)
{
    struct RClass *class;
    struct RClass *class_manager;

    class = mrb_define_module(mrb, "Resource");
    class_manager = mrb_define_class_under(mrb, class, "Manager", mrb->object_class);
    mrb_define_method(mrb, class_manager, "cpurate=", ap_mrb_set_cpurate, ARGS_ANY());
    mrb_define_method(mrb, class_manager, "cpurate", ap_mrb_get_cpurate, ARGS_NONE());

    return OK;
}

static int cpurate_from_mruby(request_rec *r)
{
    FILE *mrb_file;
    mrm_config_t *conf = ap_get_module_config(r->server->module_config, &resource_manager_module);

    mrb_state *mrb = mrb_open();
    ap_mruby_class_init(mrb);
        if ((mrb_file = fopen(conf->mruby_code, "r")) == NULL) {
            ap_log_error(APLOG_MARK
                , APLOG_ERR
                , 0
                , NULL
                , "%s ERROR %s: mrb file oepn failed: %s"
                , MODULE_NAME
                , __func__
                , conf->mruby_code
            );
        }
    struct mrb_parser_state* p = mrb_parse_file(mrb, mrb_file);
    int n = mrb_generate_code(mrb, p->tree);
    mrb_pool_close(p->pool);
    ap_mrb_push_request(r);
    mrb_run(mrb, mrb_proc_new(mrb, mrb->irep[n]), mrb_nil_value());

    return OK;
}

static int resource_manager_atached(request_rec *r)
{
    mrm_config_t *conf = ap_get_module_config(r->server->module_config, &resource_manager_module);

    if (strcmp(apr_table_get(r->headers_in, "HOST"), conf->host) == 0) {
        manage_dir  = apr_psprintf(r->pool, "%s/%s", CGROUP_APACHE_ROOT, conf->host);
        manage_file = apr_psprintf(r->pool, "%s/tasks", manage_dir);
        manage_cpu  = apr_psprintf(r->pool, "%s/cpu.cfs_quota_us", manage_dir);
    
        apr_dir_make(manage_dir, APR_OS_DEFAULT, r->pool);
    
        if(apr_file_open(&manage_fp, manage_file, APR_WRITE, APR_OS_DEFAULT, r->pool) != APR_SUCCESS){
            return OK;
        }
        apr_file_printf(manage_fp, "%d\n", getpid());
        apr_file_flush(manage_fp);
        apr_file_close(manage_fp);
    
        if(apr_file_open(&manage_fp, manage_cpu, APR_WRITE, APR_OS_DEFAULT, r->pool) != APR_SUCCESS){
            return OK;
        }
        cpurate_from_mruby(r);
        apr_file_printf(manage_fp, "%ld\n", conf->cpurate);
        apr_file_flush(manage_fp);
        apr_file_close(manage_fp);
    }

    return DECLINED;
}

static int resource_manager_detached(request_rec *r)
{
    mrm_config_t *conf = ap_get_module_config(r->server->module_config, &resource_manager_module);

    if (strcmp(apr_table_get(r->headers_in, "HOST"), conf->host) == 0) {
        manage_dir  = apr_psprintf(r->pool, "%s/%s", CGROUP_APACHE_ROOT, conf->host);

        if(apr_file_open(&manage_fp, manage_cpu, APR_WRITE, APR_OS_DEFAULT, r->pool) != APR_SUCCESS){
            return OK;
        }
        apr_file_puts("100000\n", manage_fp);
        apr_file_flush(manage_fp);
        apr_file_close(manage_fp);
    }

    return OK;
}

static const char *set_resource_manager_mruby(cmd_parms *cmd, void *mconfig, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_FILES | NOT_IN_LIMIT);
    mrm_config_t *conf = ap_get_module_config(cmd->server->module_config, &resource_manager_module);

    if (err != NULL)
        return err;

    conf->mruby_code = apr_pstrdup(cmd->pool, arg);

    return NULL;
}

static const char *set_resource_manager(cmd_parms *cmd, void *mconfig, const char *rate, const char *target_host)
{
    long cpurate = strtol(rate, (char **) NULL, 10);
    mrm_config_t *conf = ap_get_module_config(cmd->server->module_config, &resource_manager_module);
    conf->cpurate = cpurate;
    conf->host = apr_pstrdup(cmd->pool, target_host);
    return NULL;
}

static void register_hooks(apr_pool_t *p)
{   
    ap_hook_post_config(resource_manager_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(resource_manager_atached, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_log_transaction(resource_manager_detached, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec resource_manager_cmds[] = {

    AP_INIT_TAKE2("ResourceManagedCPU", set_resource_manager, NULL, RSRC_CONF | ACCESS_CONF, "resource managed host."),
    AP_INIT_TAKE1("ResourceManagedmruby", set_resource_manager_mruby, NULL, RSRC_CONF | ACCESS_CONF, "resource management by mruby."),
    {NULL}
};

module AP_MODULE_DECLARE_DATA resource_manager_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                               /* dir config creater */
    NULL,                               /* dir merger */
    resource_manager_create_config,     /* server config */
    NULL,                               /* merge server config */
    resource_manager_cmds,              /* command apr_table_t */
    register_hooks                      /* register hooks */
};
