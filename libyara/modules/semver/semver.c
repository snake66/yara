#include <yara/modules.h>

#define MODULE_NAME semver

struct version {
    unsigned long major;
    unsigned long minor;
    unsigned long patch;
};

void semver_parse(struct version * v, const char * s)
{
    assert(v!= NULL);
    assert(s != NULL);

    char * p = NULL;

    v->major = strtoul(s, &p, 10);
    assert(*p == '.');

    v->minor = strtoul(++p, &p, 10);
    assert(*p == '.');

    v->patch = strtoul(++p, &p, 10);
}

define_function(semver_cmp)
{
    struct version ver;
    struct version target;

    semver_parse(&ver, string_argument(1));
    semver_parse(&target, string_argument(2));

    int res = 0;

    if (ver.major < target.major)
        res = -1;
    else if (ver.major > target.major)
        res = 1;
    else if (ver.minor < target.minor)
        res = -1;
    else if (ver.minor > target.minor)
        res = 1;
    else if (ver.patch < target.patch)
        res = -1;
    else if (ver.patch > target.patch)
        res = 1;

    return_integer(res);
}

begin_declarations;

    declare_function("cmp", "ss", "i", semver_cmp);

end_declarations;

int module_initialize(YR_MODULE * mod)
{
    return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE * mod)
{
    return ERROR_SUCCESS;
}

int module_load(
        YR_SCAN_CONTEXT * ctx,
        YR_OBJECT * obj,
        void * data,
        size_t size)
{
    return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT * obj)
{
    return ERROR_SUCCESS;
}

#undef MODULE_NAME
