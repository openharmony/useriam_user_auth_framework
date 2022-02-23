/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "user_auth_helper_north.h"

#include "user_auth_impl.h"
#include "user_auth_helper.h"
#include "userauth_hilog_wrapper.h"

using namespace OHOS::UserIAM::UserAuth;
namespace OHOS {
namespace UserAuthNorth {
napi_value Constructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value userAuth = nullptr;
    NAPI_CALL(env, napi_new_instance(env, GetCtor(env), 0, nullptr, &userAuth));
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr));
    USERAUTH_HILOGI(MODULE_JS_NAPI, "UserAuthNorth, Constructor start");
    return userAuth;
}

napi_value GetCtor(napi_env env)
{
    napi_value cons = nullptr;
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_FUNCTION("getVersion", UserIAM::UserAuth::GetVersion),
        DECLARE_NAPI_FUNCTION("getAvailableStatus", UserIAM::UserAuth::GetAvailableStatus),
        DECLARE_NAPI_FUNCTION("auth", UserIAM::UserAuth::Auth),
    };
    NAPI_CALL(env, napi_define_class(env, "UserAuthNorth", NAPI_AUTO_LENGTH,
        UserIAM::UserAuth::UserAuthServiceConstructor, nullptr,
        sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    return cons;
}

void Init(napi_env env, napi_value exports)
{
    napi_status status;
    napi_property_descriptor exportFuncs[] = {
        DECLARE_NAPI_FUNCTION("constructor", Constructor),
    };
    status = napi_define_properties(env, exports, sizeof(exportFuncs) / sizeof(*exportFuncs), exportFuncs);
    if (status != napi_ok) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "napi_define_properties faild");
    }
}

static napi_value ModuleInit(napi_env env, napi_value exports)
{
    OHOS::UserAuthNorth::Init(env, exports);
    return exports;
}
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module module = {
        .nm_version = 1,
        .nm_flags = 0,
        .nm_filename = nullptr,
        .nm_register_func = ModuleInit,
        .nm_modname = "UserAuthNorth",
        .nm_priv = nullptr,
        .reserved = {}
    };
    napi_module_register(&module);
}
} // namespace UserAuthNorth
} // namespace OHOS