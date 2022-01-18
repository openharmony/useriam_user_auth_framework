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

#include "user_auth_helper.h"

#include "auth_hilog_wrapper.h"
#include "user_auth_impl.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
/**
 * @brief Instance passed to context
 *
 * @param env
 * @param info
 * @return napi_value Instance
 */
napi_value UserAuthServiceConstructor(napi_env env, napi_callback_info info)
{
    std::shared_ptr<UserAuthImpl> userAuthImpl;
    userAuthImpl.reset(new UserAuthImpl());
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    NAPI_CALL(env, napi_wrap(
        env, thisVar, userAuthImpl.get(),
        [](napi_env env, void *data, void *hint) {
            UserAuthImpl *userAuthImpl = static_cast<UserAuthImpl *>(data);
            if (userAuthImpl != nullptr) {
                delete userAuthImpl;
            }
        },
        nullptr, nullptr));
    // Pull up the face service process
    return thisVar;
}

/**
 * @brief Get the Version object
 *
 * @param env
 * @param info
 * @return napi_value Specific version number results
 */
napi_value GetVersion(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argcAsync = 0;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    UserAuthImpl *userAuthImpl = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, (void **)&userAuthImpl));
    HILOG_INFO("UserAuthHelper, GetVersion");
    return userAuthImpl->GetVersion(env, info);
}

/**
 * @brief Get the Availabe Status object
 *
 * @param env
 * @param info
 * @return napi_value Verify that the certification capability is available
 */
napi_value GetAvailabeStatus(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argcAsync = 0;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    UserAuthImpl *userAuthImpl = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, (void **)&userAuthImpl));
    HILOG_INFO("UserAuthHelper, getAvailabeStatus");
    return userAuthImpl->GetAvailabeStatus(env, info);
}

/**
 * @brief Get the Property object
 *
 * @param env
 * @param info
 * @return napi_value It supports querying subclasses / remaining authentication times / freezing time
 */
napi_value GetProperty(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argcAsync = 0;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    UserAuthImpl *userAuthImpl = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, (void **)&userAuthImpl));
    HILOG_INFO("UserAuthHelper, GetProperty");
    return userAuthImpl->GetProperty(env, info);
}

/**
 * @brief Set the Property object
 *
 * @param env
 * @param info
 * @return napi_value Set properties: can be used to initialize algorithms
 */
napi_value SetProperty(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argcAsync = 0;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    UserAuthImpl *userAuthImpl = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, (void **)&userAuthImpl));
    HILOG_INFO("UserAuthHelper, SetProperty");
    return userAuthImpl->SetProperty(env, info);
}

/**
 * @brief user authentication
 *
 * @param env
 * @param info
 * @return napi_value Enter the challenge value, authentication method, trust level and callback, and return the result
 * and acquireinfo through the callback
 */
napi_value Auth(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argcAsync = 0;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    UserAuthImpl *userAuthImpl = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, (void **)&userAuthImpl));
    HILOG_INFO("UserAuthHelper, Auth");
    return userAuthImpl->Auth(env, info);
}

/**
 * @brief user authentication
 *
 * @param env
 * @param info
 * @return napi_value Pass in the user ID, challenge value, authentication method, trust level and callback, and return
 * the result acquireinfo through the callback
 */
napi_value AuthUser(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argcAsync = 0;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    UserAuthImpl *userAuthImpl = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, (void **)&userAuthImpl));
    HILOG_INFO("UserAuthHelper, AuthUser");
    return userAuthImpl->AuthUser(env, info);
}

/**
 * @brief Cancel authentication
 *
 * @param env
 * @param info
 * @return napi_value success or fail
 */
napi_value CancelAuth(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argcAsync = 0;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    UserAuthImpl *userAuthImpl = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, (void **)&userAuthImpl));
    HILOG_INFO("UserAuthHelper, CancelAuth");
    return userAuthImpl->CancelAuth(env, info);
}

/**
 * @brief Napi initialization
 *
 * @param env
 * @param exports
 */
void Init(napi_env env, napi_value exports)
{
    napi_status status;
    napi_property_descriptor exportFuncs[] = {
        DECLARE_NAPI_FUNCTION("constructor", UserAuth::Constructor),
    };
    status = napi_define_properties(env, exports, sizeof(exportFuncs) / sizeof(*exportFuncs), exportFuncs);
    if (status != napi_ok) {
        HILOG_ERROR("napi_define_properties faild");
    }
}

napi_value Constructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value userAuth = nullptr;
    NAPI_CALL(env, napi_new_instance(env, GetCtor(env), 0, nullptr, &userAuth));
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr));
    return userAuth;
}

napi_value GetCtor(napi_env env)
{
    napi_value cons = nullptr;
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_FUNCTION("getVersion", UserAuth::GetVersion),
        DECLARE_NAPI_FUNCTION("getAvailabeStatus", UserAuth::GetAvailabeStatus),
        DECLARE_NAPI_FUNCTION("getProperty", UserAuth::GetProperty),
        DECLARE_NAPI_FUNCTION("setProperty", UserAuth::SetProperty),
        DECLARE_NAPI_FUNCTION("auth", UserAuth::Auth),
        DECLARE_NAPI_FUNCTION("authUser", UserAuth::AuthUser),
        DECLARE_NAPI_FUNCTION("cancelAuth", UserAuth::CancelAuth),
    };
    NAPI_CALL(env, napi_define_class(env, "UserAuth", NAPI_AUTO_LENGTH, UserAuthServiceConstructor, nullptr,
        sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    return cons;
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS