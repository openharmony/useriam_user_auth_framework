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

#include <cinttypes>

#include "user_auth_impl.h"

#include <map>

#include "user_auth.h"
#include "userauth_callback.h"
#include "userauth_info.h"
#include "userauth_hilog_wrapper.h"
#include "authapi_callback.h"
#include "user_auth_helper.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
UserAuthImpl::UserAuthImpl()
{
}

UserAuthImpl::~UserAuthImpl()
{
}

napi_value UserAuthImpl::GetVersion(napi_env env, napi_callback_info info)
{
    int32_t result = UserAuth::GetInstance().GetVersion();
    USERAUTH_HILOGI(MODULE_JS_NAPI, "GetVersion result = %{public}d", result);
    napi_value version = 0;
    NAPI_CALL(env, napi_create_int32(env, result, &version));
    return version;
}

napi_value UserAuthImpl::GetAvailableStatus(napi_env env, napi_callback_info info)
{
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    size_t argc = ARGS_MAX_COUNT;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != ARGS_TWO) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "%{public}s, parms error.", __func__);
        return nullptr;
    }
    int type = authBuild.NapiGetValueInt(env, argv[PARAM0]);
    if (type == GET_VALUE_ERROR) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "%{public}s, argv[PARAM0] error.", __func__);
        return nullptr;
    }
    int level = authBuild.NapiGetValueInt(env, argv[PARAM1]);
    if (level == GET_VALUE_ERROR) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "%{public}s, argv[PARAM1] error.", __func__);
        return nullptr;
    }
    AuthType authType = AuthType(type);
    AuthTurstLevel authTurstLevel = AuthTurstLevel(level);
    int32_t result = UserAuth::GetInstance().GetAvailableStatus(authType, authTurstLevel);
    USERAUTH_HILOGI(MODULE_JS_NAPI, "GetAvailabeStatus result = %{public}d", result);
    napi_value ret = 0;
    NAPI_CALL(env, napi_create_int32(env, result, &ret));
    return ret;
}

napi_value UserAuthImpl::GetProperty(napi_env env, napi_callback_info info)
{
    AsyncHolder *asyncHolder = new (std::nothrow) AsyncHolder();
    if (asyncHolder == nullptr) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "%{public}s asyncHolder nullptr", __func__);
        return nullptr;
    }
    GetPropertyInfo *getPropertyInfo = new (std::nothrow) GetPropertyInfo();
    if (getPropertyInfo == nullptr) {
        delete asyncHolder;
        USERAUTH_HILOGE(MODULE_JS_NAPI, "%{public}s getPropertyInfo nullptr", __func__);
        return nullptr;
    }
    getPropertyInfo->callBackInfo.env = env;
    asyncHolder->data = getPropertyInfo;
    napi_value ret = GetPropertyWrap(env, info, asyncHolder);
    if (ret == nullptr) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "%{public}s GetPropertyWrap fail", __func__);
        delete getPropertyInfo;
        if (asyncHolder->asyncWork != nullptr) {
            napi_delete_async_work(env, asyncHolder->asyncWork);
        }
        delete asyncHolder;
    }
    return ret;
}

napi_value UserAuthImpl::GetPropertyWrap(napi_env env, napi_callback_info info, AsyncHolder *asyncHolder)
{
    USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s, called", __func__);
    GetPropertyInfo *getPropertyInfo = reinterpret_cast<GetPropertyInfo *>(asyncHolder->data);
    size_t argcAsync = ARGS_TWO;
    const size_t argcPromise = ARGS_ONE;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, nullptr, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }
    if (argcAsync > PARAM1) {
        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, args[PARAM1], &valuetype);
        if (valuetype == napi_function) {
            NAPI_CALL(env, napi_create_reference(env, args[PARAM1], 1, &(getPropertyInfo->callBackInfo.callBack)));
        }
    }
    if (authBuild.NapiTypeObject(env, args[PARAM0])) {
        Napi_GetPropertyRequest request = authBuild.GetPropertyRequestBuild(env, args[0]);
        getPropertyInfo->authType = request.authType_;
        getPropertyInfo->keys = request.keys_;
    }
    napi_value ret = nullptr;
    if (argcAsync > argcPromise) {
        ret = GetPropertyAsync(env, asyncHolder);
    } else {
        ret = GetPropertyPromise(env, asyncHolder);
    }
    USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s,end.", __func__);
    return ret;
}

void UserAuthImpl::GetPropertyExecute(napi_env env, void *data)
{
    USERAUTH_HILOGI(MODULE_JS_NAPI, "GetPropertyExecute, worker pool thread execute.");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    if (asyncHolder == nullptr) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "GetPropertyExecute, asyncHolder == nullptr");
        return;
    }
    GetPropertyInfo *getPropertyInfo = reinterpret_cast<GetPropertyInfo *>(asyncHolder->data);
    if (getPropertyInfo == nullptr) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "GetPropertyExecute, getPropertyInfo == nullptr");
        return;
    }
    AuthType authTypeGet = AuthType(getPropertyInfo->authType);

    GetPropertyRequest request;
    request.authType = authTypeGet;
    request.keys = getPropertyInfo->keys;
    USERAUTH_HILOGI(MODULE_JS_NAPI, "GetPropertyExecute start 1");
    GetPropApiCallback *object = new GetPropApiCallback(getPropertyInfo);
    std::shared_ptr<GetPropApiCallback> callback;
    callback.reset(object);
    UserAuth::GetInstance().GetProperty(request, callback);
    USERAUTH_HILOGI(MODULE_JS_NAPI, "GetPropertyExecute, worker pool thread execute end.");
}

void UserAuthImpl::GetPropertyPromiseExecuteDone(napi_env env, napi_status status, void *data)
{
    USERAUTH_HILOGI(MODULE_JS_NAPI, "GetPropertyPromiseExecuteDone, start");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    napi_delete_async_work(env, asyncHolder->asyncWork);
    delete asyncHolder;
    USERAUTH_HILOGI(MODULE_JS_NAPI, "GetPropertyPromiseExecuteDone, end");
}

void UserAuthImpl::GetPropertyAsyncExecuteDone(napi_env env, napi_status status, void *data)
{
    USERAUTH_HILOGI(MODULE_JS_NAPI, "GetPropertyAsyncExecuteDone, start");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    napi_delete_async_work(env, asyncHolder->asyncWork);
    delete asyncHolder;
    USERAUTH_HILOGI(MODULE_JS_NAPI, "GetPropertyAsyncExecuteDone, end");
}

napi_value UserAuthImpl::GetPropertyAsync(napi_env env, AsyncHolder *asyncHolder)
{
    USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s, asyncCallback.", __func__);
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, GetPropertyExecute, GetPropertyAsyncExecuteDone,
        (void *)asyncHolder, &asyncHolder->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncHolder->asyncWork));
    USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s, asyncCallback end.", __func__);
    return result;
}

napi_value UserAuthImpl::GetPropertyPromise(napi_env env, AsyncHolder *asyncHolder)
{
    USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s, promise.", __func__);
    GetPropertyInfo *getPropertyInfo = reinterpret_cast<GetPropertyInfo *>(asyncHolder->data);
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    getPropertyInfo->callBackInfo.callBack = nullptr;
    getPropertyInfo->callBackInfo.deferred = deferred;
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, GetPropertyExecute, GetPropertyPromiseExecuteDone,
        (void *)asyncHolder, &asyncHolder->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncHolder->asyncWork));
    USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s, promise end.", __func__);
    return promise;
}

napi_value UserAuthImpl::SetProperty(napi_env env, napi_callback_info info)
{
    AsyncHolder *asyncHolder = new (std::nothrow) AsyncHolder();
    if (asyncHolder == nullptr) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "%{public}s asyncHolder nullptr", __func__);
        return nullptr;
    }
    SetPropertyInfo *setPropertyInfo = new (std::nothrow) SetPropertyInfo();
    if (setPropertyInfo == nullptr) {
        delete asyncHolder;
        USERAUTH_HILOGE(MODULE_JS_NAPI, "%{public}s setPropertyInfo nullptr", __func__);
        return nullptr;
    }
    setPropertyInfo->callBackInfo.env = env;
    asyncHolder->data = setPropertyInfo;
    napi_value ret = SetPropertyWrap(env, info, asyncHolder);
    if (ret == nullptr) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "%{public}s SetPropertyWrap fail", __func__);
        delete setPropertyInfo;
        if (asyncHolder->asyncWork != nullptr) {
            napi_delete_async_work(env, asyncHolder->asyncWork);
        }
        delete asyncHolder;
    }
    return ret;
}

napi_value UserAuthImpl::SetPropertyWrap(napi_env env, napi_callback_info info, AsyncHolder *asyncHolder)
{
    USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s, called", __func__);
    SetPropertyInfo *setPropertyInfo = reinterpret_cast<SetPropertyInfo *>(asyncHolder->data);
    size_t argcAsync = ARGS_TWO;
    const size_t argcPromise = ARGS_ONE;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, nullptr, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }
    if (argcAsync > PARAM1) {
        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, args[PARAM1], &valuetype);
        if (valuetype == napi_function) {
            NAPI_CALL(env, napi_create_reference(env, args[PARAM1], 1, &(setPropertyInfo->callBackInfo.callBack)));
        }
    }

    if (authBuild.NapiTypeObject(env, args[PARAM0])) {
        Napi_SetPropertyRequest request = authBuild.SetPropertyRequestBuild(env, args[0]);
        setPropertyInfo->authType = request.authType_;
        setPropertyInfo->key = request.key_;
        setPropertyInfo->setInfo = request.setInfo_;
    }

    napi_value ret = 0;
    if (argcAsync > argcPromise) {
        ret = SetPropertyAsync(env, asyncHolder);
    } else {
        ret = SetPropertyPromise(env, asyncHolder);
    }
    USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s,end.", __func__);
    return ret;
}

void UserAuthImpl::SetPropertyExecute(napi_env env, void *data)
{
    USERAUTH_HILOGI(MODULE_JS_NAPI, "setPropertyExecute, worker pool thread execute.");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    if (asyncHolder == nullptr) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "SetPropertyExecute, asyncHolder == nullptr");
        return;
    }
    SetPropertyInfo *setPropertyInfo = reinterpret_cast<SetPropertyInfo *>(asyncHolder->data);
    if (setPropertyInfo == nullptr) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "SetPropertyExecute, setPropertyInfo == nullptr");
        return;
    }
    AuthType authTypeGet = AuthType(setPropertyInfo->authType);
    SetPropertyRequest request;
    request.authType = authTypeGet;
    request.key = SetPropertyType(setPropertyInfo->key);
    request.setInfo = setPropertyInfo->setInfo;
    SetPropApiCallback *object = new SetPropApiCallback(setPropertyInfo);
    std::shared_ptr<SetPropApiCallback> callback;
    callback.reset(object);
    UserAuth::GetInstance().SetProperty(request, callback);
    USERAUTH_HILOGI(MODULE_JS_NAPI, "setPropertyExecute, worker pool thread execute end.");
}

void UserAuthImpl::SetPropertyPromiseExecuteDone(napi_env env, napi_status status, void *data)
{
    USERAUTH_HILOGI(MODULE_JS_NAPI, "SetPropertyPromiseExecuteDone, start");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    napi_delete_async_work(env, asyncHolder->asyncWork);
    delete asyncHolder;
    USERAUTH_HILOGI(MODULE_JS_NAPI, "SetPropertyPromiseExecuteDone, end");
}

void UserAuthImpl::SetPropertyAsyncExecuteDone(napi_env env, napi_status status, void *data)
{
    USERAUTH_HILOGI(MODULE_JS_NAPI, "SetPropertyAsyncExecuteDone, start");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    napi_delete_async_work(env, asyncHolder->asyncWork);
    delete asyncHolder;
    USERAUTH_HILOGI(MODULE_JS_NAPI, "SetPropertyAsyncExecuteDone, end");
}

napi_value UserAuthImpl::SetPropertyAsync(napi_env env, AsyncHolder *asyncHolder)
{
    USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s, asyncCallback.", __func__);
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, SetPropertyExecute, SetPropertyAsyncExecuteDone,
        (void *)asyncHolder, &asyncHolder->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncHolder->asyncWork));
    USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s, asyncCallback end.", __func__);
    return result;
}

napi_value UserAuthImpl::SetPropertyPromise(napi_env env, AsyncHolder *asyncHolder)
{
    USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s, promise.", __func__);
    SetPropertyInfo *setPropertyInfo = reinterpret_cast<SetPropertyInfo *>(asyncHolder->data);
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    setPropertyInfo->callBackInfo.callBack = nullptr;
    setPropertyInfo->callBackInfo.deferred = deferred;
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
        SetPropertyExecute, SetPropertyPromiseExecuteDone, (void *)asyncHolder, &asyncHolder->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncHolder->asyncWork));
    USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s, promise end.", __func__);
    return promise;
}

napi_value UserAuthImpl::BuildAuthInfo(napi_env env, AuthInfo *authInfo)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    authInfo->callBackInfo.env = env;
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, authInfo->info, &argc, argv, nullptr, nullptr));
    if (argc != ARGS_FOUR) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "%{public}s, parms error.", __func__);
        return nullptr;
    }
    authInfo->challenge = authBuild.GetUint8ArrayTo64(env, argv[0]);

    if (authBuild.NapiTypeNumber(env, argv[PARAM1])) {
        int64_t type;
        NAPI_CALL(env, napi_get_value_int64(env, argv[PARAM1], &type));
        authInfo->authType = type;
    }

    if (authBuild.NapiTypeNumber(env, argv[PARAM2])) {
        int64_t level;
        NAPI_CALL(env, napi_get_value_int64(env, argv[PARAM2], &level));
        authInfo->authTrustLevel = level;
    }

    if (authBuild.NapiTypeObject(env, argv[PARAM3])) {
        NAPI_CALL(env, napi_get_named_property(env, argv[PARAM3], "onResult", &authInfo->onResultCallBack));
        NAPI_CALL(env, napi_create_reference(env, authInfo->onResultCallBack, PARAM1, &authInfo->onResult));
        NAPI_CALL(env, napi_get_named_property(env, argv[PARAM3], "onAcquireInfo", &authInfo->onAcquireInfoCallBack));
        NAPI_CALL(env, napi_create_reference(env, authInfo->onAcquireInfoCallBack, PARAM1, &authInfo->onAcquireInfo));
    }
    return result;
}

napi_value UserAuthImpl::DoExecute(ExecuteInfo* executeInfo)
{
    bool isPromise = executeInfo->isPromise;
    napi_value result = nullptr;
    if (isPromise) {
        result = executeInfo->promise;
    } else {
        napi_get_null(executeInfo->env, &result);
    }

    AuthApiCallback *object = new (std::nothrow) AuthApiCallback(executeInfo);
    if (object == nullptr) {
        delete executeInfo;
        return nullptr;
    }
    std::shared_ptr<AuthApiCallback> callback;
    callback.reset(object);
    std::map<std::string, AuthTurstLevel> convertAuthTurstLevel = {
        { "S1", ATL1 },
        { "S2", ATL2 },
        { "S3", ATL3 },
        { "S4", ATL4 },
    };
    if (convertAuthTurstLevel.count(executeInfo->level) == 0) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "execute convertAuthTurstLevel is 0");
        delete executeInfo;
        return nullptr;
    }

    UserAuth::GetInstance().Auth(0, FACE, convertAuthTurstLevel[executeInfo->level], callback);
    return result;
}

napi_value UserAuthImpl::Execute(napi_env env, napi_callback_info info)
{
    USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s, start", __func__);
    ExecuteInfo *executeInfo = new (std::nothrow) ExecuteInfo();
    if (executeInfo == nullptr) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "%{public}s executeInfo nullptr", __func__);
        return nullptr;
    }
    executeInfo->env = env;
    size_t argc = ARGS_MAX_COUNT;
    size_t callbackIndex = 0;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc < PARAM2) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "%{public}s argc check fail", __func__);
        delete executeInfo;
        return nullptr;
    }
    if (!GetExecuteInfo(env, argv, executeInfo)) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "%{public}s GetExecuteInfo fail", __func__);
        delete executeInfo;
        return nullptr;
    }
    callbackIndex = argc - 1;
    napi_valuetype valuetype;
    NAPI_CALL(env, napi_typeof(env, argv[callbackIndex], &valuetype));
    if (valuetype == napi_function) {
        executeInfo->isPromise = false;
        NAPI_CALL(env, napi_create_reference(env, argv[callbackIndex], 1, &executeInfo->callbackRef));
    } else {
        executeInfo->isPromise = true;
        NAPI_CALL(env, napi_create_promise(env, &executeInfo->deferred, &executeInfo->promise));
    }
    return DoExecute(executeInfo);
}

bool UserAuthImpl::GetExecuteInfo(napi_env env, napi_value* argv, ExecuteInfo* executeInfo)
{
    USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s, start.", __func__);
    napi_valuetype valuetype;
    napi_typeof(env, argv[PARAM0], &valuetype);
    if (valuetype != napi_string) {
        return false;
    }
    char *str = nullptr;
    size_t len = 0;
    napi_get_value_string_utf8(env, argv[PARAM0], nullptr, 0, &len);
    if (len > 0) {
        str = new char[len + 1]();
        napi_get_value_string_utf8(env, argv[PARAM0], str, len + 1, &len);
        executeInfo->type = str;
        delete[] str;
    }
    napi_typeof(env, argv[PARAM1], &valuetype);
    if (valuetype != napi_string) {
        return false;
    }
    napi_get_value_string_utf8(env, argv[PARAM1], nullptr, 0, &len);
    if (len > 0) {
        str = new char[len + 1]();
        napi_get_value_string_utf8(env, argv[PARAM1], str, len + 1, &len);
        executeInfo->level = str;
        delete[] str;
    }
    if (executeInfo->type.compare("FACE_ONLY") != 0) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "%{public}s check type fail.", __func__);
        return false;
    }
    return true;
}

napi_value UserAuthImpl::Auth(napi_env env, napi_callback_info info)
{
    USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s, start", __func__);
    AuthInfo *authInfo = new (std::nothrow) AuthInfo();
    if (authInfo == nullptr) {
        USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s authInfo nullptr", __func__);
        return nullptr;
    }
    authInfo->info = info;
    napi_value ret = BuildAuthInfo(env, authInfo);
    if (ret == nullptr) {
        USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s BuildAuthInfo fail", __func__);
        delete authInfo;
        return ret;
    }
    return AuthWrap(env, authInfo);
}

napi_value UserAuthImpl::AuthWrap(napi_env env, AuthInfo *authInfo)
{
    USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s, start.", __func__);
    AuthApiCallback *object = new AuthApiCallback(authInfo);
    std::shared_ptr<AuthApiCallback> callback;
    callback.reset(object);
    uint64_t result = UserAuth::GetInstance().Auth(
        authInfo->challenge, AuthType(authInfo->authType), AuthTurstLevel(authInfo->authTrustLevel), callback);
    USERAUTH_HILOGI(MODULE_JS_NAPI, "UserAuth::GetInstance().Auth.result =  %{public}" PRIu64 "", result);
    napi_value key = authBuild.Uint64ToUint8Array(env, result);
    USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s, end.", __func__);
    return key;
}

napi_value UserAuthImpl::AuthUser(napi_env env, napi_callback_info info)
{
    USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s, start.", __func__);
    AuthUserInfo *userInfo = new (std::nothrow) AuthUserInfo();
    if (userInfo == nullptr) {
        USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s userInfo nullptr", __func__);
        return nullptr;
    }
    userInfo->callBackInfo.env = env;
    userInfo->info = info;
    napi_value ret = BuildAuthUserInfo(env, userInfo);
    if (ret == nullptr) {
        USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s BuildAuthUserInfo fail", __func__);
        delete userInfo;
        return ret;
    }
    return AuthUserWrap(env, userInfo);
}

napi_value UserAuthImpl::BuildAuthUserInfo(napi_env env, AuthUserInfo *userInfo)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, userInfo->info, &argc, argv, nullptr, nullptr));
    if (argc != ARGS_FIVE) {
        USERAUTH_HILOGE(MODULE_JS_NAPI, "%{public}s, parms error.", __func__);
        return nullptr;
    }
    if (authBuild.NapiTypeNumber(env, argv[PARAM0])) {
        int32_t id = 0;
        NAPI_CALL(env, napi_get_value_int32(env, argv[PARAM0], &id));
        userInfo->userId = id;
    }
    userInfo->challenge = authBuild.GetUint8ArrayTo64(env, argv[PARAM1]);
    if (authBuild.NapiTypeNumber(env, argv[PARAM2])) {
        int32_t type = 0;
        napi_get_value_int32(env, argv[PARAM2], &type);
        userInfo->authType = type;
    }
    if (authBuild.NapiTypeNumber(env, argv[PARAM3])) {
        int32_t level = 0;
        NAPI_CALL(env, napi_get_value_int32(env, argv[PARAM3], &level));
        userInfo->authTrustLevel = level;
    }
    if (authBuild.NapiTypeObject(env, argv[PARAM4])) {
        USERAUTH_HILOGI(MODULE_JS_NAPI, "AuthUser is Object");
        NAPI_CALL(env, napi_get_named_property(env, argv[PARAM4], "onResult", &userInfo->onResultCallBack));
        NAPI_CALL(env, napi_create_reference(env, userInfo->onResultCallBack, PARAM1, &userInfo->onResult));
        NAPI_CALL(env, napi_get_named_property(env, argv[PARAM4], "onAcquireInfo", &userInfo->onAcquireInfoCallBack));
        NAPI_CALL(env, napi_create_reference(env, userInfo->onAcquireInfoCallBack, PARAM1, &userInfo->onAcquireInfo));
    }
    return result;
}

napi_value UserAuthImpl::AuthUserWrap(napi_env env, AuthUserInfo *userInfo)
{
    USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s, start.", __func__);
    AuthApiCallback *object = new AuthApiCallback(userInfo);
    std::shared_ptr<AuthApiCallback> callback;
    callback.reset(object);
    uint64_t result = UserAuth::GetInstance().AuthUser(userInfo->userId, userInfo->challenge,
        AuthType(userInfo->authType), AuthTurstLevel(userInfo->authTrustLevel), callback);
    USERAUTH_HILOGI(MODULE_JS_NAPI, "UserAuth::GetInstance().AuthUser. result =  %{public}" PRIu64 "", result);
    napi_value key = authBuild.Uint64ToUint8Array(env, result);
    USERAUTH_HILOGI(MODULE_JS_NAPI, "%{public}s, end.", __func__);
    return key;
}

napi_value UserAuthImpl::CancelAuth(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    uint64_t contextId = authBuild.GetUint8ArrayTo64(env, argv[0]);
    USERAUTH_HILOGI(MODULE_JS_NAPI, "CancelAuth contextId = %{public}" PRIu64 "", contextId);
    if (contextId == 0) {
        return nullptr;
    }
    int32_t result = UserAuth::GetInstance().CancelAuth(contextId);
    USERAUTH_HILOGI(MODULE_JS_NAPI, "CancelAuth result = %{public}d", result);
    napi_value key = 0;
    NAPI_CALL(env, napi_create_int32(env, result, &key));
    return key;
}

static napi_value ModuleInit(napi_env env, napi_value exports)
{
    napi_value val = UserAuthInit(env, exports);
    val = EnumExport(env, val);
    return val;
}
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module module = {
        .nm_version = 1,
        .nm_flags = 0,
        .nm_filename = nullptr,
        .nm_register_func = ModuleInit,
        .nm_modname = "UserAuth",
        .nm_priv = nullptr,
        .reserved = {}
    };
    napi_module_register(&module);
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
