/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "user_auth_impl.h"

#include <cinttypes>
#include <map>

#include "securec.h"

#include "iam_logger.h"
#include "iam_para2str.h"

#include "authapi_callback.h"
#include "user_auth_client_impl.h"

#include "user_auth_client.h"
#include "user_auth_helper.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_NAPI

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
using namespace OHOS::UserIam::UserAuth;
UserAuthImpl::UserAuthImpl()
{
}

UserAuthImpl::~UserAuthImpl()
{
}

napi_value UserAuthImpl::GetVersion(napi_env env, napi_callback_info info)
{
    int32_t result = 0;
    IAM_LOGI("start result = %{public}d", result);
    napi_value version = 0;
    NAPI_CALL(env, napi_create_int32(env, result, &version));
    return version;
}

napi_value UserAuthImpl::GetAvailableStatus(napi_env env, napi_callback_info info)
{
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    size_t argc = ARGS_MAX_COUNT;
    int32_t result = INVALID_PARAMETERS;
    napi_value ret = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != ARGS_TWO) {
        IAM_LOGE("parms error");
        NAPI_CALL(env, napi_create_int32(env, result, &ret));
        return ret;
    }
    int32_t type = authBuild.NapiGetValueInt32(env, argv[PARAM0]);
    if (type == GET_VALUE_ERROR) {
        IAM_LOGE("argv[PARAM0] error");
        NAPI_CALL(env, napi_create_int32(env, result, &ret));
        return ret;
    }
    int32_t level = authBuild.NapiGetValueInt32(env, argv[PARAM1]);
    if (level == GET_VALUE_ERROR) {
        IAM_LOGE("argv[PARAM1] error");
        NAPI_CALL(env, napi_create_int32(env, result, &ret));
        return ret;
    }
    AuthType authType = AuthType(type);
    AuthTrustLevel authTrustLevel = AuthTrustLevel(level);

    result = UserAuthClientImpl::Instance().GetAvailableStatus(authType, authTrustLevel);
    IAM_LOGI("result = %{public}d", result);
    NAPI_CALL(env, napi_create_int32(env, result, &ret));
    return ret;
}

napi_value UserAuthImpl::GetProperty(napi_env env, napi_callback_info info)
{
    AsyncHolder *asyncHolder = new (std::nothrow) AsyncHolder();
    if (asyncHolder == nullptr) {
        IAM_LOGE("asyncHolder is nullptr");
        return nullptr;
    }
    GetPropertyInfo *getPropertyInfo = new (std::nothrow) GetPropertyInfo();
    if (getPropertyInfo == nullptr) {
        delete asyncHolder;
        IAM_LOGE("getPropertyInfo is nullptr");
        return nullptr;
    }
    getPropertyInfo->callBackInfo.env = env;
    asyncHolder->data = getPropertyInfo;
    napi_value ret = GetPropertyWrap(env, info, asyncHolder);
    if (ret == nullptr) {
        IAM_LOGE("GetPropertyWrap fail");
        if (getPropertyInfo->callBackInfo.callBack != nullptr) {
            napi_delete_reference(env, getPropertyInfo->callBackInfo.callBack);
        }
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
    IAM_LOGI("start");
    GetPropertyInfo *getPropertyInfo = reinterpret_cast<GetPropertyInfo *>(asyncHolder->data);
    size_t argcAsync = ARGS_TWO;
    const size_t argcPromise = ARGS_ONE;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, nullptr, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        IAM_LOGE("wrong argument count");
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
    IAM_LOGI("end");
    return ret;
}

void UserAuthImpl::GetPropertyExecute(napi_env env, void *data)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    if (asyncHolder == nullptr) {
        IAM_LOGE("asyncHolder is nullptr");
        return;
    }
    GetPropertyInfo *getPropertyInfo = reinterpret_cast<GetPropertyInfo *>(asyncHolder->data);
    if (getPropertyInfo == nullptr) {
        IAM_LOGE("getPropertyInfo is nullptr");
        return;
    }
    AuthType authTypeGet = AuthType(getPropertyInfo->authType);

    GetPropertyRequest request;
    request.authType = authTypeGet;

    for (auto item : getPropertyInfo->keys) {
        request.keys.push_back(static_cast<Attributes::AttributeKey>(item));
    }
    GetPropApiCallback *object = new (std::nothrow) GetPropApiCallback(getPropertyInfo);
    if (object == nullptr) {
        IAM_LOGE("object is nullptr");
        return;
    }
    std::shared_ptr<GetPropApiCallback> callback;
    callback.reset(object);
    UserAuthClient::GetInstance().GetProperty(0, request, callback);
    IAM_LOGI("end");
}

void UserAuthImpl::GetPropertyPromiseExecuteDone(napi_env env, napi_status status, void *data)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    napi_delete_async_work(env, asyncHolder->asyncWork);
    delete asyncHolder;
    IAM_LOGI("end");
}

void UserAuthImpl::GetPropertyAsyncExecuteDone(napi_env env, napi_status status, void *data)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    napi_delete_async_work(env, asyncHolder->asyncWork);
    delete asyncHolder;
    IAM_LOGI("end");
}

napi_value UserAuthImpl::GetPropertyAsync(napi_env env, AsyncHolder *asyncHolder)
{
    IAM_LOGI("start");
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, GetPropertyExecute, GetPropertyAsyncExecuteDone,
        reinterpret_cast<void *>(asyncHolder), &asyncHolder->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncHolder->asyncWork));
    IAM_LOGI("end");
    return result;
}

napi_value UserAuthImpl::GetPropertyPromise(napi_env env, AsyncHolder *asyncHolder)
{
    IAM_LOGI("start");
    GetPropertyInfo *getPropertyInfo = reinterpret_cast<GetPropertyInfo *>(asyncHolder->data);
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    getPropertyInfo->callBackInfo.callBack = nullptr;
    getPropertyInfo->callBackInfo.deferred = deferred;
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, GetPropertyExecute, GetPropertyPromiseExecuteDone,
        reinterpret_cast<void *>(asyncHolder), &asyncHolder->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncHolder->asyncWork));
    IAM_LOGI("end");
    return promise;
}

napi_value UserAuthImpl::SetProperty(napi_env env, napi_callback_info info)
{
    AsyncHolder *asyncHolder = new (std::nothrow) AsyncHolder();
    if (asyncHolder == nullptr) {
        IAM_LOGE("asyncHolder is nullptr");
        return nullptr;
    }
    SetPropertyInfo *setPropertyInfo = new (std::nothrow) SetPropertyInfo();
    if (setPropertyInfo == nullptr) {
        delete asyncHolder;
        IAM_LOGE("setPropertyInfo is nullptr");
        return nullptr;
    }
    setPropertyInfo->callBackInfo.env = env;
    asyncHolder->data = setPropertyInfo;
    napi_value ret = SetPropertyWrap(env, info, asyncHolder);
    if (ret == nullptr) {
        IAM_LOGE("SetPropertyWrap fail");
        if (setPropertyInfo->callBackInfo.callBack != nullptr) {
            napi_delete_reference(env, setPropertyInfo->callBackInfo.callBack);
        }
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
    IAM_LOGI("start");
    SetPropertyInfo *setPropertyInfo = reinterpret_cast<SetPropertyInfo *>(asyncHolder->data);
    size_t argcAsync = ARGS_TWO;
    const size_t argcPromise = ARGS_ONE;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, nullptr, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        IAM_LOGE("wrong argument count");
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
    IAM_LOGI("end");
    return ret;
}

void UserAuthImpl::SetPropertyExecute(napi_env env, void *data)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    if (asyncHolder == nullptr) {
        IAM_LOGE("asyncHolder is nullptr");
        return;
    }
    SetPropertyInfo *setPropertyInfo = reinterpret_cast<SetPropertyInfo *>(asyncHolder->data);
    if (setPropertyInfo == nullptr) {
        IAM_LOGE("setPropertyInfo is nullptr");
        return;
    }
    AuthType authTypeGet = AuthType(setPropertyInfo->authType);
    SetPropertyRequest request;
    request.authType = authTypeGet;
    request.mode = OHOS::UserIam::UserAuth::PropertyMode(setPropertyInfo->key);
    request.attrs.SetUint8ArrayValue(Attributes::AttributeKey(setPropertyInfo->key), setPropertyInfo->setInfo);

    SetPropApiCallback *object = new (std::nothrow) SetPropApiCallback(setPropertyInfo);
    if (object == nullptr) {
        IAM_LOGE("object is nullptr");
        return;
    }
    std::shared_ptr<SetPropApiCallback> callback;
    callback.reset(object);
    UserAuthClient::GetInstance().SetProperty(0, request, callback);
    IAM_LOGI("end");
}

void UserAuthImpl::SetPropertyPromiseExecuteDone(napi_env env, napi_status status, void *data)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    napi_delete_async_work(env, asyncHolder->asyncWork);
    delete asyncHolder;
    IAM_LOGI("end");
}

void UserAuthImpl::SetPropertyAsyncExecuteDone(napi_env env, napi_status status, void *data)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    napi_delete_async_work(env, asyncHolder->asyncWork);
    delete asyncHolder;
    IAM_LOGI("end");
}

napi_value UserAuthImpl::SetPropertyAsync(napi_env env, AsyncHolder *asyncHolder)
{
    IAM_LOGI("start");
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, SetPropertyExecute, SetPropertyAsyncExecuteDone,
        reinterpret_cast<void *>(asyncHolder), &asyncHolder->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncHolder->asyncWork));
    IAM_LOGI("end");
    return result;
}

napi_value UserAuthImpl::SetPropertyPromise(napi_env env, AsyncHolder *asyncHolder)
{
    IAM_LOGI("start");
    SetPropertyInfo *setPropertyInfo = reinterpret_cast<SetPropertyInfo *>(asyncHolder->data);
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    setPropertyInfo->callBackInfo.callBack = nullptr;
    setPropertyInfo->callBackInfo.deferred = deferred;
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
        SetPropertyExecute, SetPropertyPromiseExecuteDone, reinterpret_cast<void *>(asyncHolder),
        &asyncHolder->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncHolder->asyncWork));
    IAM_LOGI("end");
    return promise;
}

napi_value UserAuthImpl::BuildAuthInfo(napi_env env, AuthInfo *authInfo)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, authInfo->info, &argc, argv, nullptr, nullptr));
    if (argc != ARGS_FOUR) {
        IAM_LOGE("parms error");
        return nullptr;
    }
    authInfo->challenge = authBuild.GetUint8Array(env, argv[0]);

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

napi_value UserAuthImpl::Execute(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    std::unique_ptr<ExecuteInfo> executeInfo {new (std::nothrow) ExecuteInfo(env)};
    if (executeInfo == nullptr) {
        IAM_LOGE("executeInfo is nullptr");
        return nullptr;
    }

    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    executeInfo->isPromise = true;
    if (argc > 0) {
        size_t callbackIndex = argc - 1;
        napi_valuetype valuetype;
        NAPI_CALL(env, napi_typeof(env, argv[callbackIndex], &valuetype));
        if (valuetype == napi_function) {
            executeInfo->isPromise = false;
            NAPI_CALL(env, napi_create_reference(env, argv[callbackIndex], 1, &executeInfo->callbackRef));
        } else {
            executeInfo->isPromise = true;
        }
    }

    if (executeInfo->isPromise) {
        NAPI_CALL(env, napi_create_promise(env, &executeInfo->deferred, &executeInfo->promise));
    }

    napi_value retPromise = nullptr;
    if (executeInfo->isPromise) {
        retPromise = executeInfo->promise;
    } else {
        napi_get_null(executeInfo->env, &retPromise);
    }

    ResultCode ret = ParseExecuteParameters(env, argc, argv, (*executeInfo));
    AuthTrustLevel authTrustLevel = executeInfo->trustLevel;
    std::shared_ptr<AuthApiCallback> callback = std::make_shared<AuthApiCallback>(executeInfo.release());
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("ParseExecuteParameters fail");
        UserIam::UserAuth::Attributes extra;
        callback->OnResult(ret, extra);
        return retPromise;
    }
    std::vector<uint8_t> challenge;
    UserAuthClientImpl::Instance().BeginAuthentication(challenge, FACE, authTrustLevel, callback);
    return retPromise;
}

ResultCode UserAuthImpl::ParseExecuteParametersZero(napi_env env, size_t argc, napi_value* argv,
    ExecuteInfo& executeInfo)
{
    napi_valuetype valuetype = napi_undefined;
    napi_typeof(env, argv[PARAM0], &valuetype);
    if (valuetype != napi_string) {
        IAM_LOGE("argv[PARAM0] is not string");
        return ResultCode::INVALID_PARAMETERS;
    }

    size_t len = 0;
    napi_get_value_string_utf8(env, argv[PARAM0], nullptr, 0, &len);

    if (len == 0) {
        IAM_LOGE("string length is 0");
        return ResultCode::INVALID_PARAMETERS;
    }

    char *str = new (std::nothrow) char[len + 1]();
    if (str == nullptr) {
        IAM_LOGE("str is nullptr");
        return ResultCode::INVALID_PARAMETERS;
    }
    napi_get_value_string_utf8(env, argv[PARAM0], str, len + 1, &len);
    executeInfo.type = str;
    delete[] str;

    if (executeInfo.type.compare("ALL") == 0) {
        IAM_LOGE("type is ALL");
        return ResultCode::TYPE_NOT_SUPPORT;
    }

    if (executeInfo.type.compare("FACE_ONLY") != 0) {
        IAM_LOGE("type is invalid");
        return ResultCode::INVALID_PARAMETERS;
    }

    return ResultCode::SUCCESS;
}

ResultCode UserAuthImpl::ParseExecuteParametersOne(napi_env env, size_t argc, napi_value* argv,
    ExecuteInfo& executeInfo)
{
    napi_valuetype valuetype = napi_undefined;
    napi_typeof(env, argv[PARAM1], &valuetype);
    if (valuetype != napi_string) {
        IAM_LOGE("argv[PARAM1] is not string");
        return ResultCode::INVALID_PARAMETERS;
    }
    std::map<std::string, AuthTrustLevel> convertAuthTrustLevel = {
        {"S1", ATL1},
        {"S2", ATL2},
        {"S3", ATL3},
        {"S4", ATL4},
    };
    size_t len = 0;
    napi_get_value_string_utf8(env, argv[PARAM1], nullptr, 0, &len);
    if (len == 0) {
        IAM_LOGE("string length is 0");
        return ResultCode::INVALID_PARAMETERS;
    }

    char *str = new (std::nothrow) char[len + 1]();
    if (str == nullptr) {
        IAM_LOGE("str is null");
        return ResultCode::INVALID_PARAMETERS;
    }
    napi_get_value_string_utf8(env, argv[PARAM1], str, len + 1, &len);
    if (convertAuthTrustLevel.count(str) == 0) {
        IAM_LOGE("trust level invalid");
        delete[] str;
        return ResultCode::INVALID_PARAMETERS;
    }
    executeInfo.trustLevel = convertAuthTrustLevel[str];
    delete[] str;

    return ResultCode::SUCCESS;
}

ResultCode UserAuthImpl::ParseExecuteParameters(napi_env env, size_t argc, napi_value* argv, ExecuteInfo& executeInfo)
{
    if (argc < PARAM2) {
        IAM_LOGE("argc check fail");
        return ResultCode::INVALID_PARAMETERS;
    }

    ResultCode ret = ParseExecuteParametersZero(env, argc, argv, executeInfo);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("ParseExecuteParametersZero fail");
        return ret;
    }

    ret = ParseExecuteParametersOne(env, argc, argv, executeInfo);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("ParseExecuteParametersOne fail");
        return ret;
    }

    return ResultCode::SUCCESS;
}

napi_value UserAuthImpl::Auth(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    AuthInfo *authInfo = new (std::nothrow) AuthInfo(env);
    if (authInfo == nullptr) {
        IAM_LOGE("authInfo is nullptr");
        return nullptr;
    }
    authInfo->info = info;
    napi_value ret = BuildAuthInfo(env, authInfo);
    if (ret == nullptr) {
        IAM_LOGE("BuildAuthInfo fail");
        delete authInfo;
        return ret;
    }
    return AuthWrap(env, authInfo);
}

napi_value UserAuthImpl::AuthWrap(napi_env env, AuthInfo *authInfo)
{
    IAM_LOGI("start");
    AuthApiCallback *object = new (std::nothrow) AuthApiCallback(authInfo);
    if (object == nullptr) {
        IAM_LOGE("object is nullptr");
        return nullptr;
    }
    std::shared_ptr<AuthApiCallback> callback;
    callback.reset(object);

    uint64_t result = UserAuthClientImpl::Instance().BeginAuthentication(authInfo->challenge,
        AuthType(authInfo->authType), AuthTrustLevel(authInfo->authTrustLevel), callback);
    IAM_LOGI("result's low 16 bits is %{public}s", GET_MASKED_STRING(result).c_str());
    napi_value key = authBuild.Uint64ToUint8Array(env, result);
    IAM_LOGI("end");
    return key;
}

napi_value UserAuthImpl::AuthUser(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    AuthUserInfo *userInfo = new (std::nothrow) AuthUserInfo(env);
    if (userInfo == nullptr) {
        IAM_LOGE("userInfo is nullptr");
        return nullptr;
    }
    userInfo->info = info;
    napi_value ret = BuildAuthUserInfo(env, userInfo);
    if (ret == nullptr) {
        IAM_LOGE("BuildAuthUserInfo fail");
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
        IAM_LOGE("parms error");
        return nullptr;
    }
    if (authBuild.NapiTypeNumber(env, argv[PARAM0])) {
        int32_t id = 0;
        NAPI_CALL(env, napi_get_value_int32(env, argv[PARAM0], &id));
        userInfo->userId = id;
    }
    userInfo->challenge = authBuild.GetUint8Array(env, argv[PARAM1]);
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
        NAPI_CALL(env, napi_get_named_property(env, argv[PARAM4], "onResult", &userInfo->onResultCallBack));
        NAPI_CALL(env, napi_create_reference(env, userInfo->onResultCallBack, PARAM1, &userInfo->onResult));
        NAPI_CALL(env, napi_get_named_property(env, argv[PARAM4], "onAcquireInfo", &userInfo->onAcquireInfoCallBack));
        NAPI_CALL(env, napi_create_reference(env, userInfo->onAcquireInfoCallBack, PARAM1, &userInfo->onAcquireInfo));
    }
    return result;
}

napi_value UserAuthImpl::AuthUserWrap(napi_env env, AuthUserInfo *userInfo)
{
    IAM_LOGI("start");
    AuthApiCallback *object = new (std::nothrow) AuthApiCallback(userInfo);
    if (object == nullptr) {
        IAM_LOGE("object is nullptr");
        return nullptr;
    }
    std::shared_ptr<AuthApiCallback> callback;
    callback.reset(object);

    uint64_t result = UserAuthClient::GetInstance().BeginAuthentication(userInfo->userId, userInfo->challenge,
        AuthType(userInfo->authType), AuthTrustLevel(userInfo->authTrustLevel), callback);
    IAM_LOGI("result's low 16 bits is %{public}s", GET_MASKED_STRING(result).c_str());
    napi_value key = authBuild.Uint64ToUint8Array(env, result);
    IAM_LOGI("end");
    return key;
}

napi_value UserAuthImpl::CancelAuth(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    uint64_t contextId = authBuild.GetUint8ArrayTo64(env, argv[0]);
    IAM_LOGI("contextId's low 16 bits is %{public}s", GET_MASKED_STRING(contextId).c_str());
    if (contextId == 0) {
        return nullptr;
    }
    int32_t result = UserAuthClient::GetInstance().CancelAuthentication(contextId);
    IAM_LOGI("result = %{public}d", result);
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
#ifdef USER_AUTH_FOR_KITS
        .nm_modname = "userIAM.userAuth",
#else
        .nm_modname = "UserAuth",
#endif
        .nm_priv = nullptr,
        .reserved = {}
    };
    napi_module_register(&module);
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
