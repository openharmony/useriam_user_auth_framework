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

#include "user_auth_impl.h"

#include "user_auth.h"
#include "userauth_callback.h"
#include "userauth_info.h"

#include "auth_build.h"
#include "auth_hilog_wrapper.h"
#include "authapi_callback.h"

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
    HILOG_INFO("GetVersion start");
    int32_t result = UserAuth::GetInstance().GetVersion();
    HILOG_INFO("GetVersion result = %{public}d ", result);
    napi_value version = 0;
    NAPI_CALL(env, napi_create_int32(env, result, &version));
    return version;
}

napi_value UserAuthImpl::GetAvailabeStatus(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s, start", __func__);
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    size_t argc = ARGS_MAX_COUNT;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != ARGS_TWO) {
        HILOG_ERROR("%{public}s, parms error.", __func__);
        return nullptr;
    }
    AuthBuild authBuild;
    AuthType authType = AuthType(authBuild.NapiGetValueInt(env, argv[0]));
    HILOG_INFO("GetAvailabeStatus authType");
    AuthTurstLevel authTurstLevel = AuthTurstLevel(authBuild.NapiGetValueInt(env, argv[1]));
    HILOG_INFO("GetAvailabeStatus authTrustLevel");
    int32_t result = UserAuth::GetInstance().GetAvailableStatus(authType, authTurstLevel);
    napi_value ret = 0;
    NAPI_CALL(env, napi_create_int32(env, result, &ret));
    return ret;
}

napi_value UserAuthImpl::GetProperty(napi_env env, napi_callback_info info)
{
    GetPropertyInfo *getPropertyInfo = new (std::nothrow) GetPropertyInfo();
    getPropertyInfo->callBackInfo.env = env;
    return GetPropertyWrap(env, info, getPropertyInfo);
}

napi_value UserAuthImpl::GetPropertyWrap(napi_env env, napi_callback_info info, GetPropertyInfo *getPropertyInfo)
{
    HILOG_INFO("%{public}s, called", __func__);
    size_t argcAsync = ARGS_TWO;
    const size_t argcPromise = ARGS_ONE;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, nullptr, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        HILOG_ERROR("%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }
    if (argcAsync > PARAM1) {
        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, args[PARAM1], &valuetype);
        if (valuetype == napi_function) {
            NAPI_CALL(env, napi_create_reference(env, args[PARAM1], 1, &(getPropertyInfo->callBackInfo.callBack)));
        }
    }

    // C++ need js parms get
    AuthBuild authBuild;
    if (authBuild.NapiTypeObject(env, args[0])) {
        Napi_GetPropertyRequest request = authBuild.GetPropertyRequestBuild(env, args[0]);
        getPropertyInfo->authType = request.authType_;
        getPropertyInfo->keys = request.keys_;
    }

    napi_value ret = 0;
    if (argcAsync > argcPromise) {
        ret = GetPropertyAsync(env, getPropertyInfo);
    } else {
        ret = GetPropertyPromise(env, getPropertyInfo);
    }
    HILOG_INFO("%{public}s,end.", __func__);
    return ret;
}

void UserAuthImpl::GetPropertyExecute(napi_env env, void *data)
{
    HILOG_INFO("GetPropertyExecute, worker pool thread execute.");
    GetPropertyInfo *getPropertyInfo = static_cast<GetPropertyInfo *>(data);
    if (getPropertyInfo != nullptr) {
        // do something C++
        AuthBuild authBuild;
        AuthType authTypeGet = AuthType(getPropertyInfo->authType);

        GetPropertyRequest request;
        request.authType = authTypeGet;
        request.keys = getPropertyInfo->keys;
        HILOG_INFO("GetPropertyExecute start 1");
        AuthApiCallback *object = new AuthApiCallback();
        object->getPropertyInfo_ = getPropertyInfo;
        std::shared_ptr<AuthApiCallback> callback;
        callback.reset(object);
        UserAuth::GetInstance().GetProperty(request, callback);
    } else {
        HILOG_ERROR("GetPropertyExecute, asynccallBackInfo == nullptr");
    }
    HILOG_INFO("GetPropertyExecute, worker pool thread execute end.");
}

void UserAuthImpl::GetPropertyPromiseExecuteDone(napi_env env, napi_status status, void *data)
{
    HILOG_INFO("GetPropertyPromiseExecuteDone, start");
    if (status != napi_ok) {
        HILOG_ERROR("GetPropertyPromiseExecuteDone status is not ok===>");
        return;
    }
    GetPropertyInfo *getPropertyInfo = static_cast<GetPropertyInfo *>(data);
    napi_delete_async_work(env, getPropertyInfo->asyncWork);
    HILOG_INFO("GetPropertyPromiseExecuteDone, end");
}

void UserAuthImpl::GetPropertyAsyncExecuteDone(napi_env env, napi_status status, void *data)
{
    if (status != napi_ok) {
        HILOG_ERROR("SetPropertyAsyncExecuteDone status is not ok===>");
        return;
    }
    GetPropertyInfo *getPropertyInfo = static_cast<GetPropertyInfo *>(data);
    napi_delete_async_work(env, getPropertyInfo->asyncWork);
    HILOG_INFO("GetPropertyPromiseExecuteDone, end");
}

napi_value UserAuthImpl::GetPropertyAsync(napi_env env, GetPropertyInfo *getPropertyInfo)
{
    HILOG_INFO("%{public}s, asyncCallback.", __func__);
    if (getPropertyInfo == nullptr) {
        HILOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, GetPropertyExecute, GetPropertyAsyncExecuteDone,
        (void *)getPropertyInfo, &getPropertyInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, getPropertyInfo->asyncWork));
    napi_value result = 0;
    NAPI_CALL(env, napi_get_null(env, &result));
    HILOG_INFO("%{public}s, asyncCallback end.", __func__);
    return result;
}

napi_value UserAuthImpl::GetPropertyPromise(napi_env env, GetPropertyInfo *getPropertyInfo)
{
    HILOG_INFO("%{public}s, promise.", __func__);
    if (getPropertyInfo == nullptr) {
        HILOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = 0;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    getPropertyInfo->callBackInfo.callBack = nullptr;
    getPropertyInfo->callBackInfo.deferred = deferred;

    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, GetPropertyExecute, GetPropertyPromiseExecuteDone,
        (void *)getPropertyInfo, &getPropertyInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, getPropertyInfo->asyncWork));
    HILOG_INFO("%{public}s, promise end.", __func__);
    return promise;
}

napi_value UserAuthImpl::SetProperty(napi_env env, napi_callback_info info)
{
    SetPropertyInfo *setPropertyInfo = new (std::nothrow) SetPropertyInfo();
    setPropertyInfo->callBackInfo.env = env;
    return SetPropertyWrap(env, info, setPropertyInfo);
}

napi_value UserAuthImpl::SetPropertyWrap(napi_env env, napi_callback_info info, SetPropertyInfo *setPropertyInfo)
{
    HILOG_INFO("%{public}s, called", __func__);
    size_t argcAsync = ARGS_TWO;
    const size_t argcPromise = ARGS_ONE;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, nullptr, nullptr));
    if (argcAsync > argCountWithAsync || argcAsync > ARGS_MAX_COUNT) {
        HILOG_ERROR("%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }
    if (argcAsync > PARAM1) {
        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, args[PARAM1], &valuetype);
        if (valuetype == napi_function) {
            NAPI_CALL(env, napi_create_reference(env, args[PARAM1], 1, &(setPropertyInfo->callBackInfo.callBack)));
        }
    }

    // C++ need js parms get
    AuthBuild authBuild;
    if (authBuild.NapiTypeObject(env, args[0])) {
        Napi_SetPropertyRequest request = authBuild.SetPropertyRequestBuild(env, args[0]);
        setPropertyInfo->authType = request.authType_;
        setPropertyInfo->key = request.key_;
        setPropertyInfo->setInfo = request.setInfo_;
    }

    napi_value ret = 0;
    if (argcAsync > argcPromise) {
        ret = SetPropertyAsync(env, setPropertyInfo);
    } else {
        ret = SetPropertyPromise(env, setPropertyInfo);
    }
    HILOG_INFO("%{public}s,end.", __func__);
    return ret;
}

void UserAuthImpl::SetPropertyExecute(napi_env env, void *data)
{
    HILOG_INFO("setPropertyExecute, worker pool thread execute.");
    SetPropertyInfo *setPropertyInfo = static_cast<SetPropertyInfo *>(data);
    if (setPropertyInfo != nullptr) {
        // do something C++
        AuthBuild authBuild;
        AuthType authTypeGet = AuthType(setPropertyInfo->authType);

        SetPropertyRequest request;
        request.authType = authTypeGet;
        request.key = SetPropertyType(setPropertyInfo->key);
        request.setInfo = setPropertyInfo->setInfo;
        HILOG_INFO("SetPropertyExecute start 1");
        AuthApiCallback *object = new AuthApiCallback();
        object->setPropertyInfo_ = setPropertyInfo;
        std::shared_ptr<AuthApiCallback> callback;
        callback.reset(object);
        callback->setPropertyInfo_ = setPropertyInfo;
        UserAuth::GetInstance().SetProperty(request, callback);
    } else {
        HILOG_ERROR("setPropertyExecute, asynccallBackInfo == nullptr");
    }
    HILOG_INFO("setPropertyExecute, worker pool thread execute end.");
}

void UserAuthImpl::SetPropertyPromiseExecuteDone(napi_env env, napi_status status, void *data)
{
    HILOG_INFO("SetPropertyPromiseExecuteDone, start");
    if (status != napi_ok) {
        HILOG_ERROR("SetPropertyPromiseExecuteDone status is not ok===>");
        return;
    }
    SetPropertyInfo *setPropertyInfo = static_cast<SetPropertyInfo *>(data);
    napi_delete_async_work(env, setPropertyInfo->asyncWork);
    delete setPropertyInfo;
    setPropertyInfo = nullptr;
    HILOG_INFO("SetPropertyPromiseExecuteDone, start");
}

void UserAuthImpl::SetPropertyAsyncExecuteDone(napi_env env, napi_status status, void *data)
{
    if (status != napi_ok) {
        HILOG_ERROR("setPropertyAsyncExecuteDone status is not ok===>");
        return;
    }
    if (data != nullptr) {
        SetPropertyInfo *setPropertyInfo = static_cast<SetPropertyInfo *>(data);
        if (setPropertyInfo->asyncWork != nullptr) {
            napi_delete_async_work(env, setPropertyInfo->asyncWork);
        }
        delete setPropertyInfo;
    }
}

napi_value UserAuthImpl::SetPropertyAsync(napi_env env, SetPropertyInfo *setPropertyInfo)
{
    HILOG_INFO("%{public}s, asyncCallback.", __func__);
    if (setPropertyInfo == nullptr) {
        HILOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, SetPropertyExecute, SetPropertyAsyncExecuteDone,
        (void *)setPropertyInfo, &setPropertyInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, setPropertyInfo->asyncWork));
    napi_value result = 0;
    NAPI_CALL(env, napi_get_null(env, &result));
    HILOG_INFO("%{public}s, asyncCallback end.", __func__);
    return result;
}

napi_value UserAuthImpl::SetPropertyPromise(napi_env env, SetPropertyInfo *setPropertyInfo)
{
    HILOG_INFO("%{public}s, promise.", __func__);
    if (setPropertyInfo == nullptr) {
        HILOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    napi_value resourceName = 0;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = 0;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    setPropertyInfo->callBackInfo.callBack = nullptr;
    setPropertyInfo->callBackInfo.deferred = deferred;

    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, SetPropertyExecute, SetPropertyPromiseExecuteDone,
        (void *)setPropertyInfo, &setPropertyInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, setPropertyInfo->asyncWork));
    HILOG_INFO("%{public}s, promise end.", __func__);
    return promise;
}

napi_value UserAuthImpl::Auth(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s, start", __func__);
    AuthInfo *authInfo = new (std::nothrow) AuthInfo();
    authInfo->info = info;
    authInfo->callBackInfo.env = env;
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, authInfo->info, &argc, argv, nullptr, nullptr));
    if (argc != ARGS_FOUR) {
        HILOG_ERROR("%{public}s, parms error.", __func__);
        return nullptr;
    }
    AuthBuild authBuild;
    authInfo->challenge = authBuild.GetUint8ArrayTo64(env, argv[0]);

    if (authBuild.NapiTypeNumber(env, argv[1])) {
        int64_t type;
        NAPI_CALL(env, napi_get_value_int64(env, argv[1], &type));
        authInfo->authType = type;
    }

    if (authBuild.NapiTypeNumber(env, argv[ARGS_TWO])) {
        int64_t level;
        NAPI_CALL(env, napi_get_value_int64(env, argv[ARGS_TWO], &level));
        authInfo->authTrustLevel = level;
    }

    if (authBuild.NapiTypeObject(env, argv[ARGS_THREE])) {
        HILOG_INFO("%{public}s, get callback function start.", __func__);
        authInfo->jsFunction = argv[ARGS_THREE];
        napi_value value;
        NAPI_CALL(env, napi_get_named_property(env, argv[ARGS_THREE], "onResult", &value));
        NAPI_CALL(env, napi_create_reference(env, value, 1, &authInfo->onResultCallBack));
        NAPI_CALL(env, napi_get_named_property(env, argv[ARGS_THREE], "onAcquireInfo", &value));
        NAPI_CALL(env, napi_create_reference(env, value, 1, &authInfo->onAcquireInfoCallBack));
    }
    return AuthWrap(env, authInfo);
}

napi_value UserAuthImpl::AuthWrap(napi_env env, AuthInfo *authInfo)
{
    HILOG_INFO("%{public}s, start.", __func__);
    if (authInfo == nullptr) {
        HILOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    AuthBuild authBuild;
    AuthApiCallback *object = new AuthApiCallback();
    object->authInfo_ = authInfo;
    object->userInfo_ = nullptr;
    std::shared_ptr<AuthApiCallback> callback;
    callback.reset(object);
    uint64_t result = UserAuth::GetInstance().Auth(
        authInfo->challenge, AuthType(authInfo->authType), AuthTurstLevel(authInfo->authTrustLevel), callback);
    HILOG_INFO("UserAuth::GetInstance().Auth.result =  %{public}llu", result);

    // auth BigInt
    napi_value key = authBuild.Uint64ToUint8Array(env, result);
    HILOG_INFO("%{public}s, end.", __func__);
//    callback->authInfo_ = nullptr;
//    delete authInfo;
    return key;
}

napi_value UserAuthImpl::AuthUser(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s, start.", __func__);
    AuthUserInfo *userInfo = new (std::nothrow) AuthUserInfo();
    userInfo->callBackInfo.env = env;
    userInfo->info = info;
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, userInfo->info, &argc, argv, nullptr, nullptr));
    if (argc != ARGS_FIVE) {
        HILOG_ERROR("%{public}s, parms error.", __func__);
        return nullptr;
    }
    AuthBuild authBuild;
    if (authBuild.NapiTypeNumber(env, argv[0])) {
        int32_t id = 0;
        NAPI_CALL(env, napi_get_value_int32(env, argv[0], &id));
        userInfo->userId = id;
    }

    userInfo->challenge = authBuild.GetUint8ArrayTo64(env, argv[1]);

    if (authBuild.NapiTypeNumber(env, argv[ARGS_TWO])) {
        int32_t type = 0;
        napi_get_value_int32(env, argv[ARGS_TWO], &type);
        userInfo->authType = type;
    }

    if (authBuild.NapiTypeNumber(env, argv[ARGS_THREE])) {
        int32_t level = 0;
        NAPI_CALL(env, napi_get_value_int32(env, argv[ARGS_THREE], &level));
        userInfo->authTrustLevel = level;
    }

    if (authBuild.NapiTypeObject(env, argv[ARGS_FOUR])) {
        userInfo->jsFunction = argv[ARGS_FOUR];
        NAPI_CALL(env, napi_get_named_property(env, argv[ARGS_FOUR], "onResult", &userInfo->onResultCallBack));
        NAPI_CALL(env, napi_get_named_property(env, argv[ARGS_FOUR], "onAcquireInfo",
            &userInfo->onAcquireInfoCallBack));
    }
    return AuthUserWrap(env, userInfo);
}

napi_value UserAuthImpl::AuthUserWrap(napi_env env, AuthUserInfo *userInfo)
{
    HILOG_INFO("%{public}s, start.", __func__);
    if (userInfo == nullptr) {
        HILOG_ERROR("%{public}s, param == nullptr.", __func__);
        return nullptr;
    }
    AuthApiCallback *object = new AuthApiCallback();
    object->authInfo_ = nullptr;
    object->userInfo_ = userInfo;
    std::shared_ptr<AuthApiCallback> callback;
    callback.reset(object);
    uint64_t result = UserAuth::GetInstance().AuthUser(userInfo->userId, userInfo->challenge,
        AuthType(userInfo->authType), AuthTurstLevel(userInfo->authTrustLevel), callback);
    HILOG_INFO("UserAuth::GetInstance().AuthUser. result =  %{public}llu", result);
    AuthBuild authBuild;
    napi_value key = authBuild.Uint64ToUint8Array(env, result);
    HILOG_INFO("%{public}s, end.", __func__);
    callback->userInfo_ = nullptr;
    delete userInfo;
    return key;
}

napi_value UserAuthImpl::CancelAuth(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_MAX_COUNT;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    AuthBuild authBuild;
    uint64_t contextId = authBuild.GetUint8ArrayTo64(env, argv[0]);
    HILOG_INFO("CancelAuth contextId = %{public}llu", contextId);

    int32_t result = UserAuth::GetInstance().CancelAuth(contextId);
    HILOG_INFO("CancelAuth result = %{public}d", result);
    napi_value key = 0;
    NAPI_CALL(env, napi_create_int32(env, result, &key));
    return key;
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
