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

#include "authapi_callback.h"

#include "auth_build.h"
#include "auth_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
AuthApiCallback::AuthApiCallback()
{
}

AuthApiCallback::~AuthApiCallback()
{
}

void AuthApiCallback::onExecutorPropertyInfo(const ExecutorProperty result)
{
    napi_status status;
    HILOG_INFO("AuthApiCallback onExecutorPropertyInfo 1 = %{public}d", result.result);
    peoperty_.result_ = result.result;
    HILOG_INFO("AuthApiCallback onExecutorPropertyInfo 2 = %{public}d", result.authSubType);
    peoperty_.authSubType_ = result.authSubType;
    HILOG_INFO("AuthApiCallback onExecutorPropertyInfo 3 = %{public}u", result.remainTimes);
    peoperty_.remainTimes_ = result.remainTimes;
    HILOG_INFO("AuthApiCallback onExecutorPropertyInfo 4 = %{public}u", result.freezingTime);
    peoperty_.freezingTime_ = result.freezingTime;
    if (getPropertyInfo_ != nullptr) {
        AuthBuild authBuild;
        HILOG_INFO("AuthApiCallback onExecutorPropertyInfo 5 ");
        getPropertyInfo_->result = authBuild.GetNapiExecutorProperty(getPropertyInfo_->callBackInfo.env, peoperty_);
        if (getPropertyInfo_->callBackInfo.callBack != nullptr) {
            HILOG_INFO("AuthApiCallback onExecutorPropertyInfo 6 ");
            napi_value global = nullptr;
            status = napi_get_global(getPropertyInfo_->callBackInfo.env, &global);
            if (status != napi_ok) {
                HILOG_INFO("napi_get_global faild ");
            }
            napi_value resultData[1];
            resultData[0] = getPropertyInfo_->result;
            getPropertyInfo_->result = nullptr;
            napi_value result = nullptr;
            napi_value callBack = nullptr;
            status = napi_get_reference_value(
                getPropertyInfo_->callBackInfo.env, getPropertyInfo_->callBackInfo.callBack, &callBack);
            if (status != napi_ok) {
                HILOG_INFO("napi_get_reference_value faild ");
            }
            status = napi_call_function(getPropertyInfo_->callBackInfo.env, global, callBack, 1, resultData, &result);
            if (status != napi_ok) {
                HILOG_INFO("napi_call_function faild ");
            }
        } else {
            napi_value result = getPropertyInfo_->result;
            napi_deferred deferred = getPropertyInfo_->callBackInfo.deferred;
            status = napi_resolve_deferred(getPropertyInfo_->callBackInfo.env, deferred, result);
            if (status != napi_ok) {
                HILOG_INFO("napi_resolve_deferred faild ");
            }
        }
        delete getPropertyInfo_;
        getPropertyInfo_ = nullptr;
    } else {
        HILOG_INFO("AuthApiCallback onExecutorPropertyInfo getPropertyInfo_ is nullptr");
    }
}

void AuthApiCallback::onAcquireInfo(const int32_t module, const uint32_t acquireInfo, const int32_t extraInfo)
{
    napi_status status;
    if (userInfo_ != nullptr) {
        HILOG_INFO("AuthApiCallback onAcquireInfo userInfo_ start 1");
        userInfo_->module = module;
        userInfo_->acquireInfo = acquireInfo;
        HILOG_INFO("AuthApiCallback onAcquireInfo userInfo_ start 2");
        if (extraInfo == 0) {
            userInfo_->extraInfoIsNull = true;
        } else {
            userInfo_->extraInfoIsNull = false;
        }
        HILOG_INFO("AuthApiCallback onAcquireInfo userInfo_ start 3");
        AuthBuild authBuild;
        authBuild.AuthUserCallBackAcquireInfo(userInfo_->callBackInfo.env, userInfo_);
        napi_value returnOnAcquire = nullptr;
        status = napi_call_function(userInfo_->callBackInfo.env, userInfo_->jsFunction, userInfo_->onAcquireInfoCallBack,
            ARGS_THREE, userInfo_->onAcquireInfoData, &returnOnAcquire);
        if (status != napi_ok) {
            HILOG_ERROR("napi_call_function faild");
        }
        HILOG_INFO("AuthApiCallback onAcquireInfo userInfo_ start 4");
    } else {
        HILOG_INFO("AuthApiCallback onAcquireInfo userInfo_ is nullptr ");
    }

    if (authInfo_ != nullptr) {
        HILOG_INFO("AuthApiCallback onAcquireInfo authInfo_ start 1");
        authInfo_->module = module;
        authInfo_->acquireInfo = acquireInfo;
        HILOG_INFO("AuthApiCallback onAcquireInfo authInfo_ start 2");
        if (extraInfo == 0) {
            authInfo_->extraInfoIsNull = true;
        } else {
            authInfo_->extraInfoIsNull = false;
        }
        HILOG_INFO("AuthApiCallback onAcquireInfo authInfo_ start 3");
        AuthBuild authBuild;
        authBuild.AuthCallBackAcquireInfo(authInfo_->callBackInfo.env, authInfo_);
        napi_value callbackRef;
        status = napi_get_reference_value(authInfo_->callBackInfo.env, authInfo_->onAcquireInfoCallBack, &callbackRef);
        if (status != napi_ok) {
            HILOG_ERROR("napi_get_reference_value faild %{public}d", status);
        }
        napi_value returnOnAcquire = nullptr;
        status = napi_call_function(authInfo_->callBackInfo.env, authInfo_->jsFunction,
            callbackRef, ARGS_THREE, authInfo_->onAcquireInfoData, &returnOnAcquire);
        if (status != napi_ok) {
            HILOG_ERROR("napi_call_function faild");
        }
        HILOG_INFO("AuthApiCallback onAcquireInfo authInfo_ start 4");
    } else {
        HILOG_INFO("AuthApiCallback onAcquireInfo authInfo_ is nullptr ");
    }
    HILOG_INFO("AuthApiCallback onAcquireInfo end");
}

void AuthApiCallback::onResult(const int32_t result, const AuthResult extraInfo)
{
    HILOG_INFO("AuthApiCallback onResult enter");
    napi_status status;
    if (userInfo_ != nullptr) {
        HILOG_INFO("AuthApiCallback onResult userInfo_");
        userInfo_->result = result;
        userInfo_->authResult.token_ = extraInfo.token;
        userInfo_->authResult.remainTimes_ = extraInfo.remainTimes;
        userInfo_->authResult.freezingTime_ = extraInfo.freezingTime;
        AuthBuild authBuild;
        authBuild.AuthUserCallBackResult(userInfo_->callBackInfo.env, userInfo_);
        napi_value return_val = nullptr;
        status = napi_call_function(userInfo_->callBackInfo.env, userInfo_->jsFunction,
            userInfo_->onResultCallBack, ARGS_TWO, userInfo_->onResultData, &return_val);
        if (status != napi_ok) {
            HILOG_ERROR("napi_call_function faild");
        }
    } else {
        HILOG_INFO("AuthApiCallback onResult userInfo_ is nullptr ");
    }
    if (authInfo_ != nullptr) {
        HILOG_INFO("AuthApiCallback onResult authInfo_");
        authInfo_->result = result;
        authInfo_->authResult.token_ = extraInfo.token;
        authInfo_->authResult.remainTimes_ = extraInfo.remainTimes;
        authInfo_->authResult.freezingTime_ = extraInfo.freezingTime;
        AuthBuild authBuild;
        authBuild.AuthCallBackResult(authInfo_->callBackInfo.env, authInfo_);
        napi_value return_val = nullptr;
        napi_value callbackRef;
        status = napi_get_reference_value(authInfo_->callBackInfo.env, authInfo_->onResultCallBack, &callbackRef);
        if (status != napi_ok) {
            HILOG_ERROR("napi_get_reference_value faild %{public}d", status);
        }
        status = napi_call_function(authInfo_->callBackInfo.env, authInfo_->jsFunction, callbackRef,
            ARGS_TWO, authInfo_->onResultData, &return_val);
        if (status != napi_ok) {
            HILOG_ERROR("napi_call_function faild %{public}d", status);
        }
        delete authInfo_;
        authInfo_ = nullptr;
    } else {
        HILOG_INFO("AuthApiCallback onResult authInfo_ is nullptr ");
    }
    HILOG_INFO("AuthApiCallback onResult end");
}

void AuthApiCallback::onSetExecutorProperty(const int32_t result)
{
    HILOG_INFO("onSetExecutorProperty 1 = %{public}d", result);
    napi_status status;
    if (setPropertyInfo_ != nullptr) {
        status = napi_create_int32(setPropertyInfo_->callBackInfo.env, result, &setPropertyInfo_->result);
        if (status != napi_ok) {
            HILOG_ERROR("napi_create_int32 faild");
        }
        if (setPropertyInfo_->callBackInfo.callBack != nullptr) {
            napi_value global = nullptr;
            status = napi_get_global(setPropertyInfo_->callBackInfo.env, &global);
            if (status != napi_ok) {
            HILOG_ERROR("napi_get_global faild");
            }
            napi_value resultData[1];
            resultData[0] = setPropertyInfo_->result;
            setPropertyInfo_->result = nullptr;
            napi_value result = nullptr;
            napi_value callBack = nullptr;
            status = napi_get_reference_value(
                setPropertyInfo_->callBackInfo.env, setPropertyInfo_->callBackInfo.callBack, &callBack);
            if (status != napi_ok) {
            HILOG_ERROR("napi_get_reference_value faild");
            }
            status = napi_call_function(setPropertyInfo_->callBackInfo.env, global, callBack, 1, resultData, &result);
            if (status != napi_ok) {
            HILOG_ERROR("napi_call_function faild");
            }
        } else {
            napi_value result = setPropertyInfo_->result;
            napi_deferred deferred = setPropertyInfo_->callBackInfo.deferred;
            status = napi_resolve_deferred(setPropertyInfo_->callBackInfo.env, deferred, result);
        }
    }
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS