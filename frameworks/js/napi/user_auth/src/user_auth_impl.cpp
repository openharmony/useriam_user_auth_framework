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

#include <map>

#include "securec.h"

#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"

#include "user_auth_napi_helper.h"
#include "auth_api_callback.h"
#include "user_auth_client_impl.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_NAPI

namespace OHOS {
namespace UserIam {
namespace UserAuth {
napi_value UserAuthImpl::GetVersion(napi_env env, napi_callback_info info)
{
    int32_t result = UserAuthClientImpl::Instance().GetVersion();
    IAM_LOGI("start result = %{public}d", result);
    napi_value version;
    NAPI_CALL(env, napi_create_int32(env, result, &version));
    return version;
}

napi_value UserAuthImpl::GetAvailableStatus(napi_env env, napi_callback_info info)
{
    napi_value argv[ARGS_TWO] = {nullptr};
    size_t argc = ARGS_TWO;
    napi_value result;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != ARGS_TWO) {
        IAM_LOGE("parms error");
        NAPI_CALL(env, napi_create_int32(env, INVALID_PARAMETERS, &result));
        return result;
    }
    int32_t type;
    NAPI_CALL(env, napi_get_value_int32(env, argv[PARAM0], &type));
    int32_t level;
    NAPI_CALL(env, napi_get_value_int32(env, argv[PARAM1], &level));
    AuthType authType = AuthType(type);
    AuthTrustLevel authTrustLevel = AuthTrustLevel(level);
    int32_t status = UserAuthClientImpl::Instance().GetAvailableStatus(authType, authTrustLevel);
    IAM_LOGI("result = %{public}d", status);
    NAPI_CALL(env, napi_create_int32(env, status, &result));
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

    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    napi_value retPromise = nullptr;
    if (argc == ARGS_THREE) {
        executeInfo->isPromise = false;
        NAPI_CALL(env, UserAuthNapiHelper::GetFunctionRef(env, argv[PARAM2], executeInfo->callbackRef));
        NAPI_CALL(env, napi_get_null(executeInfo->env, &retPromise));
    } else if (argc == ARGS_TWO) {
        executeInfo->isPromise = true;
        NAPI_CALL(env, napi_create_promise(env, &executeInfo->deferred, &executeInfo->promise));
        retPromise = executeInfo->promise;
    } else {
        IAM_LOGE("bad params");
        return retPromise;
    }

    AuthType authType;
    ResultCode resultCode;
    std::shared_ptr<AuthApiCallback> callback = std::make_shared<AuthApiCallback>(executeInfo.release());
    NAPI_CALL(env, ParseExecuteAuthType(env, argv[PARAM0], authType, resultCode));
    if (resultCode != ResultCode::SUCCESS) {
        IAM_LOGE("ParseAuthType fail");
        UserIam::UserAuth::Attributes extra;
        callback->OnResult(resultCode, extra);
        return retPromise;
    }
    AuthTrustLevel authTrustLevel;
    NAPI_CALL(env, ParseExecuteSecureLevel(env, argv[PARAM1], authTrustLevel, resultCode));
    if (resultCode != ResultCode::SUCCESS) {
        IAM_LOGE("ParseExecuteSecureLevel fail");
        UserIam::UserAuth::Attributes extra;
        callback->OnResult(resultCode, extra);
        return retPromise;
    }

    std::vector<uint8_t> challenge;
    UserAuthClientImpl::Instance().BeginAuthentication(challenge, FACE, authTrustLevel, callback);
    return retPromise;
}

napi_status UserAuthImpl::ParseExecuteAuthType(napi_env env, napi_value value,
    AuthType &authType, ResultCode &resultCode)
{
    resultCode = ResultCode::FAIL;
    static const size_t maxLen = 20;
    char str[maxLen] = {0};
    size_t len = maxLen;
    napi_status result = UserAuthNapiHelper::GetStrValue(env, value, str, len);
    if (result != napi_ok) {
        IAM_LOGE("getStrValue fail");
        return result;
    }
    static const char *authTypeAll = "ALL";
    static const char *authTypeFaceOnly = "FACE_ONLY";
    if (strcmp(str, authTypeAll) == 0) {
        IAM_LOGE("type ALL not supported");
        resultCode = ResultCode::TYPE_NOT_SUPPORT;
        return napi_ok;
    }
    if (strcmp(str, authTypeFaceOnly) != 0) {
        IAM_LOGE("type is invalid");
        resultCode = ResultCode::INVALID_PARAMETERS;
        return napi_ok;
    }
    resultCode = ResultCode::SUCCESS;
    return napi_ok;
}

napi_status UserAuthImpl::ParseExecuteSecureLevel(napi_env env, napi_value value,
    AuthTrustLevel &authTrustLevel, ResultCode &resultCode)
{
    resultCode = ResultCode::FAIL;
    static const size_t maxLen = 20;
    char str[maxLen] = {0};
    size_t len = maxLen;
    napi_status result = UserAuthNapiHelper::GetStrValue(env, value, str, len);
    if (result != napi_ok) {
        IAM_LOGE("getStrValue fail");
        return result;
    }
    static std::map<std::string, AuthTrustLevel> convertAuthTrustLevel = {
        {"S1", ATL1},
        {"S2", ATL2},
        {"S3", ATL3},
        {"S4", ATL4},
    };
    if (convertAuthTrustLevel.count(str) == 0) {
        IAM_LOGE("trust level invalid");
        resultCode = ResultCode::INVALID_PARAMETERS;
        return napi_ok;
    }
    authTrustLevel = convertAuthTrustLevel[str];
    resultCode = ResultCode::SUCCESS;
    return napi_ok;
}

napi_value UserAuthImpl::Auth(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    AuthInfo *authInfo = new (std::nothrow) AuthInfo(env);
    if (authInfo == nullptr) {
        IAM_LOGE("authInfo is nullptr");
        return nullptr;
    }
    std::shared_ptr<AuthApiCallback> callback = Common::MakeShared<AuthApiCallback>(authInfo);
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        delete authInfo;
        return nullptr;
    }
    size_t argc = ARGS_FOUR;
    napi_value argv[ARGS_FOUR] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != ARGS_FOUR) {
        IAM_LOGE("parms error");
        return nullptr;
    }
    std::vector<uint8_t> challenge;
    if (UserAuthNapiHelper::GetUint8ArrayValue(env, argv[PARAM0], challenge) != napi_ok) {
        IAM_LOGE("challenge invalid, use null challenge");
        challenge.clear();
    }
    int32_t authType;
    NAPI_CALL(env, UserAuthNapiHelper::GetInt32Value(env, argv[PARAM1], authType));
    int32_t authTrustLevel;
    NAPI_CALL(env, UserAuthNapiHelper::GetInt32Value(env, argv[PARAM2], authTrustLevel));
    NAPI_CALL(env, UserAuthNapiHelper::CheckNapiType(env, argv[PARAM3], napi_object));
    napi_value onResultValue;
    NAPI_CALL(env, napi_get_named_property(env, argv[PARAM3], "onResult", &onResultValue));
    NAPI_CALL(env, napi_create_reference(env, onResultValue, 1, &authInfo->onResult));
    napi_value onAcquireInfoValue;
    NAPI_CALL(env, napi_get_named_property(env, argv[PARAM3], "onAcquireInfo", &onAcquireInfoValue));
    NAPI_CALL(env, napi_create_reference(env, onAcquireInfoValue, 1, &authInfo->onAcquireInfo));
    uint64_t result = UserAuthClientImpl::Instance().BeginAuthentication(challenge,
        AuthType(authType), AuthTrustLevel(authTrustLevel), callback);
    IAM_LOGI("result is %{public}s", GET_MASKED_STRING(result).c_str());
    napi_value key = UserAuthNapiHelper::Uint64ToNapiUint8Array(env, result);
    IAM_LOGI("end");
    return key;
}

napi_value UserAuthImpl::CancelAuth(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != ARGS_ONE) {
        IAM_LOGE("parms error");
        return nullptr;
    }
    std::vector<uint8_t> contextIdArray;
    NAPI_CALL(env, UserAuthNapiHelper::GetUint8ArrayValue(env, argv[PARAM0], contextIdArray));
    uint64_t contextId;
    if (memcpy_s(reinterpret_cast<void *>(&contextId), sizeof(contextId),
        contextIdArray.data(), contextIdArray.size()) != EOK) {
        IAM_LOGE("memcpy error");
        return nullptr;
    }
    IAM_LOGI("contextId's low 16 bits is %{public}s", GET_MASKED_STRING(contextId).c_str());
    if (contextId == 0) {
        IAM_LOGE("invalid error");
        return nullptr;
    }
    int32_t result = UserAuthClient::GetInstance().CancelAuthentication(contextId);
    IAM_LOGI("result = %{public}d", result);
    napi_value key;
    NAPI_CALL(env, napi_create_int32(env, result, &key));
    return key;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
