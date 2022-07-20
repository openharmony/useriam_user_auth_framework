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

#ifndef OHOS_USERAUTH_COMMON_H
#define OHOS_USERAUTH_COMMON_H

#include <map>
#include <string>
#include <vector>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "user_auth_client.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
constexpr size_t ARGS_MAX_COUNT = 10;
constexpr size_t ARGS_ASYNC_COUNT = 1;
constexpr size_t NAPI_GET_STRING_SIZE = 128;

constexpr size_t ARGS_ONE = 1;
constexpr size_t ARGS_TWO = 2;
constexpr size_t ARGS_THREE = 3;
constexpr size_t ARGS_FOUR = 4;
constexpr size_t ARGS_FIVE = 5;
constexpr size_t ARGS_SIX = 6;
constexpr size_t ARGS_SEVEN = 7;
constexpr size_t ARGS_EIGHT = 8;
constexpr size_t ARGS_NINE = 9;
constexpr size_t ARGS_TEN = 10;

constexpr size_t PARAM0 = 0;
constexpr size_t PARAM1 = 1;
constexpr size_t PARAM2 = 2;
constexpr size_t PARAM3 = 3;
constexpr size_t PARAM4 = 4;
constexpr size_t PARAM5 = 5;
constexpr size_t PARAM6 = 6;
constexpr size_t PARAM7 = 7;
constexpr size_t PARAM8 = 8;
constexpr size_t PARAM9 = 9;
constexpr size_t PARAM10 = 10;
constexpr int32_t GET_VALUE_ERROR = -1;

struct CallBackInfo {
    napi_env env {nullptr};
    napi_ref callBack {nullptr};
    napi_deferred deferred {nullptr};
};

struct GetPropertyInfo {
    CallBackInfo callBackInfo;
    napi_value result {nullptr};
    int32_t authType;
    std::vector<uint32_t> keys;
    int32_t getResult;
    uint64_t authSubType;
    uint32_t remainTimes;
    uint32_t freezingTime;
};

struct SetPropertyInfo {
    CallBackInfo callBackInfo;
    napi_async_work asyncWork {nullptr};
    napi_value result {nullptr};
    int32_t authType;
    uint32_t key;
    std::vector<uint8_t> setInfo;
    int32_t setResult;
};

struct ExecuteInfo {
    explicit ExecuteInfo(napi_env napiEnv);
    ~ExecuteInfo();
    bool isPromise {false};
    napi_env env {nullptr};
    std::string type;
    UserIam::UserAuth::AuthTrustLevel trustLevel {UserIam::UserAuth::ATL1};
    napi_ref callbackRef {nullptr};
    napi_deferred deferred {nullptr};
    napi_value promise {nullptr};
    int32_t result {0};
};

struct AuthInfo {
    explicit AuthInfo(napi_env napiEnv);
    ~AuthInfo();
    napi_env env {nullptr};
    napi_callback_info info {nullptr};
    napi_value onResultCallBack {nullptr};
    napi_value onAcquireInfoCallBack {nullptr};
    napi_ref onResult {nullptr};
    napi_ref onAcquireInfo {nullptr};
    uint64_t challenge {0};
    int32_t authType {0};
    int32_t authTrustLevel {0};
    int32_t result {0};
    std::vector<uint8_t> token {};
    uint32_t remainTimes {0};
    uint32_t freezingTime {0};
};

struct AuthUserInfo {
    explicit AuthUserInfo(napi_env napiEnv);
    ~AuthUserInfo();
    napi_env env {nullptr};
    napi_callback_info info {nullptr};
    napi_ref onResult {nullptr};
    napi_ref onAcquireInfo {nullptr};
    napi_value onResultCallBack {nullptr};
    napi_value onAcquireInfoCallBack {nullptr};
    int32_t userId {0};
    uint64_t challenge {0};
    int32_t authType {0};
    int32_t authTrustLevel {0};
    int32_t result {0};
    std::vector<uint8_t> token {};
    uint32_t remainTimes {0};
    uint32_t freezingTime {0};
};

// For API6
enum class AuthenticationResult {
    NO_SUPPORT = -1,
    SUCCESS = 0,
    COMPARE_FAILURE = 1,
    CANCELED = 2,
    TIMEOUT = 3,
    CAMERA_FAIL = 4,
    BUSY = 5,
    INVALID_PARAMETERS = 6,
    LOCKED = 7,
    NOT_ENROLLED = 8,
    GENERAL_ERROR = 100,
};

enum GetPropertyType : uint32_t {
    AUTH_SUB_TYPE = 1,
    REMAIN_TIMES = 2,
    FREEZING_TIME = 3,
};

enum SetPropertyType : uint32_t {
    INIT_ALGORITHM = 1,
    FREEZE_TEMPLATE = 2,
    THAW_TEMPLATE = 3,
};

const std::map<int32_t, AuthenticationResult> result2ExecuteResult = {
    {UserIam::UserAuth::ResultCode::SUCCESS, AuthenticationResult::SUCCESS},
    {UserIam::UserAuth::ResultCode::FAIL, AuthenticationResult::COMPARE_FAILURE},
    {UserIam::UserAuth::ResultCode::GENERAL_ERROR, AuthenticationResult::GENERAL_ERROR},
    {UserIam::UserAuth::ResultCode::CANCELED, AuthenticationResult::CANCELED},
    {UserIam::UserAuth::ResultCode::TIMEOUT, AuthenticationResult::TIMEOUT},
    {UserIam::UserAuth::ResultCode::TYPE_NOT_SUPPORT, AuthenticationResult::NO_SUPPORT},
    {UserIam::UserAuth::ResultCode::TRUST_LEVEL_NOT_SUPPORT, AuthenticationResult::NO_SUPPORT},
    {UserIam::UserAuth::ResultCode::BUSY, AuthenticationResult::BUSY},
    {UserIam::UserAuth::ResultCode::INVALID_PARAMETERS, AuthenticationResult::INVALID_PARAMETERS},
    {UserIam::UserAuth::ResultCode::LOCKED, AuthenticationResult::LOCKED},
    {UserIam::UserAuth::ResultCode::NOT_ENROLLED, AuthenticationResult::NOT_ENROLLED},
    {UserIam::UserAuth::ResultCode::IPC_ERROR, AuthenticationResult::GENERAL_ERROR},
    {UserIam::UserAuth::ResultCode::INVALID_CONTEXT_ID, AuthenticationResult::GENERAL_ERROR},
    {UserIam::UserAuth::ResultCode::WRITE_PARCEL_ERROR, AuthenticationResult::GENERAL_ERROR},
    {UserIam::UserAuth::ResultCode::READ_PARCEL_ERROR, AuthenticationResult::GENERAL_ERROR},
    {UserIam::UserAuth::ResultCode::CHECK_PERMISSION_FAILED, AuthenticationResult::GENERAL_ERROR},
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif /* OHOS_USERAUTH_COMMON_H */
