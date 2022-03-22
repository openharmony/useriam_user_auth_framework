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

#include <string>
#include <vector>
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "userauth_info.h"

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
    bool isPromise;
    napi_env env;
    std::string type;
    AuthTurstLevel trustLevel;
    napi_ref callbackRef;
    napi_deferred deferred;
    napi_value promise;
    int32_t result;
};

struct AuthInfo {
    CallBackInfo callBackInfo;
    napi_callback_info info;
    napi_async_work asyncWork {nullptr};
    napi_value onResultCallBack;
    napi_value onAcquireInfoCallBack;
    napi_ref onResult;
    napi_ref onAcquireInfo;
    napi_value onResultData[ARGS_TWO];
    napi_value onAcquireInfoData[ARGS_THREE];
    uint64_t challenge;
    int32_t authType;
    int32_t authTrustLevel;
    int32_t result;
    std::vector<uint8_t> token;
    uint32_t remainTimes;
    uint32_t freezingTime;
};

struct AuthUserInfo {
    CallBackInfo callBackInfo;
    napi_callback_info info;
    napi_async_work asyncWork {nullptr};
    napi_ref onResult;
    napi_ref onAcquireInfo;
    napi_value onResultCallBack;
    napi_value onAcquireInfoCallBack;
    napi_value onResultData[ARGS_TWO];
    napi_value onAcquireInfoData[ARGS_THREE];
    int32_t userId;
    uint64_t challenge;
    int32_t authType;
    int32_t authTrustLevel;
    int32_t result;
    std::vector<uint8_t> token;
    uint32_t remainTimes;
    uint32_t freezingTime;
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif /* OHOS_USERAUTH_COMMON_H */
