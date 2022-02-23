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
#ifndef OHOS_USERAUTH_COMMON_H
#define OHOS_USERAUTH_COMMON_H

#include <string>
#include <vector>

#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
#define ARGS_MAX_COUNT 10
#define ARGS_ASYNC_COUNT 1
#define GET_VALUE_ERROR (-1)
#define NAPI_GET_STRING_SIZE 128

#define ARGS_ONE 1
#define ARGS_TWO 2
#define ARGS_THREE 3
#define ARGS_FOUR 4
#define ARGS_FIVE 5
#define ARGS_SIX 6
#define ARGS_SEVEN 7
#define ARGS_EIGHT 8
#define ARGS_NINE 9
#define ARGS_TEN 10

#define PARAM0 0
#define PARAM1 1
#define PARAM2 2
#define PARAM3 3
#define PARAM4 4
#define PARAM5 5
#define PARAM6 6
#define PARAM7 7
#define PARAM8 8
#define PARAM9 9
#define PARAM10 10

struct CallBackInfo {
    napi_env env;
    napi_ref callBack = 0;
    napi_deferred deferred;
};

struct GetPropertyInfo {
    GetPropertyInfo() : result(nullptr) {};
    CallBackInfo callBackInfo;
    napi_value result;
    int32_t authType;
    std::vector<uint32_t> keys;
    int32_t getResult;
    uint64_t authSubType;
    uint32_t remainTimes;
    uint32_t freezingTime;
};

struct SetPropertyInfo {
    SetPropertyInfo() : asyncWork(nullptr), result(nullptr) {};
    CallBackInfo callBackInfo;
    napi_async_work asyncWork;
    napi_value result;
    int32_t authType;
    uint32_t key;
    std::vector<uint8_t> setInfo;
    int32_t setResult;
};

struct ExecuteInfo {
    bool isPromise;
    napi_env env;
    std::string type;
    std::string level;
    napi_ref callbackRef;
    napi_deferred deferred;
    napi_value promise;
    int32_t result;
};

struct AuthInfo {
    AuthInfo() : asyncWork(nullptr) {};
    CallBackInfo callBackInfo;
    napi_callback_info info;
    napi_async_work asyncWork;
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
    AuthUserInfo() : asyncWork(nullptr) {};
    CallBackInfo callBackInfo;
    napi_callback_info info;
    napi_async_work asyncWork;
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
