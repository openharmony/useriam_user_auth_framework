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

#include "napi/native_common.h"
#include "napi/native_node_api.h"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "auth_object.h"
#include "userauth_info.h"

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

struct GetVersionInfo {
    GetVersionInfo() : asyncWork(nullptr) {};
    CallBackInfo callBackInfo;
    napi_async_work asyncWork;
};

struct GetPropertyInfo {
    GetPropertyInfo() : asyncWork(nullptr), result(nullptr) {};
    CallBackInfo callBackInfo;
    napi_async_work asyncWork;
    napi_value result;
    int32_t authType;
    UserIAM::UserAuth::ExecutorProperty property;
    std::vector<uint32_t> keys;
};

struct SetPropertyInfo {
    SetPropertyInfo() : asyncWork(nullptr), result(nullptr) {};
    CallBackInfo callBackInfo;
    napi_async_work asyncWork;
    napi_value result;
    int authType;
    int32_t key;
    std::vector<uint8_t> setInfo;
};

struct AuthInfo {
    AuthInfo() : asyncWork(nullptr) {};
    CallBackInfo callBackInfo;
    napi_callback_info info;
    napi_async_work asyncWork;
    napi_value jsFunction;
    napi_ref onResultCallBack;
    napi_ref onAcquireInfoCallBack;
    napi_value onResultData[ARGS_TWO];
    napi_value onAcquireInfoData[ARGS_THREE];
    uint64_t challenge;
    int32_t authType;
    int32_t authTrustLevel;

    int32_t module;
    uint32_t acquireInfo;
    bool extraInfoIsNull;
    int32_t result;
    Napi_AuthResult authResult;
};

struct AuthUserInfo {
    AuthUserInfo() : asyncWork(nullptr) {};
    CallBackInfo callBackInfo;
    napi_callback_info info;
    napi_async_work asyncWork;
    napi_value jsFunction;
    napi_value onResultCallBack;
    napi_value onAcquireInfoCallBack;
    napi_value onResultData[ARGS_TWO];
    napi_value onAcquireInfoData[ARGS_THREE];
    int32_t userId;
    uint64_t challenge;
    int32_t authType;
    int32_t authTrustLevel;

    int32_t module;
    uint32_t acquireInfo;
    bool extraInfoIsNull;
    int32_t result;
    Napi_AuthResult authResult;
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif /* OHOS_USERAUTH_COMMON_H */