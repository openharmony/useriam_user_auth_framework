/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef USER_AUTH_HDI
#define USER_AUTH_HDI

#include "accesstoken_kit.h"
#include "v3_0/iuser_auth_interface.h"
#include "v3_0/message_callback_stub.h"
#include "v3_0/user_auth_types.h"
#include "v3_0/user_auth_interface_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
enum HdiCallerType : int32_t {
    HDI_CALLER_TYPE_INVALID = -1,
    HDI_CALLER_TYPE_HAP = 0,
    HDI_CALLER_TYPE_NATIVE,
};

static inline HdiCallerType ConvertATokenTypeToCallerType(int32_t in)
{
    static const std::map<int32_t, HdiCallerType> data = {
        {Security::AccessToken::TOKEN_INVALID, HdiCallerType::HDI_CALLER_TYPE_INVALID},
        {Security::AccessToken::TOKEN_HAP, HdiCallerType::HDI_CALLER_TYPE_HAP},
        {Security::AccessToken::TOKEN_NATIVE, HdiCallerType::HDI_CALLER_TYPE_NATIVE},
    };
    auto it = data.find(in);
    if (it == data.end()) {
        return HDI_CALLER_TYPE_INVALID;
    }
    return it->second;
}

using IUserAuthInterface = OHOS::HDI::UserAuth::V3_0::IUserAuthInterface;
using HdiAuthType = OHOS::HDI::UserAuth::V3_0::AuthType;
using HdiExecutorRole = OHOS::HDI::UserAuth::V3_0::ExecutorRole;
using HdiExecutorSecureLevel = OHOS::HDI::UserAuth::V3_0::ExecutorSecureLevel;
using HdiPinSubType = OHOS::HDI::UserAuth::V3_0::PinSubType;
using HdiScheduleMode = OHOS::HDI::UserAuth::V3_0::ScheduleMode;
using HdiExecutorRegisterInfo = OHOS::HDI::UserAuth::V3_0::ExecutorRegisterInfo;
using HdiExecutorInfo = OHOS::HDI::UserAuth::V3_0::ExecutorInfo;
using HdiScheduleInfo = OHOS::HDI::UserAuth::V3_0::ScheduleInfo;
using HdiAuthParam = OHOS::HDI::UserAuth::V3_0::AuthParam;
using HdiExecutorSendMsg = OHOS::HDI::UserAuth::V3_0::ExecutorSendMsg;
using HdiAuthResultInfo = OHOS::HDI::UserAuth::V3_0::AuthResultInfo;
using HdiIdentifyResultInfo = OHOS::HDI::UserAuth::V3_0::IdentifyResultInfo;
using HdiEnrollParam = OHOS::HDI::UserAuth::V3_0::EnrollParam;
using HdiUserType = OHOS::HDI::UserAuth::V3_0::UserType;
using HdiCredentialInfo = OHOS::HDI::UserAuth::V3_0::CredentialInfo;
using HdiEnrolledInfo = OHOS::HDI::UserAuth::V3_0::EnrolledInfo;
using HdiEnrollResultInfo = OHOS::HDI::UserAuth::V3_0::EnrollResultInfo;
using HdiEnrolledState = OHOS::HDI::UserAuth::V3_0::EnrolledState;
using HdiReuseUnlockInfo = OHOS::HDI::UserAuth::V3_0::ReuseUnlockInfo;
using HdiReuseUnlockParam = OHOS::HDI::UserAuth::V3_0::ReuseUnlockParam;
using HdiIMessageCallback = OHOS::HDI::UserAuth::V3_0::IMessageCallback;
using UserInfo = OHOS::HDI::UserAuth::V3_0::UserInfo;
using ExtUserInfo = OHOS::HDI::UserAuth::V3_0::ExtUserInfo;
using HdiGlobalConfigType = OHOS::HDI::UserAuth::V3_0::GlobalConfigType;
using HdiGlobalConfigValue = OHOS::HDI::UserAuth::V3_0::GlobalConfigValue;
using HdiGlobalConfigParam = OHOS::HDI::UserAuth::V3_0::GlobalConfigParam;
using HdiUserAuthTokenPlain = OHOS::HDI::UserAuth::V3_0::UserAuthTokenPlain;
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // USER_AUTH_HDI