/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

// Shared `Hdi*` shorthand aliases for the real HDI types (HDI engine internals
// + test mocks). Engine-internal only — never leak the HDI headers into
// core/ipc/etc.

#ifndef IAM_HDI_TYPE_ALIASES_H
#define IAM_HDI_TYPE_ALIASES_H

#include "user_auth/v4_0/imessage_callback.h"
#include "user_auth/v4_0/user_auth_types.h"
#include "user_auth/v4_1/user_auth_types.h"
#include "v4_1/iuser_auth_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

using HdiExecutorRegisterInfo = OHOS::HDI::UserAuth::V4_0::ExecutorRegisterInfo;
using HdiEnrollResultInfo = OHOS::HDI::UserAuth::V4_0::EnrollResultInfo;
using HdiCredentialOperateResult = OHOS::HDI::UserAuth::V4_0::CredentialOperateResult;
using HdiCredentialInfo = OHOS::HDI::UserAuth::V4_0::CredentialInfo;
using HdiEnrolledInfo = OHOS::HDI::UserAuth::V4_0::EnrolledInfo;
using HdiScheduleInfo = OHOS::HDI::UserAuth::V4_0::ScheduleInfo;
using HdiIdentifyResultInfo = OHOS::HDI::UserAuth::V4_0::IdentifyResultInfo;
using HdiEnrollParam = OHOS::HDI::UserAuth::V4_0::EnrollParam;
using HdiEnrollParamExt = OHOS::HDI::UserAuth::V4_1::EnrollParamExt;
using HdiAuthParamBase = OHOS::HDI::UserAuth::V4_0::AuthParamBase;
using HdiAuthParam = OHOS::HDI::UserAuth::V4_0::AuthParam;
using HdiAuthParamExt = OHOS::HDI::UserAuth::V4_1::AuthParamExt;
using HdiAuthResultInfo = OHOS::HDI::UserAuth::V4_0::AuthResultInfo;
using HdiEnrolledState = OHOS::HDI::UserAuth::V4_0::EnrolledState;
using HdiReuseUnlockInfo = OHOS::HDI::UserAuth::V4_0::ReuseUnlockInfo;
using HdiReuseUnlockParam = OHOS::HDI::UserAuth::V4_0::ReuseUnlockParam;
using HdiGlobalConfigParam = OHOS::HDI::UserAuth::V4_0::GlobalConfigParam;
using HdiUserAuthTokenPlain = OHOS::HDI::UserAuth::V4_0::UserAuthTokenPlain;
using HdiIMessageCallback = OHOS::HDI::UserAuth::V4_0::IMessageCallback;
using HdiUserInfo = OHOS::HDI::UserAuth::V4_0::UserInfo;
using HdiExtUserInfo = OHOS::HDI::UserAuth::V4_0::ExtUserInfo;
using HdiExecutorSendMsg = OHOS::HDI::UserAuth::V4_0::ExecutorSendMsg;
using HdiCredentialOperateType = OHOS::HDI::UserAuth::V4_0::CredentialOperateType;
using HdiAuthType = OHOS::HDI::UserAuth::V4_0::AuthType;
using HdiScheduleMode = OHOS::HDI::UserAuth::V4_0::ScheduleMode;
using HdiPinSubType = OHOS::HDI::UserAuth::V4_0::PinSubType;
using HdiExecutorRole = OHOS::HDI::UserAuth::V4_0::ExecutorRole;
using HdiExecutorSecureLevel = OHOS::HDI::UserAuth::V4_0::ExecutorSecureLevel;
using HdiGlobalConfigType = OHOS::HDI::UserAuth::V4_0::GlobalConfigType;
using HdiUserType = OHOS::HDI::UserAuth::V4_0::UserType;
using IUserAuthInterface = OHOS::HDI::UserAuth::V4_1::IUserAuthInterface;

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAM_HDI_TYPE_ALIASES_H
