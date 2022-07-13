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

#include "user_idm_client_impl.h"

#include "system_ability_definition.h"

#include "iam_logger.h"
#include "ipc_client_utils.h"
#include "user_idm_callback_stub.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
std::vector<uint8_t> UserIdmClientImpl::OpenSession(int32_t userId)
{
    auto proxy = GetProxy();
    if (!proxy) {
        return {};
    }

    std::vector<uint8_t> challenge;
    auto success = proxy->OpenSession(userId, challenge);
    if (!success) {
        IAM_LOGE("OpenSession ret = %{public}d", success);
    }

    return challenge;
}

void UserIdmClientImpl::CloseSession(int32_t userId)
{
    auto proxy = GetProxy();
    if (!proxy) {
        return;
    }

    proxy->CloseSession(userId);
}

void UserIdmClientImpl::AddCredential(int32_t userId, const CredentialParameters &para,
    const std::shared_ptr<UserIdmClientCallback> &callback)
{
    if (!callback) {
        IAM_LOGE("user idm client callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        Attributes extraInfo;
        callback->OnResult(FAIL, extraInfo);
        return;
    }

    sptr<IdmCallbackInterface> wrapper = {};
    proxy->AddCredential(userId, para.authType, para.pinType.value_or(PIN_SIX), para.token, wrapper, false);
}

void UserIdmClientImpl::UpdateCredential(int32_t userId, const CredentialParameters &para,
    const std::shared_ptr<UserIdmClientCallback> &callback)
{
    if (!callback) {
        IAM_LOGE("user idm client callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        Attributes extraInfo;
        callback->OnResult(FAIL, extraInfo);
        return;
    }

    sptr<IdmCallbackInterface> wrapper = {};
    proxy->UpdateCredential(userId, para.authType, para.pinType.value_or(PIN_SIX), para.token, wrapper);
}

int32_t UserIdmClientImpl::Cancel(int32_t userId)
{
    auto proxy = GetProxy();
    if (!proxy) {
        return FAIL;
    }

    std::optional<std::vector<uint8_t>> challenge;

    return proxy->Cancel(userId, challenge);
}

void UserIdmClientImpl::DeleteCredential(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
    const std::shared_ptr<UserIdmClientCallback> &callback)
{
    if (!callback) {
        IAM_LOGE("user idm client callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        Attributes extraInfo;
        callback->OnResult(FAIL, extraInfo);
        return;
    }

    sptr<IdmCallbackInterface> wrapper = {};
    proxy->DelCredential(userId, credentialId, authToken, wrapper);
}

void UserIdmClientImpl::DeleteUser(int32_t userId, const std::vector<uint8_t> &authToken,
    const std::shared_ptr<UserIdmClientCallback> &callback)
{
    if (!callback) {
        IAM_LOGE("user idm client callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        Attributes extraInfo;
        callback->OnResult(FAIL, extraInfo);
        return;
    }

    sptr<IdmCallbackInterface> wrapper = {};
    proxy->DelUser(userId, authToken, wrapper);
}

int32_t UserIdmClientImpl::EraseUser(int32_t userId, const std::shared_ptr<UserIdmClientCallback> &callback)
{
    if (!callback) {
        IAM_LOGE("user idm client callback is nullptr");
        return FAIL;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        Attributes extraInfo;
        callback->OnResult(FAIL, extraInfo);
        return FAIL;
    }
    sptr<IdmCallbackInterface> wrapper = {};
    return proxy->EnforceDelUser(userId, wrapper);
}

int32_t UserIdmClientImpl::GetCredentialInfo(int32_t userId, AuthType authType,
    const std::shared_ptr<GetCredentialInfoCallback> &callback)
{
    if (!callback) {
        IAM_LOGE("get credential info callback is nullptr");
        return FAIL;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        std::vector<CredentialInfo> infoList;
        callback->OnCredentialInfo(infoList);
        return FAIL;
    }

    sptr<IdmGetCredInfoCallbackInterface> wrapper = {};
    return proxy->GetCredentialInfo(userId, authType, wrapper);
}

int32_t UserIdmClientImpl::GetSecUserInfo(int32_t userId, const std::shared_ptr<GetSecUserInfoCallback> &callback)
{
    if (!callback) {
        IAM_LOGE("get secure info callback is nullptr");
        return FAIL;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        SecUserInfo info = {};
        callback->OnSecUserInfo(info);
        return FAIL;
    }

    sptr<IdmGetSecureUserInfoCallbackInterface> wrapper = {};
    return proxy->GetSecInfo(userId, wrapper);
}

sptr<UserIdmInterface> UserIdmClientImpl::GetProxy()
{
    auto obj = IpcClientUtils::GetRemoteObject(SUBSYS_USERIAM_SYS_ABILITY_USERIDM);
    if (obj == nullptr) {
        IAM_LOGE("failed to get useridm service");
        return nullptr;
    }

    return iface_cast<UserIdmInterface>(obj);
}

UserIdmClient &UserIdmClient::GetInstance()
{
    static UserIdmClientImpl impl;
    return impl;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS