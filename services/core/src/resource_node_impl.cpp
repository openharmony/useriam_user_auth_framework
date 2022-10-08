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

#include "resource_node.h"

#include <cinttypes>
#include <mutex>
#include <unordered_map>

#include "hdi_wrapper.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iam_common_defines.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ResourceNodeImpl : public ResourceNode, public NoCopyable {
public:
    using IUserAuthInterface = OHOS::HDI::UserAuth::V1_0::IUserAuthInterface;
    ResourceNodeImpl(ExecutorRegisterInfo info, std::shared_ptr<ExecutorCallbackInterface> callback);
    ~ResourceNodeImpl() override;

    uint64_t GetExecutorIndex() const override;
    std::string GetOwnerDeviceId() const override;
    uint32_t GetOwnerPid() const override;
    AuthType GetAuthType() const override;
    ExecutorRole GetExecutorRole() const override;
    uint64_t GetExecutorSensorHint() const override;
    uint64_t GetExecutorMatcher() const override;
    ExecutorSecureLevel GetExecutorEsl() const override;
    std::vector<uint8_t> GetExecutorPublicKey() const override;

    int32_t BeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const Attributes &command) override;
    int32_t EndExecute(uint64_t scheduleId, const Attributes &command) override;
    int32_t SetProperty(const Attributes &properties) override;
    int32_t GetProperty(const Attributes &condition, Attributes &values) override;
    void Detach() override;
    friend ResourceNode;

private:
    int32_t SyncWithDriver(std::vector<uint64_t> &templateIdList, std::vector<uint8_t> &fwkPublicKey);

    ExecutorRegisterInfo info_;
    std::shared_ptr<ExecutorCallbackInterface> callback_;
    uint64_t executeIndex_ {0};
    bool synced {false};
};

ResourceNodeImpl::ResourceNodeImpl(ExecutorRegisterInfo info, std::shared_ptr<ExecutorCallbackInterface> callback)
    : info_(std::move(info)),
      callback_(std::move(callback))
{
}

ResourceNodeImpl::~ResourceNodeImpl()
{
    if (!synced) {
        return;
    }
    auto hdi = HdiWrapper::GetHdiInstance();
    if (!hdi) {
        IAM_LOGE("bad hdi");
        return;
    }

    auto result = hdi->DeleteExecutor(executeIndex_);
    if (result != HDF_SUCCESS) {
        IAM_LOGE("hdi DeleteExecutor ****%{public}hx with %{public}d", static_cast<uint16_t>(executeIndex_), result);
        return;
    }
    IAM_LOGI("hdi DeleteExecutor ****%{public}hx success", static_cast<uint16_t>(executeIndex_));
}

uint64_t ResourceNodeImpl::GetExecutorIndex() const
{
    return executeIndex_;
}

std::string ResourceNodeImpl::GetOwnerDeviceId() const
{
    return {};
}

uint32_t ResourceNodeImpl::GetOwnerPid() const
{
    return SUCCESS;
}

AuthType ResourceNodeImpl::GetAuthType() const
{
    return info_.authType;
}

ExecutorRole ResourceNodeImpl::GetExecutorRole() const
{
    return info_.executorRole;
}

uint64_t ResourceNodeImpl::GetExecutorSensorHint() const
{
    return info_.executorSensorHint;
}

uint64_t ResourceNodeImpl::GetExecutorMatcher() const
{
    return info_.executorMatcher;
}

ExecutorSecureLevel ResourceNodeImpl::GetExecutorEsl() const
{
    return info_.esl;
}

std::vector<uint8_t> ResourceNodeImpl::GetExecutorPublicKey() const
{
    return info_.publicKey;
}

int32_t ResourceNodeImpl::BeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
    const Attributes &command)
{
    IAM_LOGI("start");
    if (callback_ != nullptr) {
        return callback_->OnBeginExecute(scheduleId, publicKey, command);
    }
    return GENERAL_ERROR;
}

int32_t ResourceNodeImpl::EndExecute(uint64_t scheduleId, const Attributes &command)
{
    IAM_LOGI("start");
    if (callback_ != nullptr) {
        return callback_->OnEndExecute(scheduleId, command);
    }
    return GENERAL_ERROR;
}

int32_t ResourceNodeImpl::SetProperty(const Attributes &properties)
{
    IAM_LOGI("start");
    if (callback_ != nullptr) {
        return callback_->OnSetProperty(properties);
    }
    return GENERAL_ERROR;
}

int32_t ResourceNodeImpl::GetProperty(const Attributes &condition, Attributes &values)
{
    IAM_LOGI("start");
    if (callback_ != nullptr) {
        return callback_->OnGetProperty(condition, values);
    }
    return GENERAL_ERROR;
}

void ResourceNodeImpl::Detach()
{
    IAM_LOGI("start");
    synced = false;
}

int32_t ResourceNodeImpl::SyncWithDriver(std::vector<uint64_t> &templateIdList, std::vector<uint8_t> &fwkPublicKey)
{
    using HdiExecutorRegisterInfo = OHOS::HDI::UserAuth::V1_0::ExecutorRegisterInfo;
    using HdiAuthType = OHOS::HDI::UserAuth::V1_0::AuthType;
    using HdiExecutorRole = OHOS::HDI::UserAuth::V1_0::ExecutorRole;
    using HdiExecutorSecureLevel = OHOS::HDI::UserAuth::V1_0::ExecutorSecureLevel;

    HdiExecutorRegisterInfo hdiInfo = {
        .authType = static_cast<HdiAuthType>(info_.authType),
        .executorRole = static_cast<HdiExecutorRole>(info_.executorRole),
        .executorSensorHint = info_.executorSensorHint,
        .executorMatcher = info_.executorMatcher,
        .esl = static_cast<HdiExecutorSecureLevel>(info_.esl),
        .publicKey = info_.publicKey,
    };

    auto hdi = HdiWrapper::GetHdiInstance();
    if (!hdi) {
        IAM_LOGE("bad hdi");
        return GENERAL_ERROR;
    }

    int32_t result = hdi->AddExecutor(hdiInfo, executeIndex_, fwkPublicKey, templateIdList);
    if (result != HDF_SUCCESS) {
        IAM_LOGE("hdi AddExecutor failed with code %{public}d", result);
        return GENERAL_ERROR;
    }
    synced = true;
    IAM_LOGI("hdi AddExecutor ****%{public}hx success", static_cast<uint16_t>(executeIndex_));
    return SUCCESS;
}

std::shared_ptr<ResourceNode> ResourceNode::MakeNewResource(const ExecutorRegisterInfo &info,
    const std::shared_ptr<ExecutorCallbackInterface> &callback, std::vector<uint64_t> &templateIdList,
    std::vector<uint8_t> &fwkPublicKey)
{
    auto node = Common::MakeShared<ResourceNodeImpl>(info, callback);
    if (node == nullptr) {
        IAM_LOGE("bad alloc");
        return nullptr;
    }

    int32_t result = node->SyncWithDriver(templateIdList, fwkPublicKey);
    if (result != 0) {
        IAM_LOGE("hdi error with %{public}d", result);
        return nullptr;
    }

    return node;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
