/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "system_param_manager.h"

#include "iservice_registry.h"
#include "parameter.h"
#include "system_ability_definition.h"
#include "system_ability_status_change_stub.h"

#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
const char SYSTEM_VALUE_TRUE[] = "true";
const char IAM_ENABLE_FINGERPRINT_PARAM[] = "persist.useriam.enable.fingerprintauth";

bool IsEnableValue(const char *value)
{
    return (strcmp(value, SYSTEM_VALUE_TRUE) == 0);
}

void ParameterChange(const char *key, const char *value, void *context)
{
    if ((key == nullptr) || (value == nullptr)) {
        IAM_LOGE("return invalid param");
        return;
    }
    IAM_LOGI("receive param %{public}s:%{public}s", key, value);
    if (strcmp(key, IAM_ENABLE_FINGERPRINT_PARAM) != 0) {
        IAM_LOGE("event key mismatch");
        return;
    }
    SystemParamManager::GetInstance().UpdateFingerAuthEnable(IsEnableValue(value));
}
}

class SystemParamServiceStatusListener : public OHOS::SystemAbilityStatusChangeStub, public NoCopyable {
public:
    static void Subscribe();

    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

private:
    static sptr<SystemParamServiceStatusListener> GetInstance();

    SystemParamServiceStatusListener() {};
    ~SystemParamServiceStatusListener() override {};
};

void SystemParamServiceStatusListener::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId != PARAM_WATCHER_DISTRIBUTED_SERVICE_ID) {
        return;
    }

    IAM_LOGI("param watcher service add process begin");
    int32_t ret = WatchParameter(IAM_ENABLE_FINGERPRINT_PARAM, ParameterChange, nullptr);
    if (ret != 0) {
        IAM_LOGE("WatchParameter fail %{public}d", ret);
    }
    IAM_LOGI("param watcher service add process finish");
}

void SystemParamServiceStatusListener::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId != PARAM_WATCHER_DISTRIBUTED_SERVICE_ID) {
        return;
    }

    IAM_LOGE("param watcher service remove process begin");
    int32_t ret = RemoveParameterWatcher(IAM_ENABLE_FINGERPRINT_PARAM, ParameterChange, nullptr);
    if (ret != 0) {
        IAM_LOGE("RemoveParameterWatcher fail %{public}d", ret);
    }
    IAM_LOGI("param watcher service remove process finish");
}

sptr<SystemParamServiceStatusListener> SystemParamServiceStatusListener::GetInstance()
{
    static sptr<SystemParamServiceStatusListener> listener(new (std::nothrow) SystemParamServiceStatusListener());
    if (listener == nullptr) {
        IAM_LOGE("SystemParamServiceStatusListener is null");
    }
    return listener;
}

void SystemParamServiceStatusListener::Subscribe()
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        IAM_LOGE("failed to get SA manager");
        return;
    }

    auto instance = GetInstance();
    IF_FALSE_LOGE_AND_RETURN(instance != NULL);

    int32_t ret = sam->SubscribeSystemAbility(PARAM_WATCHER_DISTRIBUTED_SERVICE_ID, instance);
    if (ret != ERR_OK) {
        IAM_LOGE("failed to subscribe param watcher service status");
        return;
    }

    IAM_LOGI("subscribe param watcher service status success");
}

SystemParamManager::SystemParamManager()
{}

SystemParamManager &SystemParamManager::GetInstance()
{
    static SystemParamManager systemParamManager;
    return systemParamManager;
}

void SystemParamManager::Start()
{
    SystemParamServiceStatusListener::Subscribe();
}

void SystemParamManager::UpdateFingerAuthEnable(bool isFingerAuthEnable)
{
    std::lock_guard<std::recursive_mutex> lock(recursiveMutex_);
    IAM_LOGI("UpdateFingerAuthEnable %{public}d", isFingerAuthEnable);
    isFingerAuthEnable_ = isFingerAuthEnable;
}

bool SystemParamManager::IsAuthTypeEnable(int32_t authType)
{
    std::lock_guard<std::recursive_mutex> lock(recursiveMutex_);
    if ((authType == AuthType::FINGERPRINT) && !isFingerAuthEnable_) {
        IAM_LOGI("fingerprint not enable");
        return false;
    }
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS