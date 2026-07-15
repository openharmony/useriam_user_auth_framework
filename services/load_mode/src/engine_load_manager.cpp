/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "engine_load_manager.h"

#include "hisysevent_adapter.h"

#include "iam_common_defines.h"
#include "iam_logger.h"

#include "relative_timer.h"
#include "system_param_manager.h"
#include "user_auth_engine.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_ENGINE_LOAD_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {

EngineLoadManager &EngineLoadManager::GetInstance()
{
    static EngineLoadManager instance;
    return instance;
}

void EngineLoadManager::StartSubscribe()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (isSubscribed_) {
        return;
    }

    SystemParamManager::GetInstance().WatchParam(STOP_SA_KEY, [](const std::string &value) {
        IAM_LOGI("%{public}s changed, value %{public}s", STOP_SA_KEY, value.c_str());
        EngineLoadManager::GetInstance().OnSaStopping(value == TRUE_STR);
    });
    OnSaStopping(SystemParamManager::GetInstance().GetParam(STOP_SA_KEY, FALSE_STR) == TRUE_STR);

    IAM_LOGI("success");
    isSubscribed_ = true;
}

void EngineLoadManager::OnTimeout()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("timeout");
    timerId_ = std::nullopt;
    ProcessServiceStatus();
}

void EngineLoadManager::OnEngineReady()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("service start");
    isEngineRunning_ = true;
    ProcessServiceStatus();
}

void EngineLoadManager::OnEngineUnavailable()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("service stop");
    isEngineRunning_ = false;
    ProcessServiceStatus();
}

void EngineLoadManager::OnSaStopping(bool isStopping)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    isSaStopping_ = isStopping;
    ProcessServiceStatus();
}

bool EngineLoadManager::Load()
{
    IAM_LOGI("start");
    int32_t loadRet = GetUserAuthEngine().Load();
    if (loadRet != SUCCESS) {
        IAM_LOGE("load %{public}s service failed, ret:%{public}d", GetUserAuthEngine().GetType().c_str(), loadRet);
        SaLoadEngineFailureTrace saLoadEngineFailureTraceInfo = {};
        saLoadEngineFailureTraceInfo.errCode = loadRet;
        UserIam::UserAuth::ReportSaLoadEngineFailure(saLoadEngineFailureTraceInfo);
        return false;
    }
    return true;
}

bool EngineLoadManager::Unload()
{
    IAM_LOGI("start");
    if (GetUserAuthEngine().Unload() != SUCCESS) {
        IAM_LOGE("unload %{public}s service failed", GetUserAuthEngine().GetType().c_str());
        return false;
    }
    return true;
}

void EngineLoadManager::ProcessServiceStatus()
{
    const uint32_t RETRY_LOAD_INTERVAL = 1000; // 1s

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto engineName = GetUserAuthEngine().GetType();
    bool shouldRunning = !isSaStopping_;
    IAM_LOGI("process service %{public}s status %{public}d, isSaStopping_ %{public}d", engineName.c_str(),
        isEngineRunning_, isSaStopping_);
    if (isEngineRunning_ != shouldRunning) {
        if (shouldRunning) {
            bool loadRet = Load();
            if (loadRet) {
                IAM_LOGI("load service %{public}s success", engineName.c_str());
                isEngineRunning_ = true;
            }
        } else {
            bool unloadRet = Unload();
            if (unloadRet) {
                IAM_LOGI("unload service %{public}s success", engineName.c_str());
                isEngineRunning_ = false;
            }
        }
    }

    if (isEngineRunning_ == shouldRunning) {
        if (timerId_ != std::nullopt) {
            RelativeTimer::GetInstance().Unregister(timerId_.value());
            timerId_ = std::nullopt;
        }
    } else {
        if (timerId_ == std::nullopt) {
            timerId_ = RelativeTimer::GetInstance().Register([this]() { OnTimeout(); }, RETRY_LOAD_INTERVAL);
            IAM_LOGI("process fail, retry after %{public}d ms", RETRY_LOAD_INTERVAL);
        }
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
