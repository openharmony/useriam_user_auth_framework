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

#include "engine_state_manager.h"

#include "iam_logger.h"

#include "system_param_manager.h"
#include "user_auth_engine.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_ENGINE_STATE_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
EngineStateManager &EngineStateManager::GetInstance()
{
    static EngineStateManager instance;
    return instance;
}

void EngineStateManager::StartSubscribe()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (isSubscribed_) {
        return;
    }

    bool subscribed = GetUserAuthEngine().SetStatusCallback([](bool running) {
        if (running) {
            EngineStateManager::GetInstance().OnEngineReady();
        } else {
            EngineStateManager::GetInstance().OnEngineUnavailable();
        }
    });
    if (!subscribed) {
        IAM_LOGE("engine subscribe status failed");
        return;
    }

    IAM_LOGI("success");
    isSubscribed_ = true;
}

void EngineStateManager::OnEngineReady()
{
    IAM_LOGI("engine ready");
    std::vector<EngineUpdateCallback> startCallbacksTemp;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (isEngineRunning_.has_value() && isEngineRunning_.value()) {
            IAM_LOGI("engine already ready");
            return;
        }
        isEngineRunning_ = true;
        startCallbacksTemp = startCallbacks_;
    }

    for (auto &callback : startCallbacksTemp) {
        if (callback != nullptr) {
            callback();
        }
    }

    IAM_LOGI("engine ready processed");
}

void EngineStateManager::OnEngineUnavailable()
{
    IAM_LOGI("engine unavailable");
    std::vector<EngineUpdateCallback> stopCallbacksTemp;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (!(isEngineRunning_.has_value() && isEngineRunning_.value())) {
            IAM_LOGI("engine already unavailable");
            return;
        }
        isEngineRunning_ = false;
        SystemParamManager::GetInstance().SetParam(FWK_READY_KEY, FALSE_STR);
        SystemParamManager::GetInstance().SetParam(IS_PIN_FUNCTION_READY_KEY, FALSE_STR);
        stopCallbacksTemp = stopCallbacks_;
    }

    for (const auto &callback : stopCallbacksTemp) {
        if (callback != nullptr) {
            callback();
        }
    }

    IAM_LOGI("engine unavailable processed");
}

void EngineStateManager::RegisterEngineReadyCallback(const EngineUpdateCallback &callback)
{
    IAM_LOGI("register engine ready callback");
    if (callback == nullptr) {
        IAM_LOGE("engine ready callback is null");
        return;
    }

    bool triggerCallback = false;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        startCallbacks_.push_back(callback);
        if (isEngineRunning_.has_value() && isEngineRunning_.value()) {
            triggerCallback = true;
        }
    }

    if (triggerCallback) {
        callback();
    }
}

void EngineStateManager::RegisterEngineUnavailableCallback(const EngineUpdateCallback &callback)
{
    IAM_LOGI("register engine unavailable callback");
    if (callback == nullptr) {
        IAM_LOGE("engine unavailable callback is null");
        return;
    }

    bool triggerCallback = false;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        stopCallbacks_.push_back(callback);
        if (isEngineRunning_.has_value() && !isEngineRunning_.value()) {
            triggerCallback = true;
        }
    }

    if (triggerCallback) {
        callback();
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
