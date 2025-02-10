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

#ifndef LOAD_MODE_HANDLER_DEFAULT_H
#define LOAD_MODE_HANDLER_DEFAULT_H

#include "load_mode_handler.h"

#include <mutex>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class LoadModeHandlerDefault : public LoadModeHandler {
public:
    LoadModeHandlerDefault();
    ~LoadModeHandlerDefault() override = default;

    void Init() override;
    void OnFwkReady() override;
    void OnExecutorRegistered(AuthType authType, ExecutorRole executorRole) override;
    void OnExecutorUnregistered(AuthType authType, ExecutorRole executorRole) override;
    void OnCredentialUpdated(AuthType authType) override;
    void OnPinAuthServiceReady() override;
    void OnPinAuthServiceStop() override;
    void OnDriverStart() override;
    void OnDriverStop() override;

private:
    bool isInit_ = false;
    std::recursive_mutex mutex_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // LOAD_MODE_HANDLER_DEFAULT_H