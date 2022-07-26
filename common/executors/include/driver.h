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

#ifndef EXECUTOR_DRIVER_H
#define EXECUTOR_DRIVER_H

#include <string>
#include <vector>

#include "nocopyable.h"

#include "executor.h"
#include "idriver_manager.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class Driver : public NoCopyable {
public:
    Driver(const std::string &serviceName, HdiConfig hdiConfig);
    ~Driver() override = default;

    void OnHdiConnect();
    void OnHdiDisconnect();
    void OnFrameworkReady();

private:
    std::mutex mutex_;
    std::string serviceName_;
    HdiConfig hdiConfig_;
    bool hdiConnected_ = false;
    std::vector<std::shared_ptr<Executor>> executorList_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // EXECUTOR_DRIVER_H