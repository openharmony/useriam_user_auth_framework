/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "mock_iuser_auth_interface.h"

#include "memory"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

std::shared_ptr<IUserAuthInterface> HdiWrapper::GetHdiInstance()
{
    // A single stateless mock for the whole process, intentionally leaked.
    // Avoids a use-after-free at fuzzer teardown: the static ResourceNodePool is
    // destroyed at exit and its ~ResourceNodeImpl -> DeleteExecutor ->
    // GetHdiInstance chain would otherwise recreate/reach the mock after global
    // singletons have begun being torn down. The mock is stateless (every method
    // returns 0), so a process-wide instance is equivalent to the previous
    // on-demand weak_ptr one.
    static MockIUserAuthInterface *leaky = new (std::nothrow) MockIUserAuthInterface();
    return std::shared_ptr<MockIUserAuthInterface>(leaky, [](MockIUserAuthInterface *) {});
}

sptr<IRemoteObject> HdiWrapper::GetHdiRemoteObjInstance()
{
    sptr<IRemoteObject> tmp(nullptr);
    return tmp;
}

std::shared_ptr<MockIUserAuthInterface> MockIUserAuthInterface::Holder::Get()
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto mock = mock_.lock();
    if (!mock) {
        mock = std::make_shared<MockIUserAuthInterface>();
        mock_ = mock;
    }
    return mock;
}

void MockIUserAuthInterface::Holder::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    mock_.reset();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
