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

#ifndef MOCK_IAUTH_EXECUTOR_MGR_WRAPPER_H
#define MOCK_IAUTH_EXECUTOR_MGR_WRAPPER_H

#include "gmock/gmock.h"

#include "executor_mgr_wrapper.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS::UserIam::UserAuth;
class MockExecutorMgrWrapper : public ExecutorMgrWrapper {
public:
    virtual ~MockExecutorMgrWrapper() = default;
    MOCK_METHOD2(Register, void(const ExecutorInfo &info, std::shared_ptr<ExecutorRegisterCallback> callback));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // MOCK_IAUTH_EXECUTOR_MGR_WRAPPER_H