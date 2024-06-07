/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef DUMMY_CONTEXT_POOL_LISTENER_H
#define DUMMY_CONTEXT_POOL_LISTENER_H

#include "context_pool.h"
#include "context_callback_impl.h"
#include "simple_auth_context.h"
#include "dummy_authentication.h"
#include "dummy_iam_callback_interface.h"
#include "iam_ptr.h"


#undef private

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyContextPoolListener : public ContextPool::ContextPoolListener {
public:
    void OnContextPoolInsert(const std::shared_ptr<Context> &context) {};
    void OnContextPoolDelete(const std::shared_ptr<Context> &context) {};
};
}
} // UserAuth
} // UserIam
} // OHOS

#endif // DUMMY_CONTEXT_POOL_LISTENER_H