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

#ifndef MOCK_WIDGET_CALLBACK_SERVICE_H
#define MOCK_WIDGET_CALLBACK_SERVICE_H

#include <gmock/gmock.h>

#include "widget_callback_stub.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockWidgetCallbackService final : public WidgetCallbackStub {
public:
    MOCK_METHOD1(SendCommand, int32_t(const std::string &cmdData));
    MOCK_METHOD1(CallbackEnter, int32_t(uint32_t code));
    MOCK_METHOD2(CallbackExit, int32_t(uint32_t code, int32_t result));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // MOCK_USER_AUTH_CALLBACK_SERVICE_H
