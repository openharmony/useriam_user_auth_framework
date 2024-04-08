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
#ifndef IAM_MOCK_UPDATE_PIN_PARAM_INFO_H
#define IAM_MOCK_UPDATE_PIN_PARAM_INFO_H

#include <gmock/gmock.h>

#include "update_pin_param_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockUpdatePinParamInfo final : public UpdatePinParamInterface {
public:
    virtual ~MockUpdatePinParamInfo() = default;
    MOCK_CONST_METHOD0(GetOldCredentialId, uint64_t());
    MOCK_CONST_METHOD0(GetOldRootSecret, std::vector<uint8_t>());
    MOCK_CONST_METHOD0(GetRootSecret, std::vector<uint8_t>());
    MOCK_CONST_METHOD0(GetAuthToken, std::vector<uint8_t>());
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_UPDATE_PIN_PARAM_INFO_H