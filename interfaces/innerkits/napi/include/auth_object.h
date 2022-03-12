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

#ifndef AUTH_OBJECT_H
#define AUTH_OBJECT_H

#include <vector>

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class Napi_ExecutorProperty {
public:
    int32_t result_ = 0;
    uint64_t authSubType_ = 0;
    uint32_t remainTimes_ = 0;
    uint32_t freezingTime_ = 0;
};

class Napi_SetPropertyRequest {
public:
    int32_t authType_ = 0;
    uint32_t key_ = 0;
    std::vector<std::uint8_t> setInfo_;
};

class Napi_GetPropertyRequest {
public:
    int32_t authType_ = 0;
    std::vector<uint32_t> keys_;
};

class Napi_AuthResult {
public:
    std::vector<uint8_t> token_;
    uint32_t remainTimes_;
    uint32_t freezingTime_;
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif // AUTH_OBJECT_H
