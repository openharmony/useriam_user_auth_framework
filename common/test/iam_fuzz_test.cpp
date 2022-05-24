/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "iam_fuzz_test.h"

#include "iam_logger.h"
#include "securec.h"

#define LOG_LABEL OHOS::UserIAM::Common::LABEL_IAM_COMMON

namespace OHOS {
namespace UserIAM {
namespace Common {
namespace {
constexpr int32_t MAX_DATA_LEN = 200;
}

void FillFuzzUint8Vector(Parcel &parcel, std::vector<uint8_t> &data)
{
    uint32_t len = parcel.ReadUint32() % MAX_DATA_LEN;
    auto buffer = parcel.ReadBuffer(len);
    if (buffer == nullptr) {
        IAM_LOGE("ReadBuffer len %{public}u fail", len);
        return;
    }
    data.resize(len);
    memcpy_s(static_cast<void *>(&data[0]), len, buffer, len);
    IAM_LOGI("fill buffer len %{public}u ok", len);
}

void FillFuzzUint64Vector(Parcel &parcel, std::vector<uint64_t> &data)
{
    uint32_t len = parcel.ReadUint32() % MAX_DATA_LEN;
    uint32_t memLen = len * sizeof(uint64_t);
    auto buffer = parcel.ReadBuffer(memLen);
    if (buffer == nullptr) {
        IAM_LOGE("ReadBuffer len %{public}u fail", memLen);
        return;
    }
    data.resize(len);
    memcpy_s(static_cast<void *>(&data[0]), memLen, buffer, memLen);
    IAM_LOGI("fill buffer len %{public}u ok", len);
}
} // namespace Common
} // namespace UserIAM
} // namespace OHOS