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

#define LOG_FILE_ID LOG_FILE_HDI_WRAPPER

#include "hdi_wrapper_fuzzer.h"
#include "hdi_wrapper.h"

#include <cstdint>
#include <string>
#include <vector>

#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "parcel.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {

// NOTE: this fuzzer only exercises HdiWrapper::GetHdiInstance() and
// GetHdiRemoteObjInstance(), both of which reach for the real HDI driver
// service and contain no pure, mutable logic. Its bug-finding ROI is therefore
// very low; it is kept mainly to guard the proxy-acquisition path against
// crashes on malformed early-init state. Consider folding it into
// hdiengine_fuzzer (which mocks the HDI interface) if the maintenance cost
// grows.

void FuzzGetHdiInstance(Parcel &parcel)
{
    IAM_LOGI("start");
    (void)HdiWrapper::GetHdiInstance();
    IAM_LOGI("end");
}

void FuzzGetHdiRemoteObjInstance(Parcel &parcel)
{
    IAM_LOGI("start");
    (void)HdiWrapper::GetHdiRemoteObjInstance();
    IAM_LOGI("end");
}

using FuzzFunc = void (*)(Parcel &);
FuzzFunc g_FuzzFuncs[] = {
    FuzzGetHdiInstance,
    FuzzGetHdiRemoteObjInstance,
};

} // namespace

void HdiWrapperFuzzTest(Parcel &parcel)
{
    uint32_t index = parcel.ReadUint32() % (sizeof(g_FuzzFuncs) / sizeof(FuzzFunc));
    auto fuzzFunc = g_FuzzFuncs[index];
    fuzzFunc(parcel);
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    OHOS::UserIam::UserAuth::HdiWrapperFuzzTest(parcel);
    return 0;
}
