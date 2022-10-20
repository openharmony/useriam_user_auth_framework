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

#include "service_core_fuzz_test_main.h"

#include "resource_node_fuzz_test.h"
#include "resource_node_pool_fuzz_test.h"
#include "schedule_node_fuzz_test.h"

using FuzzEntryFunc = decltype(ScheduleNodeFuzzTest);
FuzzEntryFunc *gFuzzFuncList[] = {
    ScheduleNodeFuzzTest,
    ResourceNodePoolFuzzTest,
    ResourceNodeFuzzTest,
};

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    uint32_t index = parcel.ReadUint32() % (sizeof(gFuzzFuncList) / sizeof(FuzzEntryFunc *));
    auto fuzzEntryFunc = gFuzzFuncList[index];
    fuzzEntryFunc(parcel);
    return 0;
}