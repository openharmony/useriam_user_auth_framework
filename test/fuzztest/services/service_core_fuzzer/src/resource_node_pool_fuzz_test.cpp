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

#include "resource_node_pool_fuzz_test.h"

#include "common_dummy.h"
#include "resource_node_pool.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_USER_AUTH_SA


namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
void FuzzResourcePoolInsert(Parcel &parcel)
{
    IAM_LOGI("start");
    static_cast<void>(parcel);
    auto node = Common::MakeShared<DummyResourceNode>();
    ResourceNodePool::Instance().Insert(node);
    IAM_LOGI("end");
}

void FuzzResourcePoolDelete(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t executorIndex = parcel.ReadUint64();
    ResourceNodePool::Instance().Delete(executorIndex);
    IAM_LOGI("end");
}

void FuzzResourcePoolDeleteAll(Parcel &parcel)
{
    IAM_LOGI("start");
    static_cast<void>(parcel);
    ResourceNodePool::Instance().DeleteAll();
    IAM_LOGI("end");
}

void FuzzResourcePoolSelect(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t executorIndex = parcel.ReadUint64();
    ResourceNodePool::Instance().Select(executorIndex);
    IAM_LOGI("end");
}

void FuzzResourcePoolGetPoolSize(Parcel &parcel)
{
    IAM_LOGI("start");
    static_cast<void>(parcel);
    ResourceNodePool::Instance().GetPoolSize();
    IAM_LOGI("end");
}

void FuzzRegisterResourceNodePoolListener(Parcel &parcel)
{
    IAM_LOGI("start");
    auto listener = Common::MakeShared<DummyResourceNodePoolListener>();
    ResourceNodePool::Instance().RegisterResourceNodePoolListener(listener);
    IAM_LOGI("end");
}

void FuzzDeregisterResourceNodePoolListener(Parcel &parcel)
{
    IAM_LOGI("start");
    auto listener = Common::MakeShared<DummyResourceNodePoolListener>();
    ResourceNodePool::Instance().DeregisterResourceNodePoolListener(listener);
    IAM_LOGI("end");
}
} // namespace
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

using ResourcePoolFuzzFunc = decltype(OHOS::UserIam::UserAuth::FuzzResourcePoolInsert);
ResourcePoolFuzzFunc *gResourcePoolFuzzFuncs[] = {
    OHOS::UserIam::UserAuth::FuzzResourcePoolInsert,
    OHOS::UserIam::UserAuth::FuzzResourcePoolDelete,
    OHOS::UserIam::UserAuth::FuzzResourcePoolDeleteAll,
    OHOS::UserIam::UserAuth::FuzzResourcePoolSelect,
    OHOS::UserIam::UserAuth::FuzzResourcePoolGetPoolSize,
    OHOS::UserIam::UserAuth::FuzzRegisterResourceNodePoolListener,
    OHOS::UserIam::UserAuth::FuzzDeregisterResourceNodePoolListener,
};

void ResourceNodePoolFuzzTest(OHOS::Parcel &parcel)
{
    uint32_t index = parcel.ReadUint32() % (sizeof(gResourcePoolFuzzFuncs) / sizeof(ResourcePoolFuzzFunc *));
    auto fuzzFunc = gResourcePoolFuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
