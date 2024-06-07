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

#include "remote_executor_stub_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "parcel.h"

#include "attributes.h"
#include "iam_fuzz_test.h"
#include "iam_common_defines.h"
#include "iam_ptr.h"
#include "iam_logger.h"
#include "remote_executor_stub.h"
#include "user_auth_service.h"
#include "remote_executor_proxy.h"
#include "remote_msg_util.h"

#define LOG_TAG "USER_AUTH_SA"

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {

auto g_RemoteExecutorStub = MakeShared<RemoteExecutorStub>();

void FuzzTest(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint8_t> uint8Vector;
    FillFuzzUint8Vector(parcel, uint8Vector);

    Attributes attr = Attributes();
    attr.SetUint64Value(Attributes::ATTR_SCHEDULE_ID, parcel.ReadUint64());
    g_RemoteExecutorStub->ProcBeginExecuteRequest(attr);

    std::string connectionName = parcel.ReadString();
    std::string srcEndPoint = parcel.ReadString();
    auto request = MakeShared<Attributes>();
    request->SetInt32Value(Attributes::ATTR_MSG_TYPE, parcel.ReadInt32());
    auto reply = MakeShared<Attributes>(uint8Vector);
    g_RemoteExecutorStub->OnMessage(connectionName, srcEndPoint, request, reply);

    ExecutorRole role = static_cast<ExecutorRole>(parcel.ReadInt32());
    g_RemoteExecutorStub->OnMessage(role, uint8Vector);

    ResultCode resultCode = static_cast<ResultCode>(parcel.ReadInt32());
    auto finalResult = MakeShared<Attributes>(uint8Vector);
    g_RemoteExecutorStub->ContinueSchedule(resultCode, finalResult);

    g_RemoteExecutorStub->ProcSendDataMsg(attr);
    IAM_LOGI("end");
}

void RemoteExecutorProxyFuzzTest(Parcel &parcel)
{
    IAM_LOGI("begin");
    
    std::string connectionName = parcel.ReadString();
    ExecutorInfo regiregisterInfo = {};
    auto remoteExecutorProxy = MakeShared<RemoteExecutorProxy>(connectionName, regiregisterInfo);
    remoteExecutorProxy->Start();

    std::string srcEndPoint = parcel.ReadString();
    auto request = MakeShared<Attributes>();
    auto reply = MakeShared<Attributes>();
    remoteExecutorProxy->OnMessage(connectionName, srcEndPoint, request, reply);
    remoteExecutorProxy->OnConnectStatus(connectionName, ConnectStatus::DISCONNECTED);
    uint64_t scheduleId = parcel.ReadUint64();
    std::vector<uint8_t> publicKey;
    FillFuzzUint8Vector(parcel, publicKey);
    Attributes command;
    remoteExecutorProxy->OnBeginExecute(scheduleId, publicKey, command);
    remoteExecutorProxy->OnEndExecute(scheduleId, command);
    remoteExecutorProxy->OnSendData(scheduleId, command);
    remoteExecutorProxy->OnErrorFinish(scheduleId);

    IAM_LOGI("end");
}

void RemoteMsgUtilFuzzTest(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t contextId = parcel.ReadUint64();
    std::string connectionName = parcel.ReadString();
    RemoteMsgUtil::GetConnectionName(contextId, connectionName);
    RemoteMsgUtil::GetExecutorProxyEndPointName();
    RemoteMsgUtil::GetExecutorStubEndPointName();
    AuthParamInner authParam;
    Attributes attr;
    RemoteMsgUtil::EncodeAuthParam(authParam, attr);
    RemoteMsgUtil::DecodeAuthParam(attr, authParam);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzTest);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzTest,
    RemoteExecutorProxyFuzzTest,
    RemoteMsgUtilFuzzTest,
};

void RemoteExecutorStubFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    for (auto fuzzFunc : g_fuzzFuncs) {
        fuzzFunc(parcel);
    }
    return;
}
} // namespace
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::UserAuth::RemoteExecutorStubFuzzTest(data, size);
    return 0;
}