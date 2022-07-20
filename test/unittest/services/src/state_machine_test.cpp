/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "state_machine_test.h"

#include <chrono>

#include "finite_state_machine.h"

#include "mock_thread_handler.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

enum State : uint32_t {
    STATE_INIT,
    STATE_VERIFY_STARING,
    STATE_COLLECT_STARING,
    STATE_AUTH_PROCESSING,
    STATE_VERIFY_STOPPING,
    STATE_COLLECT_STOPPING,
    STATE_END
};

enum Event : uint32_t {
    EVENT_START_AUTH,
    EVENT_VERIFY_STARTED,
    EVENT_COLLECT_STARTED,
    EVENT_AUTH_RESULT_GET,
    EVENT_VERIFY_STOPPED,
    EVENT_COLLECT_STOP,
    EVENT_USER_CANCEL,
    EVENT_TIME_OUT,
};

void StateMachineTest::SetUpTestCase()
{
}

void StateMachineTest::TearDownTestCase()
{
}

void StateMachineTest::SetUp()
{
    ThreadHandler::GetSingleThreadInstance()->EnsureTask(nullptr);
}

void StateMachineTest::TearDown()
{
    ThreadHandler::GetSingleThreadInstance()->EnsureTask(nullptr);
}

HWTEST_F(StateMachineTest, MachineCreateSelfReturn, TestSize.Level0)
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    auto machineBuilder = FiniteStateMachine::Builder::New("testMachine0", STATE_INIT);
    EXPECT_NE(machineBuilder, nullptr);

    auto ret1 = machineBuilder->MakeTransition(STATE_INIT, EVENT_START_AUTH, STATE_VERIFY_STARING);
    EXPECT_NE(ret1, nullptr);

    auto ret2 = ret1->MakeTransition(STATE_VERIFY_STARING, EVENT_VERIFY_STARTED, STATE_COLLECT_STARING);
    EXPECT_EQ(ret2, ret1);
}

HWTEST_F(StateMachineTest, MachineCreateOnlyBuildOnce, TestSize.Level0)
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    auto machineBuilder = FiniteStateMachine::Builder::New("testMachine1", STATE_INIT);
    EXPECT_NE(machineBuilder, nullptr);

    machineBuilder->MakeTransition(STATE_INIT, EVENT_START_AUTH, STATE_VERIFY_STARING)
        ->MakeTransition(STATE_VERIFY_STARING, EVENT_VERIFY_STARTED, STATE_COLLECT_STARING);

    auto first = machineBuilder->Build();
    EXPECT_NE(first, nullptr);

    auto second = machineBuilder->Build();
    EXPECT_EQ(second, nullptr);
}

HWTEST_F(StateMachineTest, MachineCreateCheckTransition, TestSize.Level0)
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    auto machineBuilder = FiniteStateMachine::Builder::New("testMachine2", STATE_INIT);
    EXPECT_NE(machineBuilder, nullptr);

    machineBuilder->MakeTransition(STATE_INIT, EVENT_START_AUTH, STATE_VERIFY_STARING)
        ->MakeTransition(STATE_INIT, EVENT_START_AUTH, STATE_COLLECT_STARING);

    auto machine = machineBuilder->Build();
    EXPECT_EQ(machine, nullptr);
}

HWTEST_F(StateMachineTest, MachineCreateInitialState, TestSize.Level0)
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    auto machineBuilder = FiniteStateMachine::Builder::New("testMachine3", STATE_COLLECT_STOPPING);
    ASSERT_NE(machineBuilder, nullptr);

    machineBuilder->MakeTransition(STATE_COLLECT_STOPPING, EVENT_START_AUTH, STATE_VERIFY_STARING);
    auto machine = machineBuilder->Build();
    ASSERT_NE(machine, nullptr);
    EXPECT_EQ(machine->GetCurrentState(), STATE_COLLECT_STOPPING);
}

HWTEST_F(StateMachineTest, MachineCreateNameCheck, TestSize.Level0)
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    auto machineBuilder = FiniteStateMachine::Builder::New("testMachine4", STATE_COLLECT_STOPPING);
    ASSERT_NE(machineBuilder, nullptr);

    machineBuilder->MakeTransition(STATE_COLLECT_STOPPING, EVENT_START_AUTH, STATE_VERIFY_STARING);
    auto machine = machineBuilder->Build();
    ASSERT_NE(machine, nullptr);
    EXPECT_EQ(machine->GetMachineName(), "testMachine4");
}

HWTEST_F(StateMachineTest, MachineScheduleStepIn, TestSize.Level0)
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    auto machineBuilder = FiniteStateMachine::Builder::New("testMachine5", STATE_INIT);
    ASSERT_NE(machineBuilder, nullptr);

    machineBuilder->MakeTransition(STATE_INIT, EVENT_START_AUTH, STATE_VERIFY_STARING)
        ->MakeTransition(STATE_VERIFY_STARING, EVENT_VERIFY_STARTED, STATE_COLLECT_STARING);

    auto machine = machineBuilder->Build();
    ASSERT_NE(machine, nullptr);
    EXPECT_EQ(machine->GetCurrentState(), STATE_INIT);

    machine->Schedule(EVENT_START_AUTH);
    EXPECT_EQ(machine->EnsureCurrentState(), STATE_VERIFY_STARING);
    machine->Schedule(EVENT_VERIFY_STARTED);
    EXPECT_EQ(machine->EnsureCurrentState(), STATE_COLLECT_STARING);
    machine->Schedule(EVENT_VERIFY_STARTED);
    EXPECT_EQ(machine->EnsureCurrentState(), STATE_COLLECT_STARING);
}

HWTEST_F(StateMachineTest, MachineScheduleWithAction, TestSize.Level0)
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    auto machineBuilder = FiniteStateMachine::Builder::New("testMachine6", STATE_INIT);
    ASSERT_NE(machineBuilder, nullptr);

    MockFunction<void(FiniteStateMachine & machine, uint32_t event)> action1;
    MockFunction<void(FiniteStateMachine & machine, uint32_t event)> action2;
    {
        auto init = [](FiniteStateMachine &machine) { return machine.GetCurrentState() == STATE_INIT; };
        auto verify = [](FiniteStateMachine &machine) { return machine.GetCurrentState() == EVENT_VERIFY_STARTED; };
        InSequence s;
        EXPECT_CALL(action1, Call(Truly(init), EVENT_START_AUTH)).Times(Exactly(1));
        EXPECT_CALL(action2, Call(Truly(verify), EVENT_VERIFY_STARTED)).Times(Exactly(1));
    }

    machineBuilder
        ->MakeTransition(STATE_INIT, EVENT_START_AUTH, STATE_VERIFY_STARING,
            [&action1](FiniteStateMachine &machine, uint32_t event) { action1.Call(machine, event); })
        ->MakeTransition(STATE_VERIFY_STARING, EVENT_VERIFY_STARTED, STATE_COLLECT_STARING,
            [&action2](FiniteStateMachine &machine, uint32_t event) { action2.Call(machine, event); });

    auto machine = machineBuilder->Build();
    ASSERT_NE(machine, nullptr);
    EXPECT_EQ(machine->EnsureCurrentState(), STATE_INIT);

    machine->Schedule(EVENT_START_AUTH);
    EXPECT_EQ(machine->EnsureCurrentState(), STATE_VERIFY_STARING);
    machine->Schedule(EVENT_VERIFY_STARTED);
    EXPECT_EQ(machine->EnsureCurrentState(), STATE_COLLECT_STARING);
    machine->Schedule(EVENT_VERIFY_STARTED);
    EXPECT_EQ(machine->EnsureCurrentState(), STATE_COLLECT_STARING);
}

HWTEST_F(StateMachineTest, MachineScheduleWithComplexActionDirectly, TestSize.Level0)
{
    auto handler = MockThreadHandler::InvokeDirectly();
    auto machineBuilder = FiniteStateMachine::Builder::New("testMachine7", STATE_INIT);
    ASSERT_NE(machineBuilder, nullptr);

    MockFunction<void(FiniteStateMachine & machine, uint32_t event)> action1;
    MockFunction<void(FiniteStateMachine & machine, uint32_t event)> action2;
    {
        auto init = [](FiniteStateMachine &machine) { return machine.GetCurrentState() == STATE_INIT; };
        auto verify = [](FiniteStateMachine &machine) { return machine.GetCurrentState() == EVENT_VERIFY_STARTED; };

        InSequence s;
        EXPECT_CALL(action1, Call(Truly(init), EVENT_START_AUTH)).Times(Exactly(1));
        EXPECT_CALL(action2, Call(Truly(verify), EVENT_VERIFY_STARTED)).Times(Exactly(1));
    }

    machineBuilder
        ->MakeTransition(STATE_INIT, EVENT_START_AUTH, STATE_VERIFY_STARING,
            [&action1](FiniteStateMachine &machine, uint32_t event) {
                action1.Call(machine, event);
                machine.Schedule(EVENT_VERIFY_STARTED);
            })
        ->MakeTransition(STATE_VERIFY_STARING, EVENT_VERIFY_STARTED, STATE_COLLECT_STARING,
            [&action2](FiniteStateMachine &machine, uint32_t event) {
                action2.Call(machine, event);
                machine.Schedule(EVENT_COLLECT_STARTED);
            })
        ->MakeTransition(STATE_COLLECT_STARING, EVENT_COLLECT_STARTED, STATE_AUTH_PROCESSING, nullptr);

    auto machine = machineBuilder->Build();
    ASSERT_NE(machine, nullptr);
    EXPECT_EQ(machine->EnsureCurrentState(), STATE_INIT);

    machine->Schedule(EVENT_START_AUTH);
    EXPECT_EQ(machine->EnsureCurrentState(), STATE_AUTH_PROCESSING);
}

HWTEST_F(StateMachineTest, MachineScheduleWithComplexActionBackGround, TestSize.Level0)
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    auto machineBuilder = FiniteStateMachine::Builder::New("testMachine8", STATE_INIT);
    ASSERT_NE(machineBuilder, nullptr);

    machineBuilder
        ->MakeTransition(STATE_INIT, EVENT_START_AUTH, STATE_VERIFY_STARING,
            [](FiniteStateMachine &machine, [[maybe_unused]] uint32_t event) {
                machine.Schedule(EVENT_VERIFY_STARTED);
                machine.Schedule(EVENT_COLLECT_STARTED);
                machine.Schedule(EVENT_USER_CANCEL);
            })
        ->MakeTransition(STATE_VERIFY_STARING, EVENT_VERIFY_STARTED, STATE_COLLECT_STARING, nullptr)
        ->MakeTransition(STATE_COLLECT_STARING, EVENT_COLLECT_STARTED, STATE_AUTH_PROCESSING, nullptr)
        ->MakeTransition(STATE_AUTH_PROCESSING, EVENT_USER_CANCEL, STATE_END, nullptr);
    auto machine = machineBuilder->Build();
    ASSERT_NE(machine, nullptr);
    EXPECT_EQ(machine->EnsureCurrentState(), STATE_INIT);

    machine->Schedule(EVENT_START_AUTH);
    EXPECT_EQ(machine->EnsureCurrentState(), STATE_END);
}

HWTEST_F(StateMachineTest, MachineScheduleDeadlock, TestSize.Level0)
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    auto machineBuilder = FiniteStateMachine::Builder::New("testMachine9", STATE_INIT);
    ASSERT_NE(machineBuilder, nullptr);
    machineBuilder->MakeTransition(STATE_INIT, STATE_INIT, STATE_INIT, [](FiniteStateMachine &machine, uint32_t event) {
        machine.Schedule(STATE_INIT);
        machine.Schedule(STATE_INIT);
        machine.Schedule(STATE_INIT);
    });
    auto machine = machineBuilder->Build();
    ASSERT_NE(machine, nullptr);
    EXPECT_EQ(machine->EnsureCurrentState(), STATE_INIT);

    machine->Schedule(EVENT_START_AUTH);
    EXPECT_EQ(machine->EnsureCurrentState(), STATE_INIT);
}

HWTEST_F(StateMachineTest, MachineScheduleContinues, TestSize.Level0)
{
    MockFunction<void(FiniteStateMachine & machine, uint32_t event)> action;
    EXPECT_CALL(action, Call(_, STATE_INIT)).Times(Exactly(3));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    {
        auto machineBuilder = FiniteStateMachine::Builder::New("testMachine10", STATE_INIT);
        ASSERT_NE(machineBuilder, nullptr);
        machineBuilder->MakeTransition(STATE_INIT, STATE_INIT, STATE_INIT,
            [&action](FiniteStateMachine &machine, [[maybe_unused]] uint32_t event) {
                action.Call(machine, STATE_INIT);
            });
        auto machine = machineBuilder->Build();
        ASSERT_NE(machine, nullptr);
        machine->Schedule(STATE_INIT);
        machine->Schedule(STATE_INIT);
        machine->Schedule(STATE_INIT);
        handler->EnsureTask(nullptr);
    }
}

HWTEST_F(StateMachineTest, MachineScheduleExpireNodeTimeout, TestSize.Level0)
{
    auto handler = ThreadHandler::GetSingleThreadInstance();

    MockFunction<void(FiniteStateMachine & machine, uint32_t event)> action;
    EXPECT_CALL(action, Call(_, STATE_INIT)).Times(Exactly(5));
    {
        auto machineBuilder = FiniteStateMachine::Builder::New("testMachine11", STATE_INIT);
        ASSERT_NE(machineBuilder, nullptr);
        machineBuilder->MakeTransition(STATE_INIT, STATE_INIT, STATE_INIT,
            [&action](FiniteStateMachine &machine, [[maybe_unused]] uint32_t event) {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                action.Call(machine, STATE_INIT);
            });
        auto machine = machineBuilder->Build();
        ASSERT_NE(machine, nullptr);

        machine->SetThreadHandler(handler);
        handler->EnsureTask(nullptr);
        machine->Schedule(STATE_INIT);
        machine->Schedule(STATE_INIT);
        machine->Schedule(STATE_INIT);
        machine->Schedule(STATE_INIT);
        machine->Schedule(STATE_INIT);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        machine = nullptr;
        handler->EnsureTask(nullptr);
    }
}

HWTEST_F(StateMachineTest, MachineScheduleExpireNodeExpire, TestSize.Level0)
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    MockFunction<void(FiniteStateMachine & machine, uint32_t event)> action;
    EXPECT_CALL(action, Call(_, STATE_INIT)).Times(Exactly(0));
    {
        auto machineBuilder = FiniteStateMachine::Builder::New("testMachine12", STATE_INIT);
        ASSERT_NE(machineBuilder, nullptr);
        machineBuilder->MakeTransition(STATE_INIT, STATE_INIT, STATE_INIT,
            [&action](FiniteStateMachine &machine, [[maybe_unused]] uint32_t event) {
                action.Call(machine, STATE_INIT);
            });
        auto machine = machineBuilder->Build();
        ASSERT_NE(machine, nullptr);
        handler->PostTask([]() { std::this_thread::sleep_for(std::chrono::milliseconds(1000)); });
        machine->Schedule(STATE_INIT);
        machine->Schedule(STATE_INIT);
        machine->Schedule(STATE_INIT);
        machine->Schedule(STATE_INIT);
        machine->Schedule(STATE_INIT);
        machine = nullptr;
    }
    handler->EnsureTask(nullptr);
}

HWTEST_F(StateMachineTest, MachineScheduleEnterAndLeave, TestSize.Level0)
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    MockFunction<void(FiniteStateMachine & machine, uint32_t event)> action;
    MockFunction<void(FiniteStateMachine & machine, uint32_t event)> enter;
    MockFunction<void(FiniteStateMachine & machine, uint32_t event)> leave;

    InSequence s;
    EXPECT_CALL(action, Call(_, EVENT_START_AUTH));
    EXPECT_CALL(leave, Call(_, STATE_INIT));
    EXPECT_CALL(enter, Call(_, STATE_VERIFY_STARING));

    EXPECT_CALL(action, Call(_, EVENT_VERIFY_STARTED));
    EXPECT_CALL(leave, Call(_, STATE_VERIFY_STARING));
    EXPECT_CALL(enter, Call(_, STATE_COLLECT_STARING));

    EXPECT_CALL(action, Call(_, EVENT_COLLECT_STARTED));
    EXPECT_CALL(leave, Call(_, STATE_COLLECT_STARING));
    EXPECT_CALL(enter, Call(_, STATE_AUTH_PROCESSING));

    EXPECT_CALL(action, Call(_, EVENT_USER_CANCEL));
    EXPECT_CALL(leave, Call(_, STATE_AUTH_PROCESSING));
    EXPECT_CALL(enter, Call(_, STATE_END));

    auto machineBuilder = FiniteStateMachine::Builder::New("testMachine13", STATE_INIT);
    ASSERT_NE(machineBuilder, nullptr);

    machineBuilder
        ->MakeTransition(STATE_INIT, EVENT_START_AUTH, STATE_VERIFY_STARING,
            [&action](FiniteStateMachine &machine, uint32_t event) {
                action.Call(machine, event);
                machine.Schedule(EVENT_VERIFY_STARTED);
                machine.Schedule(EVENT_COLLECT_STARTED);
            })
        ->MakeTransition(STATE_VERIFY_STARING, EVENT_VERIFY_STARTED, STATE_COLLECT_STARING,
            [&action](FiniteStateMachine &machine, uint32_t event) { action.Call(machine, event); })
        ->MakeTransition(STATE_COLLECT_STARING, EVENT_COLLECT_STARTED, STATE_AUTH_PROCESSING,
            [&action](FiniteStateMachine &machine, uint32_t event) { action.Call(machine, event); })
        ->MakeTransition(STATE_AUTH_PROCESSING, EVENT_USER_CANCEL, STATE_END,
            [&action](FiniteStateMachine &machine, uint32_t event) { action.Call(machine, event); });

    machineBuilder->MakeOnStateEnter(STATE_INIT,
        [&enter](FiniteStateMachine &machine, uint32_t event) { enter.Call(machine, event); });
    machineBuilder->MakeOnStateLeave(STATE_INIT,
        [&leave](FiniteStateMachine &machine, uint32_t event) { leave.Call(machine, event); });

    machineBuilder->MakeOnStateEnter(STATE_VERIFY_STARING,
        [&enter](FiniteStateMachine &machine, uint32_t event) { enter.Call(machine, event); });
    machineBuilder->MakeOnStateLeave(STATE_VERIFY_STARING,
        [&leave](FiniteStateMachine &machine, uint32_t event) { leave.Call(machine, event); });

    machineBuilder->MakeOnStateEnter(STATE_COLLECT_STARING,
        [&enter](FiniteStateMachine &machine, uint32_t event) { enter.Call(machine, event); });
    machineBuilder->MakeOnStateLeave(STATE_COLLECT_STARING,
        [&leave](FiniteStateMachine &machine, uint32_t event) { leave.Call(machine, event); });

    machineBuilder->MakeOnStateEnter(STATE_AUTH_PROCESSING,
        [&enter](FiniteStateMachine &machine, uint32_t event) { enter.Call(machine, event); });
    machineBuilder->MakeOnStateLeave(STATE_AUTH_PROCESSING,
        [&leave](FiniteStateMachine &machine, uint32_t event) { leave.Call(machine, event); });

    machineBuilder->MakeOnStateEnter(STATE_END,
        [&enter](FiniteStateMachine &machine, uint32_t event) { enter.Call(machine, event); });

    auto machine = machineBuilder->Build();
    ASSERT_NE(machine, nullptr);

    machine->SetThreadHandler(handler);
    handler->EnsureTask(nullptr);
    machine->Schedule(EVENT_START_AUTH);
    handler->EnsureTask(nullptr);
    machine->Schedule(EVENT_USER_CANCEL);
    EXPECT_EQ(STATE_END, machine->EnsureCurrentState());

    handler->EnsureTask(nullptr);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS