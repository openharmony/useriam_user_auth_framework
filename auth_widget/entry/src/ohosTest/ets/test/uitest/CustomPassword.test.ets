/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")
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

import abilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
import { Driver, ON } from '@ohos.UiTest';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from '@ohos/hypium';

const delegator = abilityDelegatorRegistry.getAbilityDelegator();
const bundleName = abilityDelegatorRegistry.getArguments().bundleName;
const delayms: number = 1000;

export default function CustomPasswordTest() {
  describe('CustomPasswordTest', function () {
    beforeAll(async function () {
      let want = {
        bundleName: bundleName,
        abilityName: "EntryAbility"
      }
      await delegator.startAbility(want);
    })
    beforeEach(function () {
    })
    afterEach(function () {
    })
    afterAll(function () {
    })
    // full six-PIN
    it('clickEventCancal_Input', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayms);
      await driver.delayMs(delayms);
      let numberOne = await driver.findComponent(ON.type('Text').isAfter(ON.text('1')));
      await numberOne.click();
      await driver.delayMs(delayms);
      await numberOne.click();
      await driver.delayMs(delayms);
      await numberOne.click();
      await driver.delayMs(delayms);
      await numberOne.click();
      await driver.delayMs(delayms);
      await numberOne.click();
      await driver.delayMs(delayms);
      await numberOne.click();
      await driver.delayMs(delayms);
      done();
    })
    it('assertEqual', 0, function () {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      let a = 'test';
      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      expect(a).assertEqual('test');
    })
  })
}