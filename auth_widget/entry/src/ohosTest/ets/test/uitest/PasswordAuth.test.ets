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
import UIAbility from '@ohos.app.ability.UIAbility';
import { Driver, ON } from '@ohos.UiTest';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from '@ohos/hypium';

const delegator = abilityDelegatorRegistry.getAbilityDelegator();
const bundleName = abilityDelegatorRegistry.getArguments().bundleName;
const delayms: number = 1000;
let ab: UIAbility;

export default function PasswordAuthTest() {
  describe('PasswordAuthTest', function () {
    beforeAll(async function () {
      await  delegator.addAbilityMonitor({
        abilityName: 'EntryAbility',
        moduleName: bundleName,
        onAbilityCreate(ability: UIAbility) {
          ab = ability;
        }
      });
      let want = {
        bundleName: bundleName,
        abilityName: "EntryAbility"
      }
      await delegator.startAbility(want);
    })
    beforeEach(function () {
      // Presets an action, which is performed before each unit test case starts.
      // The number of execution times is the same as the number of test cases defined by **it**.
      // This API supports only one parameter: preset action function.
    })
    afterEach(function () {
      // Presets a clear action, which is performed after each unit test case ends.
      // The number of execution times is the same as the number of test cases defined by **it**.
      // This API supports only one parameter: clear action function.
    })
    afterAll(function () {
      // Presets a clear action, which is performed after all test cases of the test suite end.
      // This API supports only one parameter: clear action function.
    })

    it('clickEventOk_Input', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayms);

      let pinInput = await driver.findComponent(ON.id('pinInput'));
      await pinInput.inputText('111111');
      await driver.delayMs(delayms);
      let input_new = await driver.findComponent(ON.id('pinInput'));
      let text = await input_new.getText();
      expect(text === '111111').assertTrue();

      done();
    })

    it('clickEventCancel_Input', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayms);
      await driver.delayMs(delayms);
      let cancel_btn = await driver.findComponent(ON.id('pinInput'))
      await cancel_btn.inputText('1221212')
      await driver.delayMs(delayms);
      let ok_btn = await driver.findComponent(ON.id('okBtn'))
      await ok_btn.click()
      await driver.delayMs(delayms);
      await cancel_btn.inputText('111111')
      await ok_btn.click()
      await driver.delayMs(delayms);
      done()
    })

    it('clickEventError_Input', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayms);
      await driver.delayMs(delayms);

      let Input = await driver.findComponent(ON.id('pinInput'));

      await Input.inputText('2345643');
      await driver.delayMs(delayms);
      let ok_btn = await driver.findComponent(ON.id('okBtn'));
      await ok_btn.click();
      await driver.delayMs(delayms);

      await Input.inputText('2345643');
      await driver.delayMs(delayms);
      await ok_btn.click();
      await driver.delayMs(delayms);

      await driver.delayMs(delayms);

      await Input.inputText('2345643');
      await driver.delayMs(delayms);
      await ok_btn.click()
      await driver.delayMs(delayms);

      await Input.inputText('2345643');
      await driver.delayMs(delayms);
      await ok_btn.click()
      await driver.delayMs(delayms);

      await Input.inputText('2345643');
      await driver.delayMs(delayms);
      await ok_btn.click();
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