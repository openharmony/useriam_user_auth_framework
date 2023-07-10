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

export default function IndexTest() {
  describe('IndexTest', function () {
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
    it('clickEventCancal_Input', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayms);
      await driver.delayMs(delayms);
      let cancel_btn = await driver.findComponent(ON.id('pinSix'));
      await cancel_btn.inputText('11111');
      await driver.delayMs(delayms);
    })
    it('clickEventUsePassWord_Input', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayms);
      let cancel_btn = await driver.findComponent(ON.type('Button').isAfter(ON.text('使用密码')));
      cancel_btn.click();
      done();
    })

    it('clickEventOk_Input', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayms);
      await driver.delayMs(delayms);
      let cancel_btn = await driver.findComponent(ON.id('pinSix'));
      await cancel_btn.inputText('111111');
      await driver.delayMs(delayms);
      let ok_btn = await driver.findComponent(ON.id('cancelBtn_dialog_pwd'));
      await ok_btn.click();
      done();
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
      await ok_btn.click();
      await driver.delayMs(delayms);

      await Input.inputText('2345643');
      await driver.delayMs(delayms);
      await ok_btn.click();
      await driver.delayMs(delayms);

      await Input.inputText('2345643');
      await driver.delayMs(delayms);
      await ok_btn.click();
      await driver.delayMs(delayms);

      done();
    })
    it('assertEqual', 0, function () {
      let a = 'test';
      expect(a).assertEqual('test');
    })
  })
}