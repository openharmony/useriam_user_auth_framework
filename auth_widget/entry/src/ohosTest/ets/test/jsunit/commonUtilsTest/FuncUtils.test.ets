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

import userAuth from '@ohos.userIAM.userAuth';
import { beforeAll, describe, expect, it } from '@ohos/hypium';
import AuthUtils from '../../../../../main/ets/common/utils/AuthUtils';
import FuncUtils from '../../../../../main/ets/common/utils/FuncUtils';
import LogUtils from '../../../../../main/ets/common/utils/LogUtils';

const TAG = 'FuncUtilsTest';

export default function FuncUtilsTest() {
  describe('funcUtilsTest', function () {
    beforeAll(async function () {
      let userAuthInstance = null;
      const authParam = {
        challenge: new Uint8Array([49, 49, 49, 49, 49, 49]),
        authType: [1],
        authTrustLevel: 10000,
      };
      const widgetParam = {
        title: '',
        windowMode: 1,
        navigationButtonText: '',
      };
      userAuthInstance = await userAuth.getUserAuthInstance(authParam, widgetParam);
      userAuthInstance.on('result', {
        callback: function (result) {
          LogUtils.i(TAG, 'callback result = ' + JSON.stringify(result));
        }
      });
      userAuthInstance.start();
    })

    it('getUint8PWFunc_test', 0, function (done) {
      const data1 = FuncUtils.getUint8PW('111111');
      const data2 = FuncUtils.getUint8PW('11111111');
      expect(data1).assertInstanceOf('Uint8Array');
      expect(data2).assertInstanceOf('Uint8Array');
      done();
    })

    it('getDialogTypeFunc_test', 0, function (done) {
      const data1 = FuncUtils.getDialogType([1]);
      const data2 = FuncUtils.getDialogType([1, 2, 3]);
      const data3 = FuncUtils.getDialogType([]);
      const data4 = FuncUtils.getDialogType(null);
      const data5 = FuncUtils.getDialogType(undefined);
      expect(data1).assertEqual(1);
      expect(data2).assertEqual(6);
      expect(data3).assertEqual(1);
      expect(data4).assertEqual(1);
      expect(data5).assertEqual(1);
      done();
    })

    it('sendNotice_test', 0, async function (done) {
      AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', ['pin']);
      done();
    })
  })
}