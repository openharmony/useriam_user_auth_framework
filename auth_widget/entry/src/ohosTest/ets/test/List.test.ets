/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import IndexTest from './Index.test';
import funcUtilsTest from './jsunit/commonUtilsTest/FuncUtils.test';
import constantsTest from './jsunit/constantsTest/Constants.test';
import customPasswordTest from './jsunit/widgetTest/CustomPassword.test';
import CustomPasswordFaceTest from './jsunit/widgetTest/CustomPasswordFace.test';
import CustomPasswordFingerTest from './jsunit/widgetTest/CustomPasswordFinger.test';
import FaceAuth from './jsunit/widgetTest/FaceAuth.test';
import FingerprintAuth from './jsunit/widgetTest/FingerprintAuth.test';
import pageComTest from './jsunit/widgetTest/PageCom.test';
import passwordAuthTest from './jsunit/widgetTest/PasswordAuth.test';
import PasswordAuthTestSix from './jsunit/widgetTest/PasswordAuthSix.test';
import CustomPasswordTest from './uitest/CustomPassword.test';
import FaceAuthTest from './uitest/FaceAuth.test';
import FingerprintAuthTest from './uitest/FingerprintAuth.test';
import PasswordAuthTest from './uitest/PasswordAuth.test';

export default function testsuite() {
  IndexTest();
  CustomPasswordTest();
  PasswordAuthTest();
  FaceAuthTest();
  FingerprintAuthTest();
  funcUtilsTest();
  pageComTest();
  constantsTest();
  passwordAuthTest();
  PasswordAuthTestSix();
  FaceAuth();
  FingerprintAuth();
  customPasswordTest();
  CustomPasswordFaceTest();
  CustomPasswordFingerTest();
}