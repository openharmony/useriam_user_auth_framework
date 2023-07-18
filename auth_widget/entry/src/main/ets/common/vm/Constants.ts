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

export default class Constants {
  static deviceDpi = ['360vp', '780vp'];

  // Pin type
  static pinSix = 'PIN_SIX';
  static pinNumber = 'PIN_NUMBER';
  static pinMixed = 'PIN_MIXED';

  // layout params - Pic
  static fullContainerWidth = '100%';
  static fullContainerHeight = '100%';
  static halfContainerWidth = '50%';
  static ninetyPercentWidth = '90%';

  // getUserAuthWidgetMgr params
  static userAuthWidgetMgrVersion = 1;
  // command result success
  static userAuthWidgetMgrSuccess = 0;

  // sendNotice param: version
  static noticeVersion = '1';
  // type
  static noticeTypePin = 'pin';
  static noticeTypeFace = 'face';
  static noticeTypeFinger = 'fingerprint';

  static fingerSensorPositionLine = 0.75;

  static hintTimesByFailLess = 3;
  static maxFailTimes = 5;

  static numKeyBoard = [
    {
      index: 0,
      row1: '1',
      row2: ' ',
      value: 1,
      bkg: false
    },
    {
      index: 1,
      row1: '2',
      row2: 'ABC',
      value: 2,
      bkg: false
    },
    {
      index: 2,
      row1: '3',
      row2: 'DEF',
      value: 3,
      bkg: false
    },
    {
      index: 3,
      row1: '4',
      row2: 'GHI',
      value: 4,
      bkg: false
    },
    {
      index: 4,
      row1: '5',
      row2: 'JKL',
      value: 5,
      bkg: false
    },
    {
      index: 5,
      row1: '6',
      row2: 'MNO',
      value: 6,
      bkg: false
    },
    {
      index: 6,
      row1: '7',
      row2: 'PQRS',
      value: 7,
      bkg: false
    },
    {
      index: 7,
      row1: '8',
      row2: 'TUV',
      value: 8,
      bkg: false
    },
    {
      index: 8,
      row1: '9',
      row2: 'WXYZ',
      value: 9,
      bkg: false
    },
    {
      index: 9,
      row1: $r('app.string.unified_authwidget_notarize'),
      row2: '',
      value: -1,
      bkg: false
    },
    {
      index: 10,
      row1: '0',
      row2: '+',
      value: 0,
      bkg: false
    },
    {
      index: 11,
      row1: $r('app.string.unified_authwidget_back'),
      row2: '',
      value: -3,
      bkg: false
    }];
}

export interface FingerPosition {
  sensorType: string,
  udSensorCenterXInThousandth?: number,
  udSensorCenterYInThousandth?: number,
  udSensorRadiusInPx?: number,
  outOfScreenSensorType?: string
}

export interface CmdData {
  type: string,
  remainAttempts: number,
  lockoutDuration: number,
  sensorInfo?: string
}

export interface CmdType {
  event: string,
  payload: CmdData,
}