# Embedded User Authentication Control


## Introduction

Provide face and fingerprint authentication icon displayed on the application interface, with specific functions as follows:
1. Provide embedded face and fingerprint authentication control icon that can be integrated into applications.
2. Support customizing the color and size of icon, but the icon style cannot be changed.
3. After clicking on the control icon, the system pop-up style face and fingerprint authentication control can be pulled up.


## Directory Structure

```undefined
//base/useriam/user_auth_framework/user_auth_icon
├── library                              # library module directory
│   ├── src/main/ets/components/mainpage # the entry point for implementing embedded controls
```


### Available APIs

**Table 1** APIs for embedded user authentication

**table1** Icon click event callback interface

| interface  | description                             |
| ------ | -------------------------------- |
| onIconClick?: () => void; | Notify the application that a click event has been triggered. |

**table2** Identity authentication result notification callback interface

| interface  | description                             |
| ------ | -------------------------------- |
| onAuthResult: (result: userAuth.UserAuthResult) => void; | Notify the application of user authentication result information. |



## Demo

```undefined
import userAuth from '@ohos.userIAM.userAuth';
import UserAuthIcon from '@ohos.userIAM.userAuthIcon';

@Entry
@Component
struct Index {
  authParam: userAuth.AuthParam = {
    challenge: new Uint8Array([49, 49, 49, 49, 49, 49]),
    authType: [userAuth.UserAuthType.FACE, userAuth.UserAuthType.PIN],
    authTrustLevel: userAuth.AuthTrustLevel.ATL3,
  };
  widgetParam: userAuth.WidgetParam = {
    title: '请进行身份认证',
  };

  build() {
    Row() {
      Column() {
        UserAuthIcon({
          authParam: this.authParam,
          widgetParam: this.widgetParam,
          iconHeight: 200,
          iconColor: Color.Blue,
          onIconClick: () => {
            console.info("The user clicked the icon.");
          },
          onAuthResult: (result: userAuth.UserAuthResult) => {
            console.info('Get user auth result, result = ' + JSON.stringify(result));
          },
        })
      }
    }
  }
}
```
