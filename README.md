# jwt-auth

>在yii2框架下使用的jwt-auth。

## 配置文件
``` php
    'components' => [
        'jwtManager' => [
            'class' => 'JwtAuth\Manager',
            'userClass' => 'app\models\User',
            'whitelistEnable' => true,
            'blacklistEnable' => false,
            'salt' => 'L3AeVgpV70I9HouNFd06bYjmdG7bFE4F',
            'ttl' => 20,
            'refreshTtl' => 40,
            'cache' => [
                'class' => 'yii\redis\Cache',
                'redis' => [
                    'hostname' => 'localhost',
                    'port' => 6379,
                    'database' => 0,
                ]
            ]
        ]
    ]
```
1. 如果没有配置cache，默认使用 `Yii::$app->cache`。或cache配置为`'cache'=>'redisCache'`则使用`Yii::$app->redisCache`。
2. `userClass`指定的类需要实现`JwtAuth\UserAuthInterface`接口。
3. `ttl`为token有效时长，`refreshTtl`为token刷新有效时长，若想禁用token刷新机制，可设置`refreshTtl`大于`ttl`。单位：秒。
4. `salt`为token的加密秘钥。

## 生成token
``` php
    public function actionLogin()
    {
        $token = Yii::$app->jwtManager->createToken();

        return $token;
    }
```
## 验证token
``` php
    public function behaviors()
    {
        return [
            'jwtFilter' => [
                'class' => \JwtAuth\Filters\AuthFilter::class,
                'except' => ['login']
            ],
        ];
    }
```
## 注销token
``` php
    public function actionLogout()
    {
        Yii::$app->jwtManager->invalidateToken();
        
        return 'successfully!';
    }
```

## 获取token认证后的用户实例
``` php
    public function actionUser()
    {
        $user = $identify=Yii::$app->jwtManager->user();
        
        return $user->name;
    }
```

## User示例
``` php
<?php

namespace app\models;

use JwtAuth\Models\AbstractIdentityModel;

class User extends AbstractIdentityModel
{
    public $id;
    public $name;
    public $password;
    public $email;

    public static function getUserById($id)
    {
        $user = new User();
        $user->id = 1;
        $user->name = 'yyliziqiu';
        $user->password = '123456';
        $user->email = 'yyliziqiu@163.com';

        return $user;
    }

    public static function getUserByRequest($request)
    {
        $user = new User();
        $user->id = 1;
        $user->name = 'yyliziqiu';
        $user->password = '123456';
        $user->email = 'yyliziqiu@163.com';

        return $user;
    }

    public function getId()
    {
        return $this->id;
    }

    public function genCustomClaims()
    {
        return ['name' => 'yyliziqiu', 'aud' => 'phone'];
    }

    public function genContent()
    {
        return ['address' => 'Hebei'];
    }
}
```
