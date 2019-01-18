<?php

namespace JwtAuth;

use Yii;
use JwtAuth\Exceptions\TokenInvalidException;
use JwtAuth\Exceptions\UserNotFoundException;
use JwtAuth\Exceptions\UserUnauthorizedException;

class Auth
{
    /**
     * @var string
     */
    public $token;

    /**
     * @var UserAuthInterface
     */
    public $user;

    /**
     * @var Manager
     */
    private $manager;

    /**
     * @var \yii\web\Request
     */
    private $request;

    /**
     * @var \yii\web\Response
     */
    private $response;

    /**
     * Auth constructor.
     */
    public function __construct()
    {
        $this->manager = Yii::$app->jwtManager;
        $this->request = Yii::$app->request;
        $this->response = Yii::$app->response;
    }

    /**
     * 用户登录认证
     *
     * @return UserAuthInterface
     * @throws UserUnauthorizedException
     */
    public function login()
    {
        $userClass = $this->manager->userClass;
        $user = $userClass::getUserByRequest($this->request);
        if (!isset($user) || $user === false || !($user instanceof UserAuthInterface)) {
            throw new UserUnauthorizedException('User name or password error!');
        }
        return $this->registerUser($user);
    }

    /**
     * 通过用户唯一标识创建用户实例
     *
     * @param int|string $id
     * @return UserAuthInterface
     * @throws UserNotFoundException
     */
    public function getUserById($id)
    {
        $userClass = $this->manager->userClass;
        $user = $userClass::getUserById($id);
        if (!isset($user) || $user === false || !($user instanceof UserAuthInterface)) {
            throw new UserNotFoundException('User not be found!');
        }
        return $this->registerUser($user);
    }

    /**
     * 通过用户唯一标识创建用户实例并附加自定义载荷和白名单
     *
     * @param int|string $id
     * @param array $customClaims
     * @param array $content
     * @return UserAuthInterface
     * @throws UserNotFoundException
     */
    public function configureUserById($id, $customClaims, $content)
    {
        $user = $this->getUserById($id);
        $user->fillCustomClaims($customClaims);
        $user->fillContent($content);

        return $user;
    }

    /**
     * 注册用户实例到应用
     *
     * @param UserAuthInterface $user
     * @return UserAuthInterface
     */
    private function registerUser($user)
    {
        return $this->user = $user;
    }

    /**
     * 从客户端请求中获取token
     *
     * @return string
     * @throws TokenInvalidException
     */
    public function fetchTokenFromRequest()
    {
        $token = $this->request->getQueryParam('token');
        if (isset($token)) {
            return $token;
        }

        $headers = $this->request->getHeaders();
        if (isset($headers['Authorization'])) {
            $position = strpos($headers['Authorization'], 'Bearer ');
            if ($position !== false) {
                return substr($headers['Authorization'], $position + 7);
            }
        }

        $token = $this->request->getBodyParam('token');
        if (isset($token)) {
            return $token;
        }

        $raw = $this->request->getRawBody();
        if ($data = json_decode($raw, true)) {
            if (isset($data['token'])) {
                return $data['token'];
            }
        }

        throw new TokenInvalidException('Token can not be found!');
    }

    /**
     * 添加token到http响应头
     */
    public function addTokenToResponse()
    {
        $this->response->getHeaders()
            ->set('Authorization', 'Bearer ' . $this->token());
    }

    /**
     * 从http响应头删除token
     */
    public function removeTokenFromResponse()
    {
        $this->response->getHeaders()
            ->remove('Authorization');
    }

    /**
     * @return string
     * @throws TokenInvalidException
     */
    public function token()
    {
        if (!isset($this->token)) {
            $this->token = $this->fetchTokenFromRequest();
        }
        return $this->token;
    }

    /**
     * @return UserAuthInterface
     * @throws UserUnauthorizedException
     */
    public function user()
    {
        if (!isset($this->user)) {
            $this->login();
        }
        return $this->user;
    }
}
