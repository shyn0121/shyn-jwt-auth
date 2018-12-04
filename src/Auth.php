<?php

namespace JwtAuth;

use Yii;
use yii\base\BaseObject;
use yii\web\UnauthorizedHttpException;
use JwtAuth\Exceptions\TokenInvalidException;

class Auth extends BaseObject
{
    /**
     * @var string token token字符串
     */
    private $_token;

    /**
     * @var IdentityInterface 认证用户实例
     */
    private $_identify;

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
     * @param array $config
     */
    public function __construct($config = [])
    {
        parent::__construct($config);

        $this->request = Yii::$app->request;
        $this->response = Yii::$app->response;
        $this->manager = Yii::$app->jwtManager;
    }

    /**
     * 登录认证
     *
     * @return IdentityInterface
     * @throws UnauthorizedHttpException
     */
    public function login()
    {
        $identify_class = $this->manager->identifyClass;
        $identify = $identify_class::findIdentityFromRequest($this->request);
        if (!isset($identify) || $identify === false || !($identify instanceof IdentityInterface)) {
            throw new UnauthorizedHttpException('Identify user failed!');
        }

        $this->registerIdentify($identify);
        return $this->_identify;
    }

    /**
     * 通过用户唯一标志获取用户
     *
     * @param string|int $id
     * @return IdentityInterface
     * @throws UnauthorizedHttpException
     */
    public function getIdentityById($id)
    {
        $identify_class = $this->manager->identifyClass;
        $identify = $identify_class::findIdentityById($id);
        if (!isset($identify) || $identify === false || !($identify instanceof IdentityInterface)) {
            throw new UnauthorizedHttpException('Identify user failed!');
        }

        $this->registerIdentify($identify);
        return $this->_identify;
    }

    /**
     * 通过用户唯一标志获取用户并配置用户信息
     *
     * @param string|int $id
     * @param array $custom_claims
     * @param array $content
     * @return IdentityInterface
     * @throws UnauthorizedHttpException
     */
    public function configureIdentityById($id, $custom_claims, $content)
    {
        $identify = $this->getIdentityById($id);
        $identify->customClaims = $custom_claims;
        $identify->content = $content;
        return $identify;
    }

    /**
     * 从请求中获取token
     *
     * @return string
     * @throws TokenInvalidException
     */
    private function fetchTokenFromRequest()
    {
        $token = $this->request->getQueryParam('token');
        if (isset($token)) {
            return $this->_token = $token;
        }

        $headers = $this->request->getHeaders();
        if (isset($headers['Authorization'])) {
            if (strpos($headers['Authorization'], 'Bearer') !== false) {
                $token = explode(' ', $headers['Authorization']);
                if (count($token) == 2) {
                    return $this->_token = $token[1];
                }
            }
        }

        $token = $this->request->getBodyParam('token');
        if (isset($token)) {
            return $this->_token = $token;
        }

        $raw = $this->request->getRawBody();
        if ($data = json_decode($raw, true)) {
            if (isset($data['token'])) {
                return $this->_token = $data['token'];
            }
        }

        throw new TokenInvalidException('Token can not be fetched from request!');
    }

    /**
     * 注册identify到auth
     *
     * @param $identify
     */
    private function registerIdentify($identify)
    {
        $this->_identify = $identify;
    }

    /**
     * 把token添加到http响应头部
     */
    public function addTokenToResponse()
    {
        $this->response->getHeaders()
            ->set('Authorization', 'Bearer ' . $this->token);
    }

    /**
     * 把token从http响应头部删除
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
    public function getToken()
    {
        if (!isset($this->_token)) {
            $this->fetchTokenFromRequest();
        }
        return $this->_token;
    }

    /**
     * @param string $token
     */
    public function setToken($token)
    {
        $this->_token = $token;
    }

    /**
     * @return IdentityInterface
     * @throws UnauthorizedHttpException
     */
    public function getIdentify()
    {
        if (!isset($this->_identify)) {
            $this->login();
        }
        return $this->_identify;
    }
}
