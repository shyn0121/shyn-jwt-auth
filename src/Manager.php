<?php

namespace JwtAuth;

use Yii;
use yii\base\Component;
use yii\base\UnknownMethodException;
use yii\base\UnknownPropertyException;
use JwtAuth\Exceptions\TokenExpiredException;
use JwtAuth\Exceptions\TokenInvalidException;

class Manager extends Component
{
    /**
     * @var bool 开启黑名单机制
     */
    private $black_list_enable = false;

    /**
     * @var bool 开启白名单机制
     */
    private $white_list_enable = false;

    /**
     * @var string 用户认证类路径
     */
    private $identify_class;

    /**
     * @var string 加密算法
     */
    private $alg = 'sha256';

    /**
     * @var string 加密秘钥
     */
    private $salt;

    /**
     * @var int token过期时间 单位：秒
     */
    private $ttl = 86400;

    /**
     * @var int token刷新过期时间 单位：秒
     */
    private $refresh_ttl = 2592000;

    /**
     * @var int token开始使用时间 单位：秒
     */
    private $wait_ttl = 0;

    /**
     * @var \yii\caching\Cache
     */
    private $cache;

    /**
     * @var Auth
     */
    private $_auth = null;

    /**
     * Manager constructor.
     * @param array $config
     * @throws \yii\base\InvalidConfigException
     */
    public function __construct(array $config = [])
    {
        parent::__construct($config);

        $this->configureCache();
    }

    /**
     * @param string $name
     * @return mixed
     */
    public function __get($name)
    {
        try {
            return parent::__get($name);
        } catch (UnknownPropertyException $ex) {
            return $this->auth->$name;
        }
    }

    /**
     * @param string $name
     * @param mixed $value
     */
    public function __set($name, $value)
    {
        try {
            parent::__set($name, $value);
        } catch (UnknownPropertyException $ex) {
            $this->auth->$name = $value;
        }
    }

    /**
     * @param string $name
     * @param array $params
     * @return mixed
     */
    public function __call($name, $params)
    {
        try {
            return parent::__call($name, $params);
        } catch (UnknownMethodException $ex) {
            return call_user_func_array([$this->auth, $name], $params);
        }
    }

    /**
     * 生成token
     *
     * @return string
     */
    public function createToken()
    {
        $identify = $this->login();

        $jwt = $this->genJwtByIdentify($identify);

        $this->registerToken($jwt->token);
        $this->addTokenToWhiteList($jwt, $identify->content);
        $this->addTokenToResponse();

        return $this->token;
    }

    /**
     * 验证token，并返回认证的用户
     *
     * @param null|string $token
     * @param bool $auto_refresh
     * @return IdentityInterface
     * @throws TokenExpiredException
     * @throws TokenInvalidException
     */
    public function parseToken($token = null, $auto_refresh = false)
    {
        if (isset($token) && is_string($token)) {
            $this->registerToken($token);
        }

        $jwt = $this->genJwt();
        try {
            $jwt->parseToken($this->token, $this->refresh_ttl);
        } catch (TokenExpiredException $exception) {
            if ($auto_refresh) {
                $this->refreshToken($jwt);
                return $this->identify;
            }
            throw $exception;
        }

        $content = $this->verifyTokenInList($jwt);
        $identify = $this->configureIdentityById($jwt->sub, $jwt->customClaims, $content);

        return $identify;
    }

    /**
     * 刷新token
     *
     * @param null|string|Jwt $token
     * @return string
     * @throws TokenInvalidException
     */
    public function refreshToken($token = null)
    {
        if (isset($token) && is_string($token)) {
            $this->registerToken($token);
        }
        if (isset($token) && $token instanceof Jwt) {
            $jwt = $token;
        } else {
            $jwt = $this->genJwt();
            $jwt->parseRefreshToken($this->token, $this->refresh_ttl);
        }

        $content = $this->verifyTokenInList($jwt);
        $this->changeListOnRemoveToken($jwt);

        $this->refreshJwt($jwt);
        $this->registerToken($jwt->token);

        $this->addTokenToWhiteList($jwt, $content);
        $this->configureIdentityById($jwt->sub, $jwt->customClaims, $content);
        $this->addTokenToResponse();

        return $this->token;
    }

    /**
     * 注销token
     *
     * @param null|string $token
     */
    public function invalidateToken($token = null)
    {
        if (isset($token) && is_string($token)) {
            $this->registerToken($token);
        }

        $jwt = $this->genJwt();
        try {
            $jwt->parseToken($this->token, $this->refresh_ttl);
        } catch (\Exception $exception) {
            if (!($exception instanceof TokenExpiredException)) {
                return;
            }
        }
        $this->changeListOnRemoveToken($jwt);
        $this->removeTokenFromResponse();
    }

    /**
     * 注册token到manager
     *
     * @param string $token
     */
    private function registerToken($token)
    {
        $this->token = $token;
    }

    /**
     * 添加token到黑名单
     *
     * @param Jwt $jwt
     */
    private function addTokenToBlackList($jwt)
    {
        if ($this->black_list_enable) {
            BlackList::set($jwt->jti, [], $this->genExpiredTime($jwt));
        }
    }

    /**
     * 添加token到白名单
     *
     * @param Jwt $jwt
     * @param array $content
     */
    private function addTokenToWhiteList($jwt, $content)
    {
        if ($this->white_list_enable) {
            WhiteList::set($jwt->jti, isset($content) ? $content : [], $this->genExpiredTime($jwt));
        }
    }

    /**
     * 从白名单中移除token
     *
     * @param Jwt $jwt
     */
    private function removeTokenFromWhiteList($jwt)
    {
        if ($this->white_list_enable) {
            WhiteList::delete($jwt->jti);
        }
    }

    /**
     * 删除token时，把该token添加到黑名单，并从白名单中移除
     *
     * @param Jwt $jwt
     */
    private function changeListOnRemoveToken($jwt)
    {
        $this->addTokenToBlackList($jwt);
        $this->removeTokenFromWhiteList($jwt);
    }

    /**
     * 检测token是否通过黑白名单验证
     *
     * @param Jwt $jwt
     * @return mixed
     * @throws TokenInvalidException
     */
    private function verifyTokenInList($jwt)
    {
        if ($this->black_list_enable) {
            $value = BlackList::get($jwt->jti);
            if ($value !== false) {
                throw new TokenInvalidException('Token is unavailable in blacklist!');
            }
        }

        if ($this->white_list_enable) {
            $value = WhiteList::get($jwt->jti);
            if ($value === false) {
                throw new TokenInvalidException('Token is unavailable in whitelist!');
            }
            return $value;
        }
        return [];
    }

    /**
     * @return Auth
     */
    public function getAuth()
    {
        if (!isset($this->_auth)) {
            $this->_auth = new Auth();
        }
        return $this->_auth;
    }

    /**
     * @param int|string $sub
     * @return array
     */
    private function genClaims($sub)
    {
        return [
            'iss' => PayLoad::genIss(),
            'aud' => PayLoad::genAud(),
            'exp' => PayLoad::genExp($this->ttl),
            'nbf' => PayLoad::genNbf($this->wait_ttl),
            'iat' => PayLoad::genIat(),
            'jti' => PayLoad::genJti(),
            'sub' => (string)$sub
        ];
    }

    /**
     * @return array
     */
    private function genHeadSegments()
    {
        return ['type' => 'jwt', 'alg' => $this->alg];
    }

    /**
     * @param Head $head
     * @param PayLoad $payload
     * @return array
     */
    private function genJwtSegments($head, $payload)
    {
        return ['head' => $head, 'payload' => $payload];
    }

    /**
     * @param IdentityInterface $identify
     * @return Jwt
     */
    private function genJwtByIdentify($identify)
    {
        $head = $this->genHead();
        $head->attributes = $this->genHeadSegments();

        $payload = $this->genPayLoad($identify->customClaims);
        $payload->attributes = $this->genClaims($identify->getId());

        $jwt = $this->genJwt();
        $jwt->attributes = $this->genJwtSegments($head, $payload);

        return $jwt;
    }

    /**
     * @return Head
     */
    private function genHead()
    {
        return new Head();
    }

    /**
     * @param array $custom_claims
     * @return PayLoad
     */
    private function genPayLoad($custom_claims)
    {
        return new PayLoad($custom_claims);
    }

    /**
     * @return Jwt
     */
    private function genJwt()
    {
        return new Jwt($this->salt);
    }

    /**
     * @param Jwt $jwt
     * @return int
     */
    private function genExpiredTime($jwt)
    {
        return Timer::secondsTo($jwt->iat) + $this->refresh_ttl;
    }

    /**
     * @param Jwt $jwt
     * @return string
     * @throws Exception\InvalidSegmentException
     */
    private function refreshJwt($jwt)
    {
        $jwt->exp = PayLoad::genExp($this->ttl);
        $jwt->nbf = PayLoad::genNbf($this->wait_ttl);
        $jwt->iat = PayLoad::genIat();
        $jwt->jti = PayLoad::genJti();

        return $jwt->refresh();
    }

    /**
     * 配置缓存驱动
     *
     * @throws \yii\base\InvalidConfigException
     */
    private function configureCache()
    {
        if (!isset($this->cache)) {
            $this->cache = Yii::$app->cache;
        } else if (is_string($this->cache)) {
            $this->cache = Yii::$app->{$this->cache};
        } else {
            $this->cache = Yii::createObject($this->cache);
        }
    }

    /**
     * @return bool
     */
    public function getBlackListEnable()
    {
        return $this->black_list_enable;
    }

    /**
     * @param bool $black_list_enable
     */
    public function setBlackListEnable($black_list_enable)
    {
        $this->black_list_enable = $black_list_enable;
    }

    /**
     * @return bool
     */
    public function getWhiteListEnable()
    {
        return $this->white_list_enable;
    }

    /**
     * @param bool $white_list_enable
     */
    public function setWhiteListEnable($white_list_enable)
    {
        $this->white_list_enable = $white_list_enable;
    }

    /**
     * @return string
     */
    public function getIdentifyClass()
    {
        return $this->identify_class;
    }

    /**
     * @param string $identify_class
     */
    public function setIdentifyClass($identify_class)
    {
        $this->identify_class = $identify_class;
    }

    /**
     * @return string
     */
    public function getAlg()
    {
        return $this->alg;
    }

    /**
     * @param string $alg
     */
    public function setAlg($alg)
    {
        $this->alg = $alg;
    }

    /**
     * @return string
     */
    public function getSalt()
    {
        return $this->salt;
    }

    /**
     * @param string $salt
     */
    public function setSalt($salt)
    {
        $this->salt = $salt;
    }

    /**
     * @return int
     */
    public function getTtl()
    {
        return $this->ttl;
    }

    /**
     * @param int $ttl
     */
    public function setTtl($ttl)
    {
        $this->ttl = $ttl;
    }

    /**
     * @return int
     */
    public function getRefreshTtl()
    {
        return $this->refresh_ttl;
    }

    /**
     * @param int $refresh_ttl
     */
    public function setRefreshTtl($refresh_ttl)
    {
        $this->refresh_ttl = $refresh_ttl;
    }

    /**
     * @return int
     */
    public function getWaitTtl()
    {
        return $this->wait_ttl;
    }

    /**
     * @param int $wait_ttl
     */
    public function setWaitTtl($wait_ttl)
    {
        $this->wait_ttl = $wait_ttl;
    }

    /**
     * @return \yii\caching\Cache
     */
    public function getCache()
    {
        return $this->cache;
    }

    /**
     * @param \yii\caching\Cache $cache
     */
    public function setCache($cache)
    {
        $this->cache = $cache;
    }
}
