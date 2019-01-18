<?php

namespace JwtAuth;

use Yii;
use yii\base\Component;
use JwtAuth\Exceptions\TokenExpiredException;
use JwtAuth\Exceptions\TokenInvalidException;
use JwtAuth\Exceptions\SegmentErrorException;
use JwtAuth\Exceptions\UserUnauthorizedException;
use JwtAuth\Exceptions\UserNotFoundException;
use JwtAuth\Exceptions\UnknownPropertyException;

class Manager extends Component
{
    /**
     * @var bool 开启黑名单机制
     */
    public $blacklistEnable = false;

    /**
     * @var bool 开启白名单机制
     */
    public $whitelistEnable = false;

    /**
     * @var string 用户认证类路径
     */
    public $userClass;

    /**
     * @var string 加密算法
     */
    public $alg = 'sha256';

    /**
     * @var string 加密秘钥
     */
    public $salt;

    /**
     * @var int token过期时间 单位：秒
     */
    public $ttl = 86400;

    /**
     * @var int token刷新过期时间 单位：秒
     */
    public $refreshTtl = 2592000;

    /**
     * @var int token开始使用时间 单位：秒
     */
    public $waitTtl = 0;

    /**
     * @var \yii\caching\Cache 缓存驱动
     */
    public $cache;

    /**
     * @var Auth
     */
    private $auth = null;

    /**
     * Manager constructor.
     *
     * @param array $config
     */
    public function __construct($config = [])
    {
        parent::__construct($config);

        $this->configureCache();
    }

    /**
     * 调用Auth方法
     *
     * @param string $name
     * @param array $params
     * @return mixed
     */
    public function __call($name, $params)
    {
        return call_user_func_array([$this->auth(), $name], $params);
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
     * 生成token
     *
     * @return string
     * @throws UserUnauthorizedException
     */
    public function createToken()
    {
        $auth = $this->auth();
        $user = $auth->login();

        $jwt = $this->genJwtByUser($user);

        $this->registerToken($jwt->encode());
        $this->addTokenToWhitelist($jwt, $user->genContent());
        $auth->addTokenToResponse();

        return $auth->token;
    }

    /**
     * 验证token，并返回认证的用户实例
     *
     * @param null|string $token
     * @param bool $autoRefresh token过期是否自动刷新
     * @return UserAuthInterface
     * @throws UserNotFoundException
     * @throws UserUnauthorizedException
     * @throws TokenExpiredException
     * @throws TokenInvalidException
     */
    public function parseToken($token = null, $autoRefresh = false)
    {
        $auth = $this->auth();

        if (isset($token) && is_string($token)) {
            $this->registerToken($token);
        }

        $jwt = $this->genJwt();
        try {
            $jwt->parseToken($auth->token(), $this->refreshTtl);
        } catch (TokenExpiredException $ex) {
            if ($autoRefresh) {
                $this->refreshToken($jwt);
                return $auth->user();
            }
            throw $ex;
        }
        $content = $this->verifyTokenInList($jwt);

        return $auth->configureUserById($jwt->payload->sub, $jwt->payload->customClaims, $content);
    }

    /**
     * 刷新token
     *
     * @param null|string $token
     * @return string
     * @throws UserNotFoundException
     * @throws TokenInvalidException
     */
    public function refreshToken($token = null)
    {
        $auth = $this->auth();

        if (isset($token) && is_string($token)) {
            $this->registerToken($token);
        }
        if (isset($token) && $token instanceof Jwt) {
            $jwt = $token;
        } else {
            $jwt = $this->genJwt();
            $jwt->parseRefreshToken($auth->token(), $this->refreshTtl);
        }

        $content = $this->verifyTokenInList($jwt);
        $this->changeListOnRemoveToken($jwt);

        $this->registerToken($this->refreshJwt($jwt));
        $this->addTokenToWhitelist($jwt, $content);
        $auth->configureUserById($jwt->payload->sub, $jwt->payload->customClaims, $content);
        $auth->addTokenToResponse();

        return $auth->token();
    }

    /**
     * 注销token
     *
     * @param null|string $token
     */
    public function invalidateToken($token = null)
    {
        $auth = $this->auth();

        if (isset($token) && is_string($token)) {
            $this->registerToken($token);
        }

        $jwt = $this->genJwt();
        try {
            $jwt->parseToken($auth->token(), $this->refreshTtl);
        } catch (\Exception $ex) {
            if (!($ex instanceof TokenExpiredException)) {
                return;
            }
        }
        $this->changeListOnRemoveToken($jwt);
        $auth->removeTokenFromResponse();
    }

    /**
     * 注册token到应用
     *
     * @param string $token
     */
    private function registerToken($token)
    {
        $this->auth()->token = $token;
    }

    /**
     * 添加token到黑名单
     *
     * @param Jwt $jwt
     */
    private function addTokenToBlacklist($jwt)
    {
        if ($this->blacklistEnable) {
            Blacklist::set($jwt->payload->jti, [], $this->genExpiredTime($jwt));
        }
    }

    /**
     * 添加token到白名单
     *
     * @param Jwt $jwt
     * @param array $content
     */
    private function addTokenToWhitelist($jwt, $content)
    {
        if ($this->whitelistEnable) {
            Whitelist::set($jwt->payload->jti, is_array($content) ? $content : [], $this->genExpiredTime($jwt));
        }
    }

    /**
     * 从白名单中移除token
     *
     * @param Jwt $jwt
     */
    private function removeTokenFromWhitelist($jwt)
    {
        if ($this->whitelistEnable) {
            Whitelist::delete($jwt->payload->jti);
        }
    }

    /**
     * 删除token时，把该token添加到黑名单，并从白名单中移除
     *
     * @param Jwt $jwt
     */
    private function changeListOnRemoveToken($jwt)
    {
        $this->addTokenToBlacklist($jwt);
        $this->removeTokenFromWhitelist($jwt);
    }

    /**
     * 检测token是否通过黑白名单验证
     *
     * @param Jwt $jwt
     * @return array
     * @throws TokenInvalidException
     */
    private function verifyTokenInList($jwt)
    {
        if ($this->blacklistEnable) {
            $value = Blacklist::get($jwt->payload->jti);
            if ($value !== false) {
                throw new TokenInvalidException('Token in blacklist!');
            }
        }

        if ($this->whitelistEnable) {
            $value = Whitelist::get($jwt->payload->jti);
            if ($value === false) {
                throw new TokenInvalidException('Token not in whitelist!');
            }
            return $value;
        }

        return [];
    }

    /**
     * 刷新jwt
     *
     * @param Jwt $jwt
     * @return string
     * @throws SegmentErrorException
     */
    private function refreshJwt($jwt)
    {
        $jwt->payload->exp = Payload::genExp($this->ttl);
        $jwt->payload->nbf = Payload::genNbf($this->waitTtl);
        $jwt->payload->iat = Payload::genIat();
        $jwt->payload->jti = Payload::genJti();

        return $jwt->encode(true);
    }

    /**
     * 通过用户实例生成Jwt实例
     *
     * @param UserAuthInterface $user
     * @return Jwt
     * @throws SegmentErrorException
     */
    private function genJwtByUser($user)
    {
        $head = new Head();
        $head->configure(['type' => 'jwt', 'alg' => $this->alg]);

        $payload = new Payload($user->genCustomClaims());
        $payload->configure([
            'iss' => Payload::genIss(),
            'aud' => Payload::genAud(),
            'exp' => Payload::genExp($this->ttl),
            'nbf' => Payload::genNbf($this->waitTtl),
            'iat' => Payload::genIat(),
            'jti' => Payload::genJti(),
            'sub' => $user->getId()
        ]);

        $jwt = $this->genJwt();
        $jwt->configure(['head' => $head, 'payload' => $payload]);

        return $jwt;
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
        return Timer::secondsTo($jwt->payload->iat) + $this->refreshTtl;
    }

    /**
     * @return Auth
     */
    public function auth()
    {
        if (!isset($this->auth)) {
            $this->auth = new Auth();
        }
        return $this->auth;
    }
}
