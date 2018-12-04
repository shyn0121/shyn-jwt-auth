<?php

namespace JwtAuth;

use yii\base\UnknownPropertyException;
use JwtAuth\Exceptions\TokenExpiredException;
use JwtAuth\Exceptions\TokenInvalidException;
use JwtAuth\Exceptions\InvalidSegmentException;

class Jwt extends BaseModel
{
    /**
     * @var Head token头部
     */
    public $head;

    /**
     * @var PayLoad token载荷
     */
    public $payload;

    /**
     * @var string token字符串形式
     */
    private $token;

    /**
     * @var string 加密秘钥
     */
    private $salt;

    /**
     * @var string token的签名部分
     */
    private $signature;

    /**
     * Jwt constructor.
     * @param string $salt
     * @param array $config
     */
    public function __construct($salt, array $config = [])
    {
        parent::__construct($config);

        $this->salt = $salt;
    }

    /**
     * 访问头部或载荷属性
     *
     * @param string $name
     * @return mixed
     */
    public function __get($name)
    {
        try {
            return parent::__get($name);
        } catch (UnknownPropertyException $ex) {
            if ($name === 'type' || $name === 'alg' || $name === 'encodeHead') {
                return $this->head->$name;
            } else {
                return $this->payload->$name;
            }
        }
    }

    /**
     * 设置头部或载荷属性
     *
     * @param string $name
     * @param mixed $value
     */
    public function __set($name, $value)
    {
        try {
            parent::__set($name, $value);
        } catch (UnknownPropertyException $ex) {
            if ($name === 'type' || $name === 'alg' || $name === 'encodeHead') {
                $this->head->$name = $value;
            } else {
                $this->payload->$name = $value;
            }
        }
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->token;
    }

    /**
     * @return array
     */
    public function rules()
    {
        return [
            [['head', 'payload'], 'required'],
            [['head', 'payload'], 'validateInstance']
        ];
    }

    /**
     * 头部和载荷类型验证器
     *
     * @param string $attribute
     * @param mixed $params
     */
    public function validateInstance($attribute, $params)
    {
        if (!$this->hasErrors()) {
            $class_name = 'JwtAuth\\' . ucfirst($attribute);

            if (!$this->$attribute instanceof $class_name) {
                $this->addError($attribute, 'token ' . $attribute . ' error!');
            }
        }
    }

    /**
     * 验证token格式
     *
     * @throws TokenInvalidException
     */
    public function verifyToken()
    {
        if (!is_string($this->token)) {
            throw new TokenInvalidException('Token format error!');
        }
        if (count(explode('.', $this->token)) !== 3) {
            throw new TokenInvalidException('Token format error!');
        }
    }

    /**
     * 验证token签名
     *
     * @return bool
     * @throws TokenInvalidException
     */
    public function verifySignature()
    {
        $entity = $this->encodeHead . '.' . $this->encodePayload;

        $verified_signature = $this->sign($this->alg, $entity, $this->salt);

        if ($verified_signature !== $this->signature) {
            throw new TokenInvalidException('Token signature error!');
        }

        return true;
    }

    /**
     * 验证token过期时间
     *
     * @return bool
     * @throws TokenExpiredException
     */
    public function verifyExpiredTime()
    {
        if (Timer::isPast($this->exp)) {
            throw new TokenExpiredException('Token has expired!');
        }
        return true;
    }

    /**
     * 验证token开始使用时间
     *
     * @return bool
     * @throws TokenInvalidException
     */
    public function verifyNotBeforeTime()
    {
        if (!Timer::isNowOrPast($this->nbf)) {
            throw new TokenInvalidException('Token can not be used before nbf time!');
        }
        return true;
    }

    /**
     * 验证token刷新时间
     *
     * @param $refresh_ttl
     * @return bool
     * @throws TokenInvalidException
     */
    public function verifyRefreshTime($refresh_ttl)
    {
        if (Timer::isPastSeconds($this->iat, $refresh_ttl)) {
            throw new TokenInvalidException('Token can not be refreshed!');
        }
        return true;
    }

    /**
     * 编码token
     *
     * @return string
     * @throws InvalidSegmentException
     */
    protected function encode()
    {
        if (!$this->validate(array_keys($this->attributes))) {
            throw new InvalidSegmentException('Token header or payload error!');
        }

        $entity = $this->encodeHead . '.' . $this->encodePayload;
        $signature = $this->sign($this->alg, $entity, $this->salt);

        $this->token = $entity . '.' . $signature;
        $this->signature = $signature;

        return $this->token;
    }

    /**
     * 解码token
     *
     * @return Jwt
     * @throws TokenInvalidException
     */
    protected function decode()
    {
        $this->verifyToken();

        list($encode_head, $encode_payload, $signature) = explode('.', $this->token);

        $this->head = new Head();
        $this->encodeHead = $encode_head;

        $this->payload = new PayLoad();
        $this->encodePayload = $encode_payload;

        $this->signature = $signature;

        return $this;
    }

    /**
     * 刷新token
     *
     * @return string
     * @throws InvalidSegmentException
     */
    public function refresh()
    {
        $this->head->refresh();
        $this->payload->refresh();

        return $this->encode();
    }

    /**
     * @return string
     * @throws InvalidSegmentException
     */
    public function getToken()
    {
        if (!isset($this->token)) {
            $this->refresh();
        }
        return $this->token;
    }

    /**
     * @param string $token
     * @return Jwt
     * @throws TokenInvalidException
     */
    public function setToken($token)
    {
        $this->token = $token;
        return $this->decode();
    }

    /**
     * 解析token
     *
     * @param null|string $token
     * @param int $refresh_ttl
     * @return Jwt
     * @throws TokenExpiredException
     * @throws TokenInvalidException
     */
    public function parseToken($token = null, $refresh_ttl = 0)
    {
        if (isset($token)) {
            $this->setToken($token);
        }

        if ($this->verifySignature() && $this->verifyNotBeforeTime()
            && $this->verifyRefreshTime($refresh_ttl) && $this->verifyExpiredTime()) {
            return $this;
        }
    }

    /**
     * 解析token，并判断token是否可刷新
     *
     * @param null|string $token
     * @param $refresh_ttl
     * @return bool
     * @throws TokenInvalidException
     */
    public function parseRefreshToken($token = null, $refresh_ttl = 0)
    {
        try {
            $this->parseToken($token, $refresh_ttl);
        } catch (TokenExpiredException $ex) {

        }
        return true;
    }
}
