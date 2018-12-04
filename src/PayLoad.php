<?php

namespace JwtAuth;

use Yii;
use yii\base\UnknownPropertyException;
use JwtAuth\Exceptions\InvalidSegmentException;
use JwtAuth\Exceptions\TokenInvalidException;

class PayLoad extends BaseModel
{
    /**
     * @var string jwt签发者
     */
    public $iss;

    /**
     * @var string jwt所面向的用户
     */
    public $sub;

    /**
     * @var string 接收jwt的一方
     */
    public $aud;

    /**
     * @var int jwt的过期时间，这个过期时间必须大于签发时间
     */
    public $exp;

    /**
     * @var int 定义在什么时间之前，该jwt都是不可用的
     */
    public $nbf;

    /**
     * @var int jwt的签发时间
     */
    public $iat;

    /**
     * @var string jwt的唯一身份标识，主要用来作为一次性token，从而回避重放攻击
     */
    public $jti;

    /**
     * @var null|string 编码后的载荷
     */
    private $encode_payload = null;

    /**
     * @var array 用户自定义载荷部分
     */
    private $custom_claims = [];

    /**
     * JWTPayLoad constructor.
     * @param array $config
     */
    public function __construct($custom_claims = [], array $config = [])
    {
        parent::__construct($config);

        $this->custom_claims = isset($custom_claims) ? $custom_claims : [];
    }

    /**
     * 访问自定义载荷
     *
     * @param string $name
     * @return mixed
     */
    public function __get($name)
    {
        try {
            return parent::__get($name);
        } catch (UnknownPropertyException $ex) {
            return $this->custom_claims[$name];
        }
    }

    /**
     * 设置自定义载荷
     *
     * @param string $name
     * @param mixed $value
     */
    public function __set($name, $value)
    {
        try {
            parent::__set($name, $value);
        } catch (UnknownPropertyException $ex) {
            $this->custom_claims[$name] = $value;
        }
    }

    /**
     * @return string
     * @throws InvalidSegmentException
     */
    public function __toString()
    {
        return $this->getEncodePayload();
    }

    /**
     * @return array
     */
    public function rules()
    {
        return [
            [['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'], 'required'],
            [['iss', 'sub', 'aud', 'jti'], 'string'],
            [['exp', 'nbf', 'iat'], 'integer']
        ];
    }

    /**
     * 编码载荷
     *
     * @return null|string
     * @throws InvalidSegmentException
     */
    protected function encode()
    {
        $claims = $this->claims();

        if (!$this->validate(array_keys($claims))) {
            throw new InvalidSegmentException('Token claims error!');
        }

        $this->encode_payload = $this->encodeArray($claims);

        return $this->encode_payload;
    }

    /**
     * 解码载荷
     *
     * @return PayLoad
     * @throws TokenInvalidException
     */
    protected function decode()
    {
        $claims = $this->decodeString($this->encode_payload);

        if (!is_array($claims)) {
            throw new TokenInvalidException('Token claims error!');
        }

        Yii::configure($this, $claims);

        if (!$this->validate(array_keys($this->attributes))) {
            throw new TokenInvalidException('Token claims error!');
        }

        return $this;
    }

    /**
     * 刷新载荷
     *
     * @return null|string
     * @throws InvalidSegmentException
     */
    public function refresh()
    {
        return $this->encode();
    }

    /**
     * 合并自定义载荷和标准载荷，并将自定义载荷中标准载荷部分移动到标准载荷中
     *
     * @return array
     */
    public function claims()
    {
        $attributes = $this->attributes;

        $claims = array_merge($attributes, $this->custom_claims);
        $this->attributes = array_intersect_key($this->custom_claims, $attributes);
        $this->custom_claims = array_diff_key($this->custom_claims, $attributes);

        return $claims;
    }

    /**
     * @return string
     * @throws InvalidSegmentException
     */
    public function getEncodePayload()
    {
        if (!isset($this->encode_payload)) {
            $this->refresh();
        }
        return $this->encode_payload;
    }

    /**
     * @param string $encode_payload
     * @return PayLoad
     * @throws TokenInvalidException
     */
    public function setEncodePayload($encode_payload)
    {
        $this->encode_payload = $encode_payload;
        return $this->decode();
    }

    /**
     * @return array
     */
    public function getCustomClaims()
    {
        return $this->custom_claims;
    }

    /**
     * @param array $custom_claims
     */
    public function setCustomClaims($custom_claims)
    {
        $this->custom_claims = $custom_claims;
    }

    /**
     * @return string
     */
    public static function genIss()
    {
        return Yii::$app->id;
    }

    /**
     * @return string
     */
    public static function genAud()
    {
        return 'client';
    }

    /**
     * @param int $ttl
     * @return false|int
     */
    public static function genExp($ttl)
    {
        return Timer::atAfter($ttl);
    }

    /**
     * @param int $wait_ttl
     * @return false|int
     */
    public static function genNbf($wait_ttl)
    {
        return Timer::atAfter($wait_ttl);
    }

    /**
     * @return int
     */
    public static function genIat()
    {
        return Timer::now();
    }

    /**
     * @return string
     * @throws \yii\base\Exception
     */
    public static function genJti()
    {
        return Yii::$app->security->generateRandomString();
    }
}
