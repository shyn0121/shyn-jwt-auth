<?php

namespace JwtAuth;

use Yii;
use JwtAuth\Exceptions\SegmentErrorException;
use JwtAuth\Exceptions\TokenInvalidException;
use JwtAuth\Exceptions\UnknownPropertyException;

class Payload extends Segment
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
     * @var string jwt的唯一标识
     */
    public $jti;

    /**
     * @var array 用户自定义载荷部分
     */
    public $customClaims = [];

    /**
     * @var string|null 编码后的载荷
     */
    private $encodePayload = null;

    /**
     * Payload constructor.
     *
     * @param array $customClaims
     */
    public function __construct($customClaims = [])
    {
        $this->customClaims = is_array($customClaims) ? $customClaims : [];
    }

    /**
     * 获取自定义载荷
     *
     * @param string $name
     * @return mixed
     * @throws UnknownPropertyException
     */
    public function __get($name)
    {
        if (in_array($name, $this->customClaims)) {
            return $this->customClaims[$name];
        }
        throw new UnknownPropertyException('Getting unknown property: Payload::' . $name);
    }

    /**
     * 设置自定义载荷
     *
     * @param string $name
     * @param int|string $value
     */
    public function __set($name, $value)
    {
        $this->customClaims[$name] = $value;
    }

    /**
     * 属性格式验证
     *
     * @return bool
     */
    public function validate()
    {
        if (!(is_string($this->iss) && is_string($this->aud) && is_string($this->jti))) {
            return false;
        }
        if (!(is_int($this->exp) && is_int($this->nbf) && is_int($this->iat))) {
            return false;
        }
        if (!is_string($this->sub) && !is_int($this->sub)) {
            return false;
        }
        return true;
    }

    /**
     * 载荷编码
     *
     * @param bool $refresh
     * @return string
     * @throws SegmentErrorException
     */
    public function encode($refresh = false)
    {
        if (!$refresh && isset($this->encodePayload)) {
            return $this->encodePayload;
        }

        if (!$this->validate()) {
            throw new SegmentErrorException('Token claims error!');
        }

        return $this->encodePayload = $this->encodeArray($this->claims());
    }

    /**
     * 解码载荷
     *
     * @param string $encodePayload
     * @return Segment
     * @throws TokenInvalidException
     */
    public function decode($encodePayload)
    {
        $claims = $this->decodeString($this->encodePayload = $encodePayload);
        if (!is_array($claims)) {
            throw new TokenInvalidException('Token claims error!');
        }

        $this->configure($claims);
        if (!$this->validate()) {
            throw new TokenInvalidException('Token claims error!');
        }

        return $this;
    }

    /**
     * 合并自定义载荷和标准载荷，并将自定义载荷中标准载荷部分移动到标准载荷中
     *
     * @return array
     * @throws SegmentErrorException
     */
    public function claims()
    {
        $properties = $this->properties();
        $claims = array_merge($properties, $this->customClaims);
        $this->configure(array_intersect_key($this->customClaims, $properties));
        $this->customClaims = array_diff_key($this->customClaims, $properties);

        return $claims;
    }

    /**
     * @return string
     */
    public static function genIss()
    {
        return Yii::$app->id;
    }

    /**
     * @param string $aud
     * @return string
     */
    public static function genAud($aud = 'client')
    {
        return $aud;
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
     * @param int $waitTtl
     * @return false|int
     */
    public static function genNbf($waitTtl)
    {
        return Timer::atAfter($waitTtl);
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
     * @throws SegmentErrorException
     */
    public static function genJti()
    {
        try {
            return Yii::$app->security->generateRandomString();
        } catch (\yii\base\Exception $ex) {
            throw new SegmentErrorException($ex->getMessage());
        }
    }
}
