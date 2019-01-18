<?php

namespace JwtAuth;

use JwtAuth\Exceptions\SegmentErrorException;
use JwtAuth\Exceptions\TokenExpiredException;
use JwtAuth\Exceptions\TokenInvalidException;
use JwtAuth\Exceptions\UnknownPropertyException;

class Jwt extends Segment
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
     *
     * @param string $salt
     */
    public function __construct($salt)
    {
        $this->salt = $salt;
    }

    /**
     * 属性格式验证
     *
     * @return bool
     */
    public function validate()
    {
        if (!$this->head instanceof Head || !$this->payload instanceof Payload) {
            return false;
        }
        return true;
    }

    /**
     * jwt编码
     *
     * @param bool $refresh
     * @return string
     */
    public function encode($refresh = false)
    {
        if (!$refresh && isset($this->token)) {
            return $this->token;
        }

        if (!$this->validate()) {
            throw new SegmentErrorException('Token header or payload error!');
        }
        $entity = $this->entity($refresh);
        $this->signature = $this->sign($entity);

        return $this->token = $entity . '.' . $this->signature;
    }

    /**
     * jwt解码
     *
     * @param string $token
     * @return Segment
     * @throws TokenInvalidException
     */
    public function decode($token)
    {
        $this->token = $token;
        $this->verifyToken();

        $this->head = new Head();
        $this->payload = new Payload();
        list($encodeHead, $encodePayload, $this->signature) = explode('.', $this->token);

        $this->head->decode($encodeHead);
        $this->payload->decode($encodePayload);

        return $this;
    }

    /**
     * jwt实体编码
     *
     * @param bool $refresh
     * @return string
     * @throws SegmentErrorException
     */
    private function entity($refresh = false)
    {
        return $this->head->encode($refresh) . '.' . $this->payload->encode($refresh);
    }

    /**
     * jwt签名
     *
     * @param string $entity
     * @return string
     */
    private function sign($entity)
    {
        return hash($this->head->alg, $entity . $this->salt);
    }

    /**
     * 验证token格式
     *
     * @return bool
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

        return true;
    }

    /**
     * 解析token
     *
     * @param string $token
     * @param int $refreshTtl
     * @return bool
     * @throws TokenExpiredException
     * @throws TokenInvalidException
     */
    public function parseToken($token, $refreshTtl)
    {
        $this->decode($token);

        return $this->verifySignature() && $this->verifyNotBeforeTime()
            && $this->verifyRefreshTime($refreshTtl) && $this->verifyExpiredTime();

    }

    /**
     * 解析token，并判断token是否可刷新
     *
     * @param string $token
     * @param int $refreshTtl
     * @return bool
     * @throws TokenInvalidException
     */
    public function parseRefreshToken($token, $refreshTtl)
    {
        try {
            $this->parseToken($token, $refreshTtl);
        } catch (TokenExpiredException $ex) {

        }
        return true;
    }

    /**
     * 验证token签名
     *
     * @return bool
     * @throws SegmentErrorException
     * @throws TokenInvalidException
     */
    public function verifySignature()
    {
        $entity = $this->entity();
        $signature = $this->sign($entity);
        if ($signature !== $this->signature) {
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
        if (Timer::isPast($this->payload->exp)) {
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
        if (!Timer::isNowOrPast($this->payload->nbf)) {
            throw new TokenInvalidException('Token can not be used so far!');
        }
        return true;
    }

    /**
     * 验证token刷新时间
     *
     * @param int $refreshTtl
     * @return bool
     * @throws TokenInvalidException
     */
    public function verifyRefreshTime($refreshTtl)
    {
        if (Timer::isPastSeconds($this->payload->iat, $refreshTtl)) {
            throw new TokenInvalidException('Token can not be refreshed!');
        }
        return true;
    }
}
