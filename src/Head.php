<?php

namespace JwtAuth;

use JwtAuth\Exceptions\SegmentErrorException;
use JwtAuth\Exceptions\TokenInvalidException;

class Head extends Segment
{
    /**
     * @var string token类型
     */
    public $type;

    /**
     * @var string token签名算法
     */
    public $alg;

    /**
     * @var string base64编码后的头部
     */
    private $encodeHead = null;

    /**
     * 验证属性格式
     *
     * @return bool
     */
    public function validate()
    {
        $supportAlgos = hash_algos();
        if ($this->type !== 'jwt' || !in_array($this->alg, $supportAlgos)) {
            return false;
        }
        return true;
    }

    /**
     * jwt头部编码
     *
     * @param bool $refresh
     * @return string
     * @throws SegmentErrorException
     */
    public function encode($refresh = false)
    {
        if (!$refresh && isset($this->encodeHead)) {
            return $this->encodeHead;
        }

        if (!$this->validate()) {
            throw new SegmentErrorException('Token type or encryption algorithm error!');
        }

        return $this->encodeHead = $this->encodeArray($this->properties());
    }

    /**
     * jwt头部解码
     *
     * @param string $encodeHead
     * @return Segment
     * @throws TokenInvalidException
     */
    public function decode($encodeHead)
    {
        $heads = $this->decodeString($this->encodeHead = $encodeHead);
        if (!is_array($heads)) {
            throw new TokenInvalidException('Token type or encryption algorithm error!');
        }

        $this->configure($heads);
        if (!$this->validate()) {
            throw new TokenInvalidException('Token type or encryption algorithm error!');
        }

        return $this;
    }
}
