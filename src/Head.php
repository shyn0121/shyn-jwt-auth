<?php

namespace JwtAuth;

use Yii;
use JwtAuth\Exceptions\TokenInvalidException;
use JwtAuth\Exceptions\InvalidSegmentException;

class Head extends BaseModel
{
    /**
     * @var string token类型，值为‘jwt’
     */
    public $type;

    /**
     * @var string token签名算法，默认为sha256
     */
    public $alg;

    /**
     * @var null|string base64编码后的头部
     */
    private $encode_head = null;

    /**
     * @return null|string
     */
    public function __toString()
    {
        return $this->encodeHead;
    }

    /**
     * @return array
     */
    public function rules()
    {
        return [
            [['type', 'alg'], 'required'],
            ['type', 'validateType'],
            ['alg', 'validateAlg'],
        ];
    }

    /**
     * token类型验证器
     *
     * @param string $attribute
     * @param mixed $params
     */
    public function validateType($attribute, $params)
    {
        if (!$this->hasErrors()) {
            if ($this->type !== 'jwt') {
                $this->addError($attribute, 'Token type error!');
            }
        }
    }

    /**
     * token加密算法验证器
     *
     * @param string $attribute
     * @param mixed $params
     */
    public function validateAlg($attribute, $params)
    {
        if (!$this->hasErrors()) {
            $support_algos = hash_algos();
            if (!in_array($this->alg, $support_algos)) {
                $this->addError($attribute, 'Token encryption algorithm error!');
            }
        }
    }

    /**
     * 编码头部
     *
     * @return string
     * @throws InvalidSegmentException
     */
    protected function encode()
    {
        $heads = $this->attributes;

        if (!$this->validate(array_keys($heads))) {
            throw new InvalidSegmentException('Token type or encryption algorithm error!');
        }

        $this->encode_head = $this->encodeArray($heads);

        return $this->encode_head;
    }

    /**
     * 解码头部
     *
     * @return Head
     * @throws TokenInvalidException
     */
    protected function decode()
    {
        $heads = $this->decodeString($this->encode_head);

        if (!is_array($heads)) {
            throw new TokenInvalidException('Token type or encryption algorithm error!');
        }

        Yii::configure($this, $heads);

        if (!$this->validate(array_keys($this->attributes))) {
            throw new TokenInvalidException('Token type or encryption algorithm error!');
        }

        return $this;
    }

    /**
     * 刷新头部
     *
     * @return string
     * @throws InvalidSegmentException
     */
    public function refresh()
    {
        return $this->encode();
    }

    /**
     * @return string
     * @throws InvalidSegmentException
     */
    public function getEncodeHead()
    {
        if (!isset($this->encode_head)) {
            $this->refresh();
        }
        return $this->encode_head;
    }

    /**
     * @param $encode_head
     * @return Head
     * @throws TokenInvalidException
     */
    public function setEncodeHead($encode_head)
    {
        $this->encode_head = $encode_head;
        return $this->decode();
    }
}
