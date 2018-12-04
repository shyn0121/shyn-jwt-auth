<?php

namespace JwtAuth;

use yii\base\Model;

abstract class BaseModel extends Model
{
    /**
     * @var array 转化base64字符串中会被url编码的特殊字符
     */
    protected $base64_special_char = [
        '+' => '-',
        '/' => '_',
        '=' => '!',
    ];

    /**
     * @return string 编码
     */
    protected abstract function encode();

    /**
     * @return mixed 解码
     */
    protected abstract function decode();

    /**
     * @return string 刷新
     */
    protected abstract function refresh();

    /**
     * 编码
     *
     * @param array $array
     * @return string
     */
    protected function encodeArray($array)
    {
        $json_string = json_encode($array, JSON_UNESCAPED_SLASHES);
        $base64_string = base64_encode($json_string);
        foreach ($this->base64_special_char as $key => $value) {
            $base64_string = str_replace($key, $value, $base64_string);
        }
        return $base64_string;
    }

    /**
     * 解码
     *
     * @param  string $string
     * @return array|bool
     */
    protected function decodeString($string)
    {
        $base64_special_char = array_flip($this->base64_special_char);
        foreach ($base64_special_char as $key => $value) {
            $string = str_replace($key, $value, $string);
        }
        $json_string = base64_decode($string);
        return json_decode($json_string, true);
    }

    /**
     * 签名
     *
     * @param string $alg
     * @param string $entity
     * @param string $salt
     * @return string
     */
    protected function sign($alg, $entity, $salt)
    {
        return hash($alg, $entity . $salt);
    }
}
