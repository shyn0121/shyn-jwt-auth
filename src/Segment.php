<?php

namespace JwtAuth;

use JwtAuth\Exceptions\SegmentErrorException;
use JwtAuth\Exceptions\UnknownPropertyException;

abstract class Segment
{
    /**
     * @var array 转化base64字符串中会被url编码的特殊字符
     */
    private $specialChar = [
        '+' => '-',
        '/' => '_',
        '=' => '!',
    ];

    /**
     * 验证属性格式
     *
     * @return bool
     */
    public abstract function validate();

    /**
     * 编码
     *
     * @param bool $refresh
     * @return string
     */
    public abstract function encode($refresh);

    /**
     * 解码
     *
     * @param string $encodeSegment
     * @return Segment
     */
    public abstract function decode($encodeSegment);

    /**
     * 获取对象所用公共非静态属性的名称和值
     *
     * @return array
     * @throws SegmentErrorException
     */
    protected function properties()
    {
        try {
            $class = new \ReflectionClass($this);
        } catch (\ReflectionException $ex) {
            throw new SegmentErrorException($ex->getMessage());
        }

        $properties = [];
        foreach ($class->getProperties(\ReflectionProperty::IS_PUBLIC) as $property) {
            if (!$property->isStatic()) {
                $name = $property->getName();
                $properties[$name] = $this->$name;
            }
        }
        return $properties;
    }

    /**
     * 对象属性批量赋值
     *
     * @param array $properties
     * @return Segment
     */
    public function configure($properties)
    {
        foreach ($properties as $name => $value) {
            $this->$name = $value;
        }
        return $this;
    }

    /**
     * base64编码数组
     *
     * @param $array
     * @return string
     */
    protected function encodeArray($array)
    {
        $jsonString = json_encode($array, JSON_UNESCAPED_SLASHES);
        $baseString = base64_encode($jsonString);
        foreach ($this->specialChar as $key => $value) {
            $baseString = str_replace($key, $value, $baseString);
        }
        return $baseString;
    }

    /**
     * base64解码字符串
     *
     * @param string $string
     * @return array
     */
    protected function decodeString($string)
    {
        $specialChar = array_flip($this->specialChar);
        foreach ($specialChar as $key => $value) {
            $string = str_replace($key, $value, $string);
        }
        $jsonString = base64_decode($string);

        return json_decode($jsonString, true);
    }
}
