<?php

namespace JwtAuth;

class BlackList extends BaseList
{
    /**
     * 缓存键值前缀
     */
    const BLACK_LIST_PREFIX = 'jwt-bl-';

    /**
     * 序列化key值
     *
     * @param string $key
     * @return string
     */
    public static function serializeKey($key)
    {
        return self::BLACK_LIST_PREFIX . $key;
    }
}
