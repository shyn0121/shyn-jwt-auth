<?php

namespace JwtAuth;

class Blacklist extends Cache
{
    /**
     * 缓存键值前缀
     */
    const BLACK_LIST_PREFIX = 'jwt-blacklist-';

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
