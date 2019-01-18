<?php

namespace JwtAuth;

class Whitelist extends Cache
{
    /**
     * 缓存键值前缀
     */
    const WHITE_LIST_PREFIX = 'jwt-whitelist-';

    /**
     * 序列化key值
     *
     * @param string $key
     * @return string
     */
    public static function serializeKey($key)
    {
        return self::WHITE_LIST_PREFIX . $key;
    }
}
