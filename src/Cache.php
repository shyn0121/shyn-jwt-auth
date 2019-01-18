<?php

namespace JwtAuth;

use Yii;

abstract class Cache
{
    /**
     * 设置缓存
     *
     * @param string $key
     * @param array $value
     * @param null|int $expire
     */
    public static function set($key, $value = [], $expire = null)
    {
        Yii::$app->jwtManager->cache->set(static::serializeKey($key), $value, $expire);
    }

    /**
     * 获取缓存
     * 缓存未命中返回bool值false，所以请不要把false作为缓存内容。这个地方一定要注意
     *
     * @param string $key
     * @return mixed
     */
    public static function get($key)
    {
        return Yii::$app->jwtManager->cache->get(static::serializeKey($key));
    }

    /**
     * 删除缓存
     *
     * @param string $key
     */
    public static function delete($key)
    {
        Yii::$app->jwtManager->cache->delete(static::serializeKey($key));
    }

    /**
     * 序列化key值
     *
     * @param string $key
     * @return string
     */
    public abstract static function serializeKey($key);
}
