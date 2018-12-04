<?php

namespace JwtAuth;

use Yii;

class BaseList
{
    /**
     * 设置缓存,数据类型为字符串
     *
     * @param string $key
     * @param mixed $value
     * @param int $expire 单位：秒
     */
    public static function set($key, $value = [], $expire = null)
    {
        Yii::$app->jwtManager->cache->set(static::serializeKey($key), $value, $expire);
    }

    /**
     * 获取缓存内容
     *
     * @param string $key
     * @return bool|mixed 未命中缓存返回false
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
    public static function serializeKey($key)
    {
        return $key;
    }
}
