<?php

namespace JwtAuth;

class Timer
{
    /**
     * 返回当前时间
     *
     * @return int
     */
    public static function now()
    {
        return time();
    }

    /**
     * 返回当前时间给定秒数后的时间
     *
     * @param int $seconds
     * @return false|int
     */
    public static function atAfter($seconds)
    {
        return strtotime('+' . $seconds . ' seconds');
    }

    /**
     * 返回当前时间给定秒数前的时间
     *
     * @param int $seconds
     * @return false|int
     */
    public static function atBefore($seconds)
    {
        return strtotime('-' . $seconds . ' seconds');
    }

    /**
     * 判断当前时间是否大于给定时间
     *
     * @param int $time
     * @return bool
     */
    public static function isPast($time)
    {
        return self::now() > $time;
    }

    /**
     * 判断当前时间是否大于等给定时间
     *
     * @param int $time
     * @return bool
     */
    public static function isNowOrPast($time)
    {
        return self::now() >= $time;
    }

    /**
     * 判断当前时间距给定时间是否已过去给定的秒数
     *
     * @param int $time
     * @param int $seconds
     * @return bool
     */
    public static function isPastSeconds($time, $seconds)
    {
        return self::atBefore($seconds) > (int)$time;
    }

    /**
     * 返回当前时间距给定时间的秒数
     *
     * @param int $time
     * @return int
     */
    public static function secondsTo($time)
    {
        return $time - self::now();
    }
}
