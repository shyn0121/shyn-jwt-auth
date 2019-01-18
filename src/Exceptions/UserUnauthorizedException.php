<?php

namespace JwtAuth\Exceptions;

class UserUnauthorizedException extends JwtException
{
    /**
     * @var int http状态码
     */
    protected $statusCode = 401;
}
