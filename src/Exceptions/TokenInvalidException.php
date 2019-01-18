<?php

namespace JwtAuth\Exceptions;

class TokenInvalidException extends JwtException
{
    /**
     * @var int http状态码
     */
    protected $statusCode = 401;
}
