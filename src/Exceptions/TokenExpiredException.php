<?php

namespace JwtAuth\Exceptions;

class TokenExpiredException extends JwtException
{
    /**
     * @var int
     */
    protected $statusCode = 401;
}
