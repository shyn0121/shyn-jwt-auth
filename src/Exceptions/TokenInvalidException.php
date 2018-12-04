<?php

namespace JwtAuth\Exceptions;

class TokenInvalidException extends JwtException
{
    /**
     * @var int
     */
    protected $statusCode = 401;
}
