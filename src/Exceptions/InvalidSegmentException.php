<?php

namespace JwtAuth\Exceptions;

class InvalidSegmentException extends JwtException
{
    /**
     * @var int
     */
    protected $statusCode = 500;
}
