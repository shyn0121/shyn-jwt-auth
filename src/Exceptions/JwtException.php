<?php

namespace JwtAuth\Exceptions;

class JwtException extends \Exception
{
    /**
     * @var int http状态码
     */
    protected $statusCode = 500;

    /**
     * JwtException constructor.
     *
     * @param string $message
     * @param null|int $statusCode
     */
    public function __construct($message = 'An error occurred!', $statusCode = null)
    {
        parent::__construct($message);

        if (!is_null($statusCode)) {
            $this->setStatusCode($statusCode);
        }
    }

    /**
     * @param int $statusCode
     */
    public function setStatusCode($statusCode)
    {
        $this->statusCode = $statusCode;
    }

    /**
     * @return int
     */
    public function getStatusCode()
    {
        return $this->statusCode;
    }
}
