<?php

namespace JwtAuth\Filters;

use Yii;
use yii\base\ActionFilter;

class AuthFilter extends ActionFilter
{
    /**
     * @param \yii\base\Action $action
     * @return bool
     */
    public function beforeAction($action)
    {
        Yii::$app->jwtManager->parseToken(null, true);
        
        return true;
    }
}