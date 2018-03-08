package com.github.shafiquejamal.simplewebsocketauthenticator

import com.github.shafiquejamal.accessapi.user.UserDetails

trait PasswordResetCodeRequestActions[UD] {

  def sendUsing(userDetails: UD): Unit

}

