package com.github.shafiquejamal.simplewebsocketauthenticator

import com.github.shafiquejamal.accessapi.user.UserDetails

trait PasswordResetCodeRequestActions[US] {

  def sendUsing(userDetails: UserDetails[US]): Unit

}

