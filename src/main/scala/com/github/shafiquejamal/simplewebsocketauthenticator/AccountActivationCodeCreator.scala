package com.github.shafiquejamal.simplewebsocketauthenticator

trait AccountActivationCodeCreator {
  def generate(toHash: String): String

  def isMatch(toHash: String, toCheck: String): Boolean
}
