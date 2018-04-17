package com.github.shafiquejamal.simplewebsocketauthenticator

import akka.actor.{Actor, ActorLogging, ActorRef, Props}
import com.github.shafiquejamal.accessapi.user.UserDetails
import com.github.shafiquejamal.util.id.UUIDProvider

class AuthenticatedUserMessageTranslator(
    userDetails: UserDetails[String],
    messageRouter: ActorRef,
    uUIDProvider: UUIDProvider) extends Actor with ActorLogging {

  override def receive: Receive = {
    case msg => messageRouter ! msg
  }

}

object AuthenticatedUserMessageTranslator {

  def props(
      userDetails: UserDetails[String],
      messageRouter: ActorRef,
      uUIDProvider: UUIDProvider): Props =
    Props(new AuthenticatedUserMessageTranslator(userDetails, messageRouter, uUIDProvider))

}