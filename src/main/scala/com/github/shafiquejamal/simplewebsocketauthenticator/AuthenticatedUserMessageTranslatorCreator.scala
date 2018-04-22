package com.github.shafiquejamal.simplewebsocketauthenticator

import akka.actor.{ActorRef, Props}
import com.github.shafiquejamal.util.id.UUIDProvider

trait AuthenticatedUserMessageTranslatorCreator[UD] {

  def props(
      userDetails: UD,
      namedClient: ActorRef,
      messageRouter: ActorRef,
      uUIDProvider: UUIDProvider): Props

}
