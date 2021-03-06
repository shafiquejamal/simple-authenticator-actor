package com.github.shafiquejamal.simplewebsocketauthenticator

import java.util.UUID

import akka.actor.{ActorRef, Props}
import com.github.shafiquejamal.util.id.UUIDProvider
import com.github.shafiquejamal.util.time.JavaInstantTimeProvider

trait MessageRouterPropsCreator[UD] {

  def props(
      client: ActorRef,
      userDetails: UD,
      timeProvider: JavaInstantTimeProvider,
      uUIDProvider: UUIDProvider): Props

}