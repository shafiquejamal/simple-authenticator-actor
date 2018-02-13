package com.github.shafiquejamal.simplewebsocketauthenticator

import java.util.UUID

trait ClientPaths {

  def namedClientActorName(clientId: UUID, randomUUID: UUID): String

  def namedClientPath(clientId: UUID): String

}

