package com.github.shafiquejamal.simplewebsocketauthenticator

import java.util.UUID

import akka.actor.ActorSystem
import akka.testkit.TestKit
import com.github.shafiquejamal.accessapi.access.authentication.{AuthenticationAPI, JWTCreator, TokenValidator}
import com.github.shafiquejamal.accessapi.access.registration.{AccountActivationCodeSender, RegistrationAPI, UserActivator}
import com.github.shafiquejamal.accessapi.user.{UserAPI, UserDetails}
import com.github.shafiquejamal.accessmessage.InBound.IsEmailAvailableMessage
import com.github.shafiquejamal.accessmessage.OutBound.AccountActivationAttemptResultMessage
import com.github.shafiquejamal.simplewebsocketauthenticator.AuthenticatorMessagesFixture._
import com.github.shafiquejamal.util.id.TestUUIDProviderImpl
import com.github.shafiquejamal.util.time.TestJavaInstantTimeProvider
import org.scalamock.scalatest.MockFactory
import org.scalatest.{BeforeAndAfterAll, FlatSpecLike, Matchers}

class AuthenticatorUTest() extends TestKit(ActorSystem("test-actor-system"))
  with Matchers
  with MockFactory
  with FlatSpecLike
  with BeforeAndAfterAll {

  override def afterAll {
    TestKit.shutdownActorSystem(system)
  }

  trait Fixture {
    val timeProvider = new TestJavaInstantTimeProvider()
    val uUIDProvider = new TestUUIDProviderImpl()
    uUIDProvider.index = 200
    val newMessageuUID = uUIDProvider.randomUUID()
    uUIDProvider.index = 0
    val originatingMessageUUID = uUIDProvider.randomUUID()
    uUIDProvider.index = 200
  }

  trait MocksFixture {
    val tokeValidator = mock[TokenValidator]
    val userAPI = mock[UserAPI[UserDetails[String]]]
    val authenticationAPI = mock[AuthenticationAPI[UserDetails[String]]]
    val registrationAPI = mock[RegistrationAPI[UserDetails[String], String]]
    val jWTCreator = mock[JWTCreator[UserDetails[String]]]
    val passwordResetCodeSender = mock[PasswordResetCodeRequestActions[String]]
    val accountActivationCodeSender = mock[AccountActivationCodeSender[UserDetails[String], String]]
    val passwordResetCodeRequestActions = mock[PasswordResetCodeRequestActions[String]]
    val accountActivationCodeCreator = mock[AccountActivationCodeCreator]
    val userActivator = mock[UserActivator[UserDetails[String], AccountActivationAttemptResultMessage[String]]]
    val clientPaths = new ClientPaths {
      override def namedClientPath(clientId: UUID): String = "namedClientPath"

      override def namedClientActorName(clientId: UUID, randomUUID: UUID): String = "namedClientActorName"
    }
    val messageRouterPropsCreator = mock[MessageRouterPropsCreator]
  }

  trait OutboundMessagesFixture {
    val logMeOutMessage = LogMeOutMessageImpl.apply _
    val yourLoginAttemptFailedMessage = YourLoginAttemptFailedMessageImpl.apply _
    val yourLoginAttemptSucceededMessage = YourLoginAttemptSucceededMessageImpl.apply _
    val passwordResetCodeMessageSent = PasswordResetCodeSentImpl.apply _
    val passwordResetSuccessfulMessage = PasswordResetSuccessfulMessageImpl.apply _
    val passwordResetFailedMessage = PasswordResetFailedMessageImpl.apply _
    val emailIsAvailableMessage = EmailIsAvailableMessageImpl.apply _
    val usernameIsAvailableMessage = UsernameIsAvailableMessageImpl.apply _
    val yourRegistrationAttemptSucceededMessage = YourRegistrationAttemptSucceededMessageImpl.apply _
    val yourRegistrationAttemptFailedMessage = YourRegistrationAttemptFailedMessageImpl.apply _
    val accountActivationAttemptFailedMessage = AccountActivationAttemptFailedMessageImpl.apply _
    val accountActivationAttemptSucceededMessage = AccountActivationAttemptSucceededMessageImpl.apply _
    val resendActivationCodeResultMessage = ResendActivationCodeResultMessageImpl.apply _
    val youAreAlreadyAuthenticatedMessage = YouAreAlreadyAuthenticatedMessageImpl.apply _
    val loggingYouOutMessage = LoggingYouOutMessageImpl.apply _
    val changePasswordFailedMessage = ChangePasswordFailedMessageImpl.apply _
    val changePasswordSucceededMessage = ChangePasswordSucceededMessageImpl.apply _
    val requestChangeEmailFailedMessage = RequestChangeEmailFailedMessageImpl.apply _
    val requestChangeEmailSucceededMessage = RequestChangeEmailSucceededMessageImpl.apply _
    val activateNewEmailFailedMessage = ActivateNewEmailFailedMessageImpl.apply _
    val activateNewEmailSucceededMessage = ActivateNewEmailSucceededMessageImpl.apply _
  }

  trait AuthenticatorFixture extends OutboundMessagesFixture with MocksFixture with Fixture {
    val authenticator = system.actorOf(Authenticator.props(
      tokeValidator,
      userAPI,
      authenticationAPI,
      registrationAPI,
      jWTCreator,
      timeProvider,
      uUIDProvider,
      testActor,
      passwordResetCodeRequestActions,
      accountActivationCodeSender,
      logMeOutMessage,
      yourLoginAttemptFailedMessage,
      yourLoginAttemptSucceededMessage,
      passwordResetCodeMessageSent,
      passwordResetSuccessfulMessage,
      passwordResetFailedMessage,
      emailIsAvailableMessage,
      usernameIsAvailableMessage,
      yourRegistrationAttemptFailedMessage,
      yourRegistrationAttemptSucceededMessage,
      accountActivationAttemptFailedMessage,
      accountActivationCodeCreator,
      resendActivationCodeResultMessage,
      userActivator,
      youAreAlreadyAuthenticatedMessage,
      loggingYouOutMessage,
      clientPaths,
      changePasswordFailedMessage,
      changePasswordSucceededMessage,
      messageRouterPropsCreator,
      null,
      requestChangeEmailFailedMessage,
      requestChangeEmailSucceededMessage,
      activateNewEmailFailedMessage,
      activateNewEmailSucceededMessage
    ))
  }

  "The authenticator" should "send back a message indicating that an email address is available if it is available" in
    new AuthenticatorFixture {

      val emailToCheck = "some@email.com"
      val isEmailAvailableMessage = new IsEmailAvailableMessage {
        override def email: String = emailToCheck

        override def iD: UUID = originatingMessageUUID
      }

      authenticator ! isEmailAvailableMessage
      (registrationAPI.isEmailIsAvailable _).expects(emailToCheck).returning(true)
      expectMsg(emailIsAvailableMessage(newMessageuUID, Some(originatingMessageUUID), emailToCheck, true).toJSON)
      (registrationAPI.isEmailIsAvailable _).expects(emailToCheck).returning(false)

      uUIDProvider.index = 200
      authenticator ! isEmailAvailableMessage
      expectMsg(emailIsAvailableMessage(newMessageuUID, Some(originatingMessageUUID), emailToCheck, false).toJSON)
    }


}
