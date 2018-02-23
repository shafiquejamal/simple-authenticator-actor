package com.github.shafiquejamal.simplewebsocketauthenticator

import java.util.UUID

import com.github.shafiquejamal.accessapi.access.authentication.{AuthenticationAPI, JWTCreator, TokenValidator}
import com.github.shafiquejamal.accessapi.access.registration.{AccountActivationCodeSender, RegistrationAPI, UserActivator}
import com.github.shafiquejamal.accessapi.user.{UserAPI, UserDetails}
import com.github.shafiquejamal.accessmessage.OutBound.AccountActivationAttemptResultMessage
import com.github.shafiquejamal.simplewebsocketauthenticator.AuthenticatorMessagesFixture._
import com.github.shafiquejamal.util.id.TestUUIDProviderImpl
import com.github.shafiquejamal.util.time.TestJavaInstantTimeProvider
import org.scalamock.scalatest.MockFactory
import org.scalatest.{FlatSpecLike, Matchers}

class AuthenticatorUTest extends FlatSpecLike with Matchers with MockFactory {

  trait Fixture {
    val timeProvider = new TestJavaInstantTimeProvider()
    val uUIDProvider = new TestUUIDProviderImpl()
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

  trait MessagesFixture {
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

  "The authenticator" should "send back a message indicateding that an email address is available if it is available" in
    new MocksFixture with MessagesFixture with Fixture {

      val authenticator = Authenticator.props(
        tokeValidator,
        userAPI,
        authenticationAPI,
        registrationAPI,
        jWTCreator,
        timeProvider,
        uUIDProvider,
        null,
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
      )

    }


}
