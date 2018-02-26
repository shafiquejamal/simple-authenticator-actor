package com.github.shafiquejamal.simplewebsocketauthenticator

import java.util.UUID

import akka.actor.{Actor, ActorRef, ActorSystem, Props}
import akka.testkit.TestKit
import com.github.shafiquejamal.accessapi.access.authentication.{AuthenticationAPI, JWTCreator, TokenValidator}
import com.github.shafiquejamal.accessapi.access.registration.{AccountActivationCodeSender, RegistrationAPI, UserActivator}
import com.github.shafiquejamal.accessapi.user.{UserAPI, UserContact, UserDetails}
import com.github.shafiquejamal.accessmessage.InBound.{AuthenticateMeMessage, IsEmailAvailableMessage, IsUsernameAvailableMessage, LogMeInMessage}
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

    def resetUUID(n: Int = 200): Unit = uUIDProvider.index = n
    uUIDProvider.index = 0
    val originatingMessageUUID = uUIDProvider.randomUUID()
    val generalUUID = uUIDProvider.randomUUID()
    resetUUID()
    val newMessageUUID = uUIDProvider.randomUUID()
    val secondNewMessageUUID = uUIDProvider.randomUUID()
    val emailAddress = "some@email.com"
    val userContact = new UserContact {
      override val userID: UUID = generalUUID
      override val email: String = "some-email"
      override val username: String = "some-username"
    }
    val aJWT = "some-JWT"

  }

  trait MocksFixture {
    val tokenValidator = new TokenValidator {
      var result: Option[UserContact] = None
      override def decodeAndValidateToken(
        token: String, blockToExecuteIfAuthorized: => (UUID, String) => Option[UserContact],
        blockToExecuteIfUnauthorized: => Option[(UUID, String)]): Option[UserContact] = result

      override val blockToExecuteIfAuthorized: (UUID, String) => Option[UserContact] = null

      override def blockToExecuteIfUnauthorized: Option[(UUID, String)] = null
    }
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
    class DummyActor extends Actor {
      override def receive: Receive = {
        case _ =>
      }
    }
    object DummyActor {
      def props = Props(new DummyActor)
    }
    def namedClientProps(a1: ActorRef, a2: ActorRef): Props = DummyActor.props
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
    val authenticationSuccessfulMessage = AuthenticationSuccessfulMessageImpl.apply _
  }

  trait AuthenticatorFixture extends OutboundMessagesFixture with MocksFixture with Fixture {
    val authenticator = system.actorOf(Authenticator.props(
      tokenValidator,
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
      namedClientProps,
      requestChangeEmailFailedMessage,
      requestChangeEmailSucceededMessage,
      activateNewEmailFailedMessage,
      activateNewEmailSucceededMessage,
      authenticationSuccessfulMessage))
  }

  "The authenticator" should "send back a message indicating that an email address is available if it is available" in
  new AuthenticatorFixture {
      val isEmailAvailableMessage: IsEmailAvailableMessage = new IsEmailAvailableMessage {
        override val email: String = emailAddress
        override val iD: UUID = originatingMessageUUID
      }

      Seq(true, false).foreach { isEmailAvailability =>
        resetUUID()
        (registrationAPI.isEmailIsAvailable _).expects(emailAddress).returning(isEmailAvailability)
        authenticator ! isEmailAvailableMessage
        expectMsg(emailIsAvailableMessage(
            newMessageUUID, Some(originatingMessageUUID), emailAddress, isEmailAvailability).toJSON)
      }

   }

  it should "indicate whether a username is available" in new AuthenticatorFixture {
    val usernameToCheck = "some-user-name"
    val isUsernameAvailableMessage: IsUsernameAvailableMessage = new IsUsernameAvailableMessage {
      override val username: String = usernameToCheck
      override val iD: UUID = originatingMessageUUID
    }

    Seq(true, false).foreach { isUsernameAvailability =>
      resetUUID()
      (registrationAPI.isUsernameIsAvailable _).expects(usernameToCheck).returning(isUsernameAvailability)
      authenticator ! isUsernameAvailableMessage
      expectMsg(usernameIsAvailableMessage(
          newMessageUUID, Some(originatingMessageUUID), usernameToCheck, isUsernameAvailability).toJSON)
    }
  }

  it should "switch the receive function to the authenticated receive function only if the user presents a valid JWT" in
  new AuthenticatorFixture {
    val authenticateMeMessage: AuthenticateMeMessage = new AuthenticateMeMessage {
      override val jWT: String = aJWT
      override val iD: UUID = originatingMessageUUID
    }

    resetUUID()
    authenticator ! authenticateMeMessage
    expectMsg(loggingYouOutMessage(newMessageUUID, Some(originatingMessageUUID)).toJSON)

    resetUUID()
    tokenValidator.result = Some(userContact)
    (messageRouterPropsCreator.props _).expects(*, *, *, *, *).returning(DummyActor.props)
    authenticator ! authenticateMeMessage
    expectMsg(authenticationSuccessfulMessage(secondNewMessageUUID, Some(originatingMessageUUID)).toJSON)
  }

  it should "return a JWT if login credentials are correct, and error response otherwise" in new AuthenticatorFixture {
    val aPassword = "a-password"
    val logMeInMessage = new LogMeInMessage {
      override val maybeEmail: Option[String] = Some(emailAddress)
      override val maybeUsername: Option[String] = None
      override val password: String = aPassword
      override val iD: UUID = generalUUID
    }

    (authenticationAPI.user(_: Option[String], _: Option[String], _: String))
      .expects(None, Some(emailAddress), aPassword).returning(None)
    resetUUID()
    authenticator ! logMeInMessage
    expectMsg(yourLoginAttemptFailedMessage(newMessageUUID, Some(originatingMessageUUID)).toJSON)

    val userDetails = new UserDetails[String] {
      override val userID: UUID = userContact.userID
      override val email: String = userContact.email
      override val username: String = userContact.username
      override val userStatus: String = "user"
    }

    (authenticationAPI.user(_: Option[String], _: Option[String], _: String))
      .expects(None, Some(emailAddress), aPassword).returning(Some(userDetails))
    (jWTCreator.create _).expects(userDetails, timeProvider.now()).returning(aJWT)
    authenticator ! logMeInMessage
    expectMsg(
      yourLoginAttemptSucceededMessage(
        newMessageUUID, Some(originatingMessageUUID), userContact.username, userContact.email, aJWT).toJSON)
  }

}
