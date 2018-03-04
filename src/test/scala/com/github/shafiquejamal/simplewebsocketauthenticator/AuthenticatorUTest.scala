package com.github.shafiquejamal.simplewebsocketauthenticator

import java.util.UUID

import akka.actor.{Actor, ActorRef, ActorSystem, Props}
import akka.testkit.TestKit
import com.github.shafiquejamal.accessapi.access.authentication.{AuthenticationAPI, JWTCreator, TokenValidator}
import com.github.shafiquejamal.accessapi.access.registration.{AccountActivationCodeSender, RegistrationAPI, UserActivator}
import com.github.shafiquejamal.accessapi.user.{UserAPI, UserContact, UserDetails}
import com.github.shafiquejamal.accessmessage.InBound._
import com.github.shafiquejamal.accessmessage.OutBound.AccountActivationAttemptResultMessage
import com.github.shafiquejamal.simplewebsocketauthenticator.AuthenticatorMessagesFixture._
import com.github.shafiquejamal.util.id.TestUUIDProviderImpl
import com.github.shafiquejamal.util.time.TestJavaInstantTimeProvider
import org.scalamock.scalatest.MockFactory
import org.scalatest.{BeforeAndAfterAll, FlatSpecLike, Matchers}

import scala.util.{Failure, Success}

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
    val aPassword = "a-password"
    val userContact = new UserContact {
      override val userID: UUID = generalUUID
      override val email: String = "some-email"
      override val username: String = "some-username"
    }
    val aJWT = "some-JWT"
    val userDetails = new UserDetails[String] {
      override val userID: UUID = userContact.userID
      override val email: String = userContact.email
      override val username: String = userContact.username
      override val userStatus: String = "user"
    }
    val activationCode = "anActivationCode"
    val authenticateMeMessage: AuthenticateMeMessage = new AuthenticateMeMessage {
      override val jWT: String = aJWT
      override val iD: UUID = originatingMessageUUID
    }
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
  
    def authenticateUser() {
      resetUUID()
      tokenValidator.result = Some(userContact)
      (messageRouterPropsCreator.props _).expects(*, *, *, *, *).returning(DummyActor.props).anyNumberOfTimes()
      authenticator ! authenticateMeMessage
      expectMsg(authenticationSuccessfulMessage(secondNewMessageUUID, Some(originatingMessageUUID)).toJSON)
    }
  
  }
  
  trait InBoundMessages {
  
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
    resetUUID()
    authenticator ! authenticateMeMessage
    expectMsg(loggingYouOutMessage(newMessageUUID, Some(originatingMessageUUID)).toJSON)

    authenticateUser()
  }

  it should "return a JWT if login credentials are correct, and error response otherwise" in new AuthenticatorFixture {
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

    (authenticationAPI.user(_: Option[String], _: Option[String], _: String))
      .expects(None, Some(emailAddress), aPassword).returning(Some(userDetails))
    (jWTCreator.create _).expects(userDetails, timeProvider.now()).returning(aJWT)
    authenticator ! logMeInMessage
    expectMsg(
      yourLoginAttemptSucceededMessage(
        newMessageUUID, Some(originatingMessageUUID), userContact.username, userContact.email, aJWT).toJSON)
  }

  it should "send a password reset code if requested for a user's email that exists" in new AuthenticatorFixture {

    (userAPI.findByEmailLatest _).expects(emailAddress).returning(None)
    val passwordResetCodeRequestMessage = new PasswordResetCodeRequestMessage {
      override def email: String = emailAddress
      override def iD: UUID = userContact.userID
    }
    resetUUID()
    authenticator ! passwordResetCodeRequestMessage
    expectMsg(passwordResetCodeMessageSent(newMessageUUID, Some(originatingMessageUUID)).toJSON)

    resetUUID()
    (userAPI.findByEmailLatest _).expects(emailAddress).returning(Some(userDetails))
    (passwordResetCodeRequestActions.sendUsing _).expects(userDetails).returning(Unit)
    authenticator ! passwordResetCodeRequestMessage
    expectMsg(passwordResetCodeMessageSent(newMessageUUID, Some(originatingMessageUUID)).toJSON)
  }

  it should "reset a users password if the submitted code is correct" in new AuthenticatorFixture {
    val aNewPassword = "newPassword"
    val aCode = "a-code"
    val resetPasswordMessage = new ResetMyPasswordMessage {
      override def code: String = aCode

      override def newPassword: String = aNewPassword

      override def email: String = userDetails.email

      override def iD: UUID = userDetails.userID
    }

    resetUUID()
    (authenticationAPI.resetPassword _).expects(userDetails.email, aCode.replaceAll("-", ""), aNewPassword)
      .returning(Failure(new Exception("failure")))
    authenticator ! resetPasswordMessage
    expectMsg(passwordResetFailedMessage(newMessageUUID, Some(originatingMessageUUID)).toJSON)

    resetUUID()
    (authenticationAPI.resetPassword _).expects(userDetails.email, aCode.replaceAll("-", ""), aNewPassword)
      .returning(Success(userDetails))
    authenticator ! resetPasswordMessage
    expectMsg(passwordResetSuccessfulMessage(newMessageUUID, Some(originatingMessageUUID)).toJSON)
  }
  
  it should "process a user's registration request" in new AuthenticatorFixture {
    val registerMeMessage = new RegisterMeMessage {
      override val iD = originatingMessageUUID
      override val maybeUsername = Some(userDetails.username)
      override val email = userDetails.email
      override val password = aPassword
    }
    val statusOnRegistration = "aStatusOnRegistration"
    
    resetUUID()
    (accountActivationCodeSender.statusOnRegistration _).expects().returning(statusOnRegistration)
    (accountActivationCodeCreator.generate _).expects(userDetails.userID.toString).returning(activationCode)
    (accountActivationCodeSender.sendActivationCode _).expects(userDetails.username, userDetails.email, activationCode)
    (registrationAPI.signUp _).expects(registerMeMessage.maybeUsername, registerMeMessage.email, registerMeMessage.password, statusOnRegistration).returning(Success(userDetails))
    authenticator ! registerMeMessage
    expectMsg(yourRegistrationAttemptSucceededMessage(newMessageUUID, Some(originatingMessageUUID)).toJSON)
    
    resetUUID()
    (accountActivationCodeSender.statusOnRegistration _).expects().returning(statusOnRegistration)
    (registrationAPI.signUp _).expects(registerMeMessage.maybeUsername, registerMeMessage.email, registerMeMessage.password, statusOnRegistration).returning(Failure(new Exception("--")))
    authenticator ! registerMeMessage
    expectMsg(yourRegistrationAttemptFailedMessage(newMessageUUID, Some(originatingMessageUUID)).toJSON)
  }
  
  it should "activate a user's account if the correct activation code is given" in new AuthenticatorFixture {
    val activateMyAccountMessage = new ActivateMyAccountMessage {
      override val code: String = activationCode
      override val emailOrUsername: String = userDetails.email
      override val iD: UUID = originatingMessageUUID
    }
    
    resetUUID()
    (userAPI.findByEmailLatest _).expects(activateMyAccountMessage.emailOrUsername).returning(None)
    authenticator ! activateMyAccountMessage
    expectMsg(accountActivationAttemptFailedMessage(newMessageUUID, Some(originatingMessageUUID), "User does not exist").toJSON)
  
    resetUUID()
    (userAPI.findByEmailLatest _).expects(activateMyAccountMessage.emailOrUsername).returning(Some(userDetails))
    (accountActivationCodeCreator.isMatch _).expects(userDetails.userID.toString, activationCode).returning(false)
    authenticator ! activateMyAccountMessage
    expectMsg(accountActivationAttemptFailedMessage(newMessageUUID, Some(originatingMessageUUID), "Incorrect code").toJSON)
  
    resetUUID()
    (userAPI.findByEmailLatest _).expects(activateMyAccountMessage.emailOrUsername).returning(Some(userDetails))
    (accountActivationCodeCreator.isMatch _).expects(userDetails.userID.toString, activationCode).returning(true)
    val successMessage = accountActivationAttemptSucceededMessage(newMessageUUID, Some(originatingMessageUUID))
    (userActivator.activateUser _).expects(userDetails, activationCode).returning(successMessage)
    authenticator ! activateMyAccountMessage
    expectMsg(successMessage.toJSON)
  }
  
  it should "resend an activation code for users that have registered but whose account has not been activated" in new AuthenticatorFixture {
    val resendMyActivationCodeMessage = new ResendMyActivationCodeMessage {
      override val email: String = userDetails.email
      override val iD: UUID = originatingMessageUUID
    }
    
    resetUUID()
    (userAPI.findUnverifiedUser _).expects(resendMyActivationCodeMessage.email).returning(None)
    authenticator ! resendMyActivationCodeMessage
    expectMsg(resendActivationCodeResultMessage(newMessageUUID, Some(originatingMessageUUID), "User not registered or already verified").toJSON)
  
    resetUUID()
    (userAPI.findUnverifiedUser _).expects(resendMyActivationCodeMessage.email).returning(Some(userDetails))
    (accountActivationCodeCreator.generate _).expects(userDetails.userID.toString).returning(activationCode)
    (accountActivationCodeSender.sendActivationCode _).expects(userDetails.username, userDetails.email, activationCode)
    authenticator ! resendMyActivationCodeMessage
    expectMsg(resendActivationCodeResultMessage(newMessageUUID, Some(originatingMessageUUID), "Code sent").toJSON)
  }
  
  "For authenticated users, the authenticator" should "indicate that the user is already logged in if the user" +
  " attempts to log in or authenticate" in new AuthenticatorFixture {
  
    authenticateUser()
    resetUUID()
    authenticator ! authenticateMeMessage
    expectMsg(youAreAlreadyAuthenticatedMessage(newMessageUUID, Some(originatingMessageUUID)).toJSON)

    resetUUID()
  
  }
}
