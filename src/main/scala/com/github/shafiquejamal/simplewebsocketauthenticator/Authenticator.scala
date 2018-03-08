package com.github.shafiquejamal.simplewebsocketauthenticator

import java.util.UUID

import akka.actor.{Actor, ActorLogging, ActorRef, Props}
import com.github.shafiquejamal.accessapi.access.authentication.{AuthenticationAPI, JWTCreator, TokenValidator}
import com.github.shafiquejamal.accessapi.access.registration.{AccountActivationCodeSender, RegistrationAPI, UserActivator}
import com.github.shafiquejamal.accessapi.user.{UserAPI, UserDetails}
import com.github.shafiquejamal.accessmessage.InBound._
import com.github.shafiquejamal.accessmessage.OutBound._
import com.github.shafiquejamal.util.id.UUIDProvider
import com.github.shafiquejamal.util.time.JavaInstantTimeProvider

import scala.util.{Failure, Success}

class Authenticator[US, UD <: UserDetails[US], J] (
    userTokenValidator: TokenValidator[US, UD],
    userAPI: UserAPI[UD],
    authenticationAPI: AuthenticationAPI[UD],
    registrationAPI: RegistrationAPI[UD, US],
    jWTCreator: JWTCreator[UD],
    timeProvider: JavaInstantTimeProvider,
    uUIDProvider: UUIDProvider,
    unnamedClient: ActorRef,
    passwordResetCodeRequestActions: PasswordResetCodeRequestActions[UD],
    accountActivationCodeSender:AccountActivationCodeSender[UD, US],
    logMeOutMessage: UUID => LogMeOutMessage,
    yourLoginAttemptFailedMessage: (UUID, Option[UUID]) => YourLoginAttemptFailedMessage[J],
    yourLoginAttemptSucceededMessage: (UUID, Option[UUID], String, String, String) => YourLoginAttemptSucceededMessage[J],
    passwordResetCodeSentMessage: (UUID, Option[UUID]) => PasswordResetCodeSentMessage[J],
    passwordResetSuccessfulMessage: (UUID, Option[UUID]) => PasswordResetSuccessfulMessage[J],
    passwordResetFailedMessage: (UUID, Option[UUID]) => PasswordResetFailedMessage[J],
    emailIsAvailableMessage: (UUID, Option[UUID], String, Boolean) => EmailIsAvailableMessage[J],
    usernameIsAvailableMessage: (UUID, Option[UUID], String, Boolean) => UsernameIsAvailableMessage[J],
    yourRegistrationAttemptFailedMessage: (UUID, Option[UUID]) => YourRegistrationAttemptFailedMessage[J],
    yourRegistrationAttemptSucceededMessage: (UUID, Option[UUID]) => YourRegistrationAttemptSucceededMessage[J],
    accountActivationAttemptFailedMessage: (UUID, Option[UUID], String) => AccountActivationAttemptFailedMessage[J],
    accountActivationCodeCreator: AccountActivationCodeCreator,
    resendActivationCodeResultMessage: (UUID, Option[UUID], String) => ResendActivationCodeResultMessage[J],
    userActivator: UserActivator[UD, AccountActivationAttemptResultMessage[J]],
    youAreAlreadyAuthenticatedMessage: (UUID, Option[UUID]) => YouAreAlreadyAuthenticatedMessage[J],
    loggingYouOutMessage: (UUID, Option[UUID]) => LoggingYouOutMessage[J],
    clientPaths: ClientPaths,
    changePasswordFailedMessage: (UUID, Option[UUID]) => ChangePasswordFailedMessage[J],
    changePasswordSucceededMessage: (UUID, Option[UUID]) => ChangePasswordSucceededMessage[J],
    messageRouterPropsCreator: MessageRouterPropsCreator,
    namedClientProps: (ActorRef, ActorRef) => Props,
    requestChangeEmailFailedMessage: (UUID, Option[UUID]) => RequestChangeEmailFailedMessage[J],
    requestChangeEmailSucceededMessage: (UUID, Option[UUID]) => RequestChangeEmailSucceededMessage[J],
    activateNewEmailFailedMessage: (UUID, Option[UUID]) => ActivateNewEmailFailedMessage[J],
    activateNewEmailSucceededMessage: (UUID, Option[UUID]) => ActivateNewEmailSucceededMessage[J],
    authenticationSuccessfulMessage: (UUID, Option[UUID]) => AuthenticationSuccessfulMessage[J])
  extends Actor with ActorLogging {

  override def receive: Receive = {

    case authenticateMeMessage: AuthenticateMeMessage =>
      val maybeValidUser = userTokenValidator.decodeAndValidateToken(authenticateMeMessage.jWT)

      maybeValidUser.fold {
        val response = loggingYouOutMessage(uUIDProvider.randomUUID(), Some(authenticateMeMessage.iD))
        unnamedClient ! response.toJSON
        log.info("Authenticator", authenticateMeMessage, response)
      } { userDetails =>
        createNamedClientAndRouter(userDetails.userID, userDetails.username, userDetails.email)
        val response = authenticationSuccessfulMessage(uUIDProvider.randomUUID(), Some(authenticateMeMessage.iD))
        unnamedClient ! response.toJSON
        log.info("Authenticator", authenticateMeMessage, response)
      }

    case logMeInMessage: LogMeInMessage =>
      val maybeUserDetails =
        authenticationAPI.user(
            logMeInMessage.maybeUsername,
            logMeInMessage.maybeEmail,
            logMeInMessage.password)

      val response = maybeUserDetails
        .fold[LoginAttemptResultMessage[J]](
          yourLoginAttemptFailedMessage(uUIDProvider.randomUUID(), Some(logMeInMessage.iD))){ userDetails =>
        val jWT = jWTCreator.create(userDetails, timeProvider.now())
        yourLoginAttemptSucceededMessage(
            uUIDProvider.randomUUID(), Some(logMeInMessage.iD), userDetails.username, userDetails.email, jWT)
      }

      unnamedClient ! response.toJSON
      log.info("Authenticator", logMeInMessage, response)

    case passwordResetCodeRequestMessage: PasswordResetCodeRequestMessage =>
      val maybeUser = userAPI findByEmailLatest passwordResetCodeRequestMessage.email
      maybeUser.fold[Unit](){ userDetails => passwordResetCodeRequestActions sendUsing userDetails }
      val response = passwordResetCodeSentMessage(uUIDProvider.randomUUID(), Some(passwordResetCodeRequestMessage.iD))
      unnamedClient ! response.toJSON
      log.info("Authenticator", passwordResetCodeRequestMessage, response)

    case resetPasswordMessage: ResetMyPasswordMessage =>
      val response = authenticationAPI
        .resetPassword(
          resetPasswordMessage.email,
          resetPasswordMessage.code.replaceAll("-", ""),
          resetPasswordMessage.newPassword) match {
        case Success(userDetails) =>
          passwordResetSuccessfulMessage(uUIDProvider.randomUUID(), Some(resetPasswordMessage.iD))
        case Failure(_) =>
          passwordResetFailedMessage(uUIDProvider.randomUUID(), Some(resetPasswordMessage.iD))
      }
      unnamedClient ! response.toJSON
      log.info("Authenticator", resetPasswordMessage, response)

    case isEmailAvailableMessage : IsEmailAvailableMessage =>
      val isEmailAvailable: Boolean = registrationAPI.isEmailIsAvailable(isEmailAvailableMessage.email)
      val response = emailIsAvailableMessage(
        uUIDProvider.randomUUID(), Some(isEmailAvailableMessage.iD), isEmailAvailableMessage.email, isEmailAvailable)
      unnamedClient ! response.toJSON
      log.info("Authenticator", isEmailAvailableMessage, response)

    case isUsernameAvailableMessage: IsUsernameAvailableMessage =>
      val isUsernameAvailable: Boolean = registrationAPI.isUsernameIsAvailable(isUsernameAvailableMessage.username)
      val response = usernameIsAvailableMessage(
        uUIDProvider.randomUUID(), Some(isUsernameAvailableMessage.iD), isUsernameAvailableMessage.username, isUsernameAvailable)
      unnamedClient ! response.toJSON
      log.info("Authenticator", isUsernameAvailableMessage, response)

    case registerMeMessage: RegisterMeMessage =>
      val maybeUserDetails =
        registrationAPI.signUp(
            registerMeMessage.maybeUsername, registerMeMessage.email, registerMeMessage.password,
            accountActivationCodeSender.statusOnRegistration)
      val response = maybeUserDetails
        .toOption.fold[RegistrationAttemptResultMessage[J]](
            yourRegistrationAttemptFailedMessage(uUIDProvider.randomUUID(), Some(registerMeMessage.iD))
        ){ userDetails =>
          val activationCode = accountActivationCodeCreator.generate(userDetails.userID.toString)
          accountActivationCodeSender.sendActivationCode(userDetails.username, userDetails.email, activationCode)
          yourRegistrationAttemptSucceededMessage(uUIDProvider.randomUUID(), Some(registerMeMessage.iD))
      }
      unnamedClient ! response.toJSON

    case activateMyAccountMessage: ActivateMyAccountMessage =>
      val (email, code) = (activateMyAccountMessage.emailOrUsername, activateMyAccountMessage.code)

      val response = userAPI.findByEmailLatest(email).fold[AccountActivationAttemptResultMessage[J]](
        accountActivationAttemptFailedMessage(uUIDProvider.randomUUID(), Some(activateMyAccountMessage.iD),
          "User does not exist")
      ) { user: UD =>
        if (accountActivationCodeCreator.isMatch(user.userID.toString, code)) {
          userActivator.activateUser(user, Some(activateMyAccountMessage.iD))
        } else {
          accountActivationAttemptFailedMessage(uUIDProvider.randomUUID(), Some(activateMyAccountMessage.iD),
            "Incorrect code")
        }
      }

      unnamedClient ! response.toJSON

    case resendMyActivationCodeMessage: ResendMyActivationCodeMessage =>
      val response =
        userAPI.findUnverifiedUser(resendMyActivationCodeMessage.email).fold[ResendActivationCodeResultMessage[J]](
          resendActivationCodeResultMessage(uUIDProvider.randomUUID(), Some(resendMyActivationCodeMessage.iD),
          "User not registered or already verified")
      ) { userDetails =>
          val activationCode = accountActivationCodeCreator.generate(userDetails.userID.toString)
          accountActivationCodeSender.sendActivationCode(userDetails.username, userDetails.email, activationCode)
        resendActivationCodeResultMessage(uUIDProvider.randomUUID(), Some(resendMyActivationCodeMessage.iD),
          "Code sent")
      }
      unnamedClient ! response.toJSON

  }

  def processAuthenticatedRequests(clientUserID: UUID, email: String, messageRouter: ActorRef): Receive = {

    case m: AuthenticateMeMessage  =>
      val response = youAreAlreadyAuthenticatedMessage(uUIDProvider.randomUUID(), Some(m.iD))
      unnamedClient ! response.toJSON
      log.info("Authenticator", m, response)
      
    case m: LogMeInMessage =>
      val response = youAreAlreadyAuthenticatedMessage(uUIDProvider.randomUUID(), Some(m.iD))
      unnamedClient ! response.toJSON
      log.info("Authenticator", m, response)

    case m: LogMeOutMessage =>
      val response = loggingYouOutMessage(uUIDProvider.randomUUID(), Some(m.iD))
      unnamedClient ! response.toJSON
      log.info("Authenticator", m, response)
      context.unbecome()

    case m: LogMeOutOfAllDevicesMessage =>
      authenticationAPI logoutAllDevices clientUserID
      val allAuthenticatorsForThisUser = context.actorSelection(clientPaths.namedClientPath(clientUserID))
      allAuthenticatorsForThisUser ! logMeOutMessage(uUIDProvider.randomUUID())

    case changePasswordMessage: ChangeMyPasswordMessage =>
      val maybeUser = authenticationAPI.user(clientUserID, changePasswordMessage.currentPassword)
      val maybeUserDetails = maybeUser.flatMap { _ =>
        userAPI.changePassword(clientUserID, changePasswordMessage.newPassword).toOption
      }

      val response = maybeUserDetails.fold[ChangePasswordAttemptResultMessage[J]](
          changePasswordFailedMessage(uUIDProvider.randomUUID(), Some(changePasswordMessage.iD))){ _ =>
        changePasswordSucceededMessage(uUIDProvider.randomUUID(), Some(changePasswordMessage.iD)) }
      context.unbecome()

      unnamedClient ! response.toJSON

    case requestChangeEmailMessage: RequestChangeEmailMessage =>
      userAPI.requestChangeEmail(clientUserID, requestChangeEmailMessage.newEmail) match {
        case Success(_) =>
          unnamedClient ! requestChangeEmailSucceededMessage(uUIDProvider.randomUUID(),
            Some(requestChangeEmailMessage.iD)).toJSON
        case Failure(_) =>
          unnamedClient ! requestChangeEmailFailedMessage(uUIDProvider.randomUUID(),
            Some(requestChangeEmailMessage.iD)).toJSON
      }

    case activateNewEmailMessage: ActivateNewEmailMessage =>
      userAPI
      .activateNewEmail(clientUserID, email, activateNewEmailMessage.newEmail, activateNewEmailMessage.code) match {
        case Success(_) =>
          unnamedClient ! activateNewEmailSucceededMessage(uUIDProvider.randomUUID(),
            Some(activateNewEmailMessage.iD)).toJSON
        case Failure(_) =>
          unnamedClient ! activateNewEmailFailedMessage(uUIDProvider.randomUUID(),
            Some(activateNewEmailMessage.iD)).toJSON
      }

    case msg =>
      messageRouter ! msg
  }

  private def createNamedClientAndRouter(clientId: UUID, clientUsername: String, email: String): Unit = {
    val namedClient =
      context.actorOf(
        namedClientProps(unnamedClient, self), clientPaths.namedClientActorName(clientId, uUIDProvider.randomUUID()))
    val messageRouter =
      context.actorOf(
        messageRouterPropsCreator.props(
          namedClient, clientId, clientUsername, timeProvider, uUIDProvider))
    context.become(processAuthenticatedRequests(clientId, email, messageRouter))
  }

}

object Authenticator {

  def props[US, UD <: UserDetails[US], J](
      userTokenValidator: TokenValidator[US, UD],
      userAPI: UserAPI[UD],
      authenticationAPI: AuthenticationAPI[UD],
      registrationAPI: RegistrationAPI[UD, US],
      jWTCreator: JWTCreator[UD],
      timeProvider: JavaInstantTimeProvider,
      uUIDProvider: UUIDProvider,
      unnamedClient: ActorRef,
      passwordResetCodeRequestActions: PasswordResetCodeRequestActions[UD],
      accountActivationCodeSender:AccountActivationCodeSender[UD, US],
      logMeOutMessage: UUID => LogMeOutMessage,
      yourLoginAttemptFailedMessage: (UUID, Option[UUID]) => YourLoginAttemptFailedMessage[J],
      yourLoginAttemptSucceededMessage: (UUID, Option[UUID], String, String, String) => YourLoginAttemptSucceededMessage[J],
      passwordResetCodeSentMessage: (UUID, Option[UUID]) => PasswordResetCodeSentMessage[J],
      passwordResetSuccessfulMessage: (UUID, Option[UUID]) => PasswordResetSuccessfulMessage[J],
      passwordResetFailedMessage: (UUID, Option[UUID]) => PasswordResetFailedMessage[J],
      emailIsAvailableMessage: (UUID, Option[UUID], String, Boolean) => EmailIsAvailableMessage[J],
      usernameIsAvailableMessage: (UUID, Option[UUID], String, Boolean) => UsernameIsAvailableMessage[J],
      yourRegistrationAttemptFailedMessage: (UUID, Option[UUID]) => YourRegistrationAttemptFailedMessage[J],
      yourRegistrationAttemptSucceededMessage: (UUID, Option[UUID]) => YourRegistrationAttemptSucceededMessage[J],
      accountActivationAttemptFailedMessage: (UUID, Option[UUID], String) => AccountActivationAttemptFailedMessage[J],
      accountActivationCodeCreator: AccountActivationCodeCreator,
      resendActivationCodeResultMessage: (UUID, Option[UUID], String) => ResendActivationCodeResultMessage[J],
      userActivator: UserActivator[UD, AccountActivationAttemptResultMessage[J]],
      youAreAlreadyAuthenticatedMessage: (UUID, Option[UUID]) => YouAreAlreadyAuthenticatedMessage[J],
      loggingYouOutMessage: (UUID, Option[UUID]) => LoggingYouOutMessage[J],
      clientPaths: ClientPaths,
      changePasswordFailedMessage: (UUID, Option[UUID]) => ChangePasswordFailedMessage[J],
      changePasswordSucceededMessage: (UUID, Option[UUID]) => ChangePasswordSucceededMessage[J],
      messageRouterPropsCreator: MessageRouterPropsCreator,
      namedClientProps: (ActorRef, ActorRef) => Props,
      requestChangeEmailFailedMessage: (UUID, Option[UUID]) => RequestChangeEmailFailedMessage[J],
      requestChangeEmailSucceededMessage: (UUID, Option[UUID]) => RequestChangeEmailSucceededMessage[J],
      activateNewEmailFailedMessage: (UUID, Option[UUID]) => ActivateNewEmailFailedMessage[J],
      activateNewEmailSucceededMessage: (UUID, Option[UUID]) => ActivateNewEmailSucceededMessage[J],
      authenticationSuccessfulMessage: (UUID, Option[UUID]) => AuthenticationSuccessfulMessage[J]) =
    Props(
      new Authenticator(
        userTokenValidator,
        userAPI,
        authenticationAPI,
        registrationAPI,
        jWTCreator,
        timeProvider,
        uUIDProvider,
        unnamedClient,
        passwordResetCodeRequestActions,
        accountActivationCodeSender,
        logMeOutMessage,
        yourLoginAttemptFailedMessage,
        yourLoginAttemptSucceededMessage,
        passwordResetCodeSentMessage,
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
