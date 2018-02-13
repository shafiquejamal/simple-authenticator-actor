package com.github.shafiquejamal.simplewebsocketauthenticator

import java.util.UUID

import akka.actor.{Actor, ActorLogging, ActorRef, Props}
import com.github.shafiquejamal.accessapi.access.authentication.{AuthenticationAPI, JWTCreator, PasswordResetCodeSender, TokenValidator}
import com.github.shafiquejamal.accessapi.access.registration.{AccountActivationCodeSender, RegistrationAPI, UserActivator}
import com.github.shafiquejamal.accessapi.user.{UserAPI, UserDetails}
import com.github.shafiquejamal.accessmessage.InBound._
import com.github.shafiquejamal.accessmessage.OutBound._
import com.github.shafiquejamal.util.id.UUIDProvider
import com.github.shafiquejamal.util.time.JavaInstantTimeProvider

import scala.util.{Failure, Success}

class Authenticator[US, R, J] (
    userTokenValidator: TokenValidator,
    userAPI: UserAPI[UserDetails[US]],
    authenticationAPI: AuthenticationAPI[UserDetails[US]],
    registrationAPI: RegistrationAPI[UserDetails[US], US],
    jWTCreator: JWTCreator[UserDetails[US]],
    timeProvider: JavaInstantTimeProvider,
    uUIDProvider: UUIDProvider,
    unnamedClient: ActorRef,
    passwordResetCodeSender: PasswordResetCodeSender[UserDetails[US], R],
    accountActivationCodeSender:AccountActivationCodeSender[UserDetails[US], US],
    toServerMessageRouter: ActorRef,
    logMeOutMessage: LogMeOutMessage,
    yourLoginAttemptFailedMessage: YourLoginAttemptFailedMessage[J],
    yourLoginAttemptSucceededMessage: (String, String, String) => YourLoginAttemptSucceededMessage[J],
    passwordResetActions: UserDetails[US] => Unit,
    passwordResetCodeSentMessage: PasswordResetCodeSentMessage[J],
    passwordResetSuccessfulMessage: PasswordResetSuccessfulMessage[J],
    passwordResetFailedMessage: PasswordResetFailedMessage[J],
    emailIsAvailableMessage: (String, Boolean) => EmailIsAvailableMessage[J],
    usernameIsAvailableMessage: (String, Boolean) => UsernameIsAvailableMessage[J],
    yourRegistrationAttemptFailedMessage: YourRegistrationAttemptFailedMessage[J],
    yourRegistrationAttemptSucceededMessage: YourRegistrationAttemptSucceededMessage[J],
    activationCodeKey: String,
    accountActivationAttemptFailedMessage: String => AccountActivationAttemptFailedMessage[J],
    accountActivationAttemptSucceededMessage: AccountActivationAttemptSucceededMessage[J],
    accountActivationCodeCreator: AccountActivationCodeCreator,
    resendActivationCodeResultMessage: String => ResendActivationCodeResultMessage[J],
    userActivator: UserActivator[UserDetails[US], AccountActivationAttemptResultMessage[J]],
    youAreAlreadyAuthenticatedMessage: YouAreAlreadyAuthenticatedMessage[J],
    loggingYouOutMessage: LoggingYouOutMessage[J],
    clientPaths: ClientPaths,
    changePasswordFailedMessage: ChangePasswordFailedMessage[J],
    changePasswordSucceededMessage: ChangePasswordSucceededMessage[J],
    messageRouterPropsCreator: MessageRouterPropsCreator,
    namedClientProps: (ActorRef, ActorRef) => Props,
    requestChangeEmailFailedMessage: RequestChangeEmailFailedMessage[J],
    requestChangeEmailSucceededMessage: RequestChangeEmailSucceededMessage[J],
    activateNewEmailFailedMessage: ActivateNewEmailFailedMessage[J],
    activateNewEmailSucceededMessage: ActivateNewEmailSucceededMessage[J])
  extends Actor with ActorLogging {

  override def receive: Receive = {

    case authenticateMeMessage: AuthenticateMeMessage =>
      val maybeValidUser = userTokenValidator.decodeAndValidateToken(
        authenticateMeMessage.jWT,
        userTokenValidator.blockToExecuteIfAuthorized,
        userTokenValidator.blockToExecuteIfUnauthorized)

      maybeValidUser.fold {
        unnamedClient ! loggingYouOutMessage.add(authenticateMeMessage).toJSON
      } { userContact => createNamedClientAndRouter(userContact.userID, userContact.username, userContact.email) }

    case logMeInMessage: LogMeInMessage =>
      val maybeUserDetails =
        authenticationAPI.user(
            logMeInMessage.maybeUsername,
            logMeInMessage.maybeEmail,
            logMeInMessage.password)

      val response = maybeUserDetails.fold[LoginAttemptResultMessage[J]](yourLoginAttemptFailedMessage){ userDetails =>
        val jWT = jWTCreator.create(userDetails, timeProvider.now())
        yourLoginAttemptSucceededMessage(userDetails.username, userDetails.email, jWT)
      }

      unnamedClient ! response.add(logMeInMessage).toJSON

    case passwordResetCodeRequestMessage: PasswordResetCodeRequestMessage =>
      val maybeUser = userAPI.findByEmailLatest(passwordResetCodeRequestMessage.email)
      maybeUser.fold[Unit](){ userDetails => passwordResetActions(userDetails) }
      unnamedClient ! passwordResetCodeSentMessage.add(passwordResetCodeRequestMessage).toJSON

    case resetPasswordMessage: ResetMyPasswordMessage =>
      authenticationAPI
        .resetPassword(
          resetPasswordMessage.email,
          resetPasswordMessage.code.replaceAll("-", ""),
          resetPasswordMessage.newPassword) match {
        case Success(user) =>
          unnamedClient ! passwordResetSuccessfulMessage.add(resetPasswordMessage).toJSON
        case Failure(_) =>
          unnamedClient ! passwordResetFailedMessage.add(resetPasswordMessage).toJSON
      }

    case isEmailAvailableMessage : IsEmailAvailableMessage =>
      val isEmailAvailable: Boolean = registrationAPI.isEmailIsAvailable(isEmailAvailableMessage.email)
      unnamedClient ! emailIsAvailableMessage(isEmailAvailableMessage.email, isEmailAvailable).add(isEmailAvailableMessage).toJSON

    case isUsernameAvailableMessage: IsUsernameAvailableMessage =>
      val isUsernameAvailable: Boolean = registrationAPI.isUsernameIsAvailable(isUsernameAvailableMessage.username)
      unnamedClient ! usernameIsAvailableMessage(isUsernameAvailableMessage.username, isUsernameAvailable).add(isUsernameAvailableMessage).toJSON

    case registerMeMessage: RegisterMeMessage =>
      val maybeUserDetails =
        registrationAPI.signUp(
            registerMeMessage.maybeUsername, registerMeMessage.email, registerMeMessage.password,
            accountActivationCodeSender.statusOnRegistration)
      val response = maybeUserDetails
        .toOption.fold[RegistrationAttemptResultMessage[J]](yourRegistrationAttemptFailedMessage){ userDetails =>
          val activationCode = accountActivationCodeCreator.generate(userDetails.userID.toString, activationCodeKey)
          accountActivationCodeSender.sendActivationCode(userDetails.username, userDetails.email, activationCode)
          yourRegistrationAttemptSucceededMessage
      }
      unnamedClient ! response.add(registerMeMessage).toJSON

    case activateMyAccountMessage: ActivateMyAccountMessage =>
      val (email, code) = (activateMyAccountMessage.emailOrUsername, activateMyAccountMessage.code)

      val response = userAPI.findByEmailLatest(email).fold[AccountActivationAttemptResultMessage[J]](
        accountActivationAttemptFailedMessage("User does not exist")
      ) { user: UserDetails[US] =>
        if (accountActivationCodeCreator.isMatch(user.userID.toString, code, activationCodeKey)) {
          userActivator.activateUser(user, code)
        } else {
          accountActivationAttemptFailedMessage("Incorrect code")
        }
      }

      unnamedClient ! response.add(activateMyAccountMessage).toJSON

    case resendMyActivationCodeMessage: ResendMyActivationCodeMessage =>
      val response = userAPI.findUnverifiedUser(resendMyActivationCodeMessage.email).fold[ResendActivationCodeResultMessage[J]](
        resendActivationCodeResultMessage("User not registered or already verified")
      ) { user =>
        accountActivationCodeSender.sendActivationCode(user.username, user.email, activationCodeKey)
        resendActivationCodeResultMessage("Code sent")
      }
      unnamedClient ! response.add(resendMyActivationCodeMessage).toJSON

  }

  def processAuthenticatedRequests(clientUserID: UUID, email: String, messageRouter: ActorRef): Receive = {

    case m: AuthenticateMeMessage  =>
      unnamedClient ! youAreAlreadyAuthenticatedMessage.add(m).toJSON

    case m: LogMeInMessage =>
      unnamedClient ! youAreAlreadyAuthenticatedMessage.add(m).toJSON

    case m: LogMeOutMessage =>
      unnamedClient ! loggingYouOutMessage.add(m).toJSON
      context.unbecome()

    case m: LogMeOutOfAllDevicesMessage =>
      authenticationAPI logoutAllDevices clientUserID
      val allAuthenticatorsForThisUser = context.actorSelection(clientPaths.namedClientPath(clientUserID))
      allAuthenticatorsForThisUser ! logMeOutMessage.add(m)

    case changePasswordMessage: ChangeMyPasswordMessage =>
      val maybeUser = authenticationAPI.user(clientUserID, changePasswordMessage.currentPassword)
      val maybeUserDetails = maybeUser.flatMap { userDetails =>
        userAPI.changePassword(clientUserID, changePasswordMessage.newPassword).toOption
      }

      val response = maybeUserDetails.fold[ChangePasswordAttemptResultMessage[J]](changePasswordFailedMessage){ _ =>
        changePasswordSucceededMessage }
      context.unbecome()

      unnamedClient ! response.add(changePasswordMessage).toJSON

    case requestChangeEmailMessage: RequestChangeEmailMessage =>
      userAPI.requestChangeEmail(clientUserID, requestChangeEmailMessage.newEmail) match {
        case Success(_) =>
          unnamedClient ! requestChangeEmailSucceededMessage.add(requestChangeEmailMessage).toJSON
        case Failure(_) =>
          unnamedClient ! requestChangeEmailFailedMessage.add(requestChangeEmailMessage).toJSON
      }

    case activateNewEmailMessage: ActivateNewEmailMessage =>
      userAPI.activateNewEmail(clientUserID, email, activateNewEmailMessage.newEmail, activateNewEmailMessage.code) match {
        case Success(_) =>
          unnamedClient ! activateNewEmailSucceededMessage.add(activateNewEmailMessage).toJSON
        case Failure(_) =>
          unnamedClient ! activateNewEmailFailedMessage.add(activateNewEmailMessage).toJSON
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

  def props[US, R, J](
      userTokenValidator: TokenValidator,
      userAPI: UserAPI[UserDetails[US]],
      authenticationAPI: AuthenticationAPI[UserDetails[US]],
      registrationAPI: RegistrationAPI[UserDetails[US], US],
      jWTCreator: JWTCreator[UserDetails[US]],
      timeProvider: JavaInstantTimeProvider,
      uUIDProvider: UUIDProvider,
      unnamedClient: ActorRef,
      passwordResetCodeSender: PasswordResetCodeSender[UserDetails[US], R],
      accountActivationLinkSender:AccountActivationCodeSender[UserDetails[US], US],
      toServerMessageRouter: ActorRef,
      logMeOutMessage: LogMeOutMessage,
      yourLoginAttemptFailedMessage: YourLoginAttemptFailedMessage[J],
      yourLoginAttemptSucceededMessage: (String, String, String) => YourLoginAttemptSucceededMessage[J],
      passwordResetActions: UserDetails[US] => Unit,
      passwordResetCodeSentMessage: PasswordResetCodeSentMessage[J],
      passwordResetSuccessfulMessage: PasswordResetSuccessfulMessage[J],
      passwordResetFailedMessage: PasswordResetFailedMessage[J],
      emailIsAvailableMessage: (String, Boolean) => EmailIsAvailableMessage[J],
      usernameIsAvailableMessage: (String, Boolean) => UsernameIsAvailableMessage[J],
      yourRegistrationAttemptFailedMessage: YourRegistrationAttemptFailedMessage[J],
      yourRegistrationAttemptSucceededMessage: YourRegistrationAttemptSucceededMessage[J],
      activationCodeKey: String,
      accountActivationAttemptFailedMessage: String => AccountActivationAttemptFailedMessage[J],
      accountActivationAttemptSucceededMessage: AccountActivationAttemptSucceededMessage[J],
      accountActivationCodeCreator: AccountActivationCodeCreator,
      resendActivationCodeResultMessage: String => ResendActivationCodeResultMessage[J],
      userActivator: UserActivator[UserDetails[US], AccountActivationAttemptResultMessage[J]],
      youAreAlreadyAuthenticatedMessage: YouAreAlreadyAuthenticatedMessage[J],
      loggingYouOutMessage: LoggingYouOutMessage[J],
      clientPaths: ClientPaths,
      changePasswordFailedMessage: ChangePasswordFailedMessage[J],
      changePasswordSucceededMessage: ChangePasswordSucceededMessage[J],
      messageRouterPropsCreator: MessageRouterPropsCreator,
      namedClientProps: (ActorRef, ActorRef) => Props,
      requestChangeEmailFailedMessage: RequestChangeEmailFailedMessage[J],
      requestChangeEmailSucceededMessage: RequestChangeEmailSucceededMessage[J],
      activateNewEmailFailedMessage: ActivateNewEmailFailedMessage[J],
      activateNewEmailSucceededMessage: ActivateNewEmailSucceededMessage[J]) =
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
        passwordResetCodeSender,
        accountActivationLinkSender,
        toServerMessageRouter,
        logMeOutMessage,
        yourLoginAttemptFailedMessage,
        yourLoginAttemptSucceededMessage,
        passwordResetActions,
        passwordResetCodeSentMessage,
        passwordResetSuccessfulMessage,
        passwordResetFailedMessage,
        emailIsAvailableMessage,
        usernameIsAvailableMessage,
        yourRegistrationAttemptFailedMessage,
        yourRegistrationAttemptSucceededMessage,
        activationCodeKey,
        accountActivationAttemptFailedMessage,
        accountActivationAttemptSucceededMessage,
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
        activateNewEmailSucceededMessage))

}