package com.github.shafiquejamal.simplewebsocketauthenticator

import java.util.UUID

import com.github.shafiquejamal.accessmessage.InBound._
import com.github.shafiquejamal.accessmessage.OutBound._

object AuthenticatorMessagesFixture {

  case class LogMeOutMessageImpl(override val iD: UUID, override val previousMessageID: Option[UUID] = None)
    extends LogMeOutMessage

  case class YourLoginAttemptFailedMessageImpl(
      override val iD: UUID, override val previousMessageID: Option[UUID] = None)
    extends YourLoginAttemptFailedMessage[String] {
    override def toJSON: String = "YourLoginAttemptFailedMessageImpl_${iD.toString}"
  }

  case class YourLoginAttemptSucceededMessageImpl(
    override val iD: UUID,
    override val previousMessageID: Option[UUID],
    override val payload: String,
    override val username: String,
    override val email: String) extends YourLoginAttemptSucceededMessage[String] {
    override def toJSON: String = s"YourLoginAttemptSucceededMessageImpl"
  }

  case class PasswordResetCodeSentImpl(override val iD: UUID, override val previousMessageID: Option[UUID])
    extends PasswordResetCodeSentMessage[String] {
    override def toJSON: String = s"PasswordResetCodeSentImpl_${iD.toString}"
  }

  case class PasswordResetSuccessfulMessageImpl(override val iD: UUID, override val previousMessageID: Option[UUID])
    extends PasswordResetSuccessfulMessage[String] {
    override def toJSON: String = s"PasswordResetSuccessfulMessageImpl_${iD.toString}"
  }

  case class PasswordResetFailedMessageImpl(override val iD: UUID, override val previousMessageID: Option[UUID])
    extends PasswordResetFailedMessage[String] {
    override def toJSON: String = s"PasswordResetFailedMessageImpl_${iD.toString}"
  }

  case class EmailIsAvailableMessageImpl(
      override val iD: UUID, override val previousMessageID: Option[UUID],
      override val email: String,
      override val isEmailIsAvailable: Boolean)
    extends EmailIsAvailableMessage[String] {
    override def toJSON: String = s"EmailIsAvailableMessageImpl_${iD.toString}"
  }

  case class UsernameIsAvailableMessageImpl(
      override val iD: UUID,
      override val previousMessageID: Option[UUID],
      override val username: String,
      override val isUsernameIsAvailable: Boolean) extends UsernameIsAvailableMessage[String] {
    override def toJSON: String = s"EmailIsAvailableMessageImpl_${iD.toString}"
  }

  case class YourRegistrationAttemptFailedMessageImpl(
      override val iD: UUID, override val previousMessageID: Option[UUID])
    extends YourRegistrationAttemptFailedMessage[String] {
    override def toJSON: String = s"YourRegistrationAttemptFailedMessageImpl_${iD.toString}"
  }

  case class YourRegistrationAttemptSucceededMessageImpl(
      override val iD: UUID, override val previousMessageID: Option[UUID])
    extends YourRegistrationAttemptSucceededMessage[String] {
    override def toJSON: String = s"YourRegistrationAttemptSucceededMessage_${iD.toString}"
  }

  case class AccountActivationAttemptFailedMessageImpl(
      override val iD: UUID,
      override val previousMessageID: Option[UUID],
      override val errorMessage: String)
    extends AccountActivationAttemptFailedMessage[String] {
    override def toJSON: String = s"AccountActivationAttemptFailedMessageImpl_${iD.toString}"
  }

  case class AccountActivationAttemptSucceededMessageImpl(
      override val iD: UUID,
      override val previousMessageID: Option[UUID])
    extends AccountActivationAttemptSucceededMessage[String] {
    override def toJSON: String = s"AccountActivationAttemptSucceededMessageImpl_${iD.toString}"
  }

  case class ResendActivationCodeResultMessageImpl(
      override val iD: UUID, override val previousMessageID: Option[UUID], override val message: String)
    extends ResendActivationCodeResultMessage[String] {
    override def toJSON: String = s"ResendActivationCodeResultMessageImpl_${iD.toString}"
  }

  case class YouAreAlreadyAuthenticatedMessageImpl(override val iD: UUID, override val previousMessageID: Option[UUID])
    extends YouAreAlreadyAuthenticatedMessage[String] {
    override def toJSON: String = s"YouAreAlreadyAuthenticatedMessageImpl_${iD.toString}"
  }

  case class LoggingYouOutMessageImpl(override val iD: UUID, override val previousMessageID: Option[UUID])
    extends LoggingYouOutMessage[String] {
    override def toJSON: String = s"LoggingYouOutMessageImpl_${iD.toString}"
  }

  case class ChangePasswordFailedMessageImpl(override val iD: UUID, override val previousMessageID: Option[UUID])
    extends ChangePasswordFailedMessage[String] {
    override def toJSON: String = s"ChangePasswordFailedMessageImpl_${iD.toString}"
  }

  case class ChangePasswordSucceededMessageImpl(override val iD: UUID, override val previousMessageID: Option[UUID])
    extends ChangePasswordSucceededMessage[String] {
    override def toJSON: String = s"ChangePasswordSucceededMessageImpl_${iD.toString}"
  }

  case class RequestChangeEmailFailedMessageImpl(override val iD: UUID, override val previousMessageID: Option[UUID])
    extends RequestChangeEmailFailedMessage[String] {
    override def toJSON: String = s"RequestChangeEmailFailedMessageImpl_${iD.toString}"
  }

  case class RequestChangeEmailSucceededMessageImpl(override val iD: UUID, override val previousMessageID: Option[UUID])
    extends RequestChangeEmailSucceededMessage[String] {
    override def toJSON: String = s"RequestChangeEmailSucceededMessageImpl_${iD.toString}"
  }

  case class ActivateNewEmailFailedMessageImpl(override val iD: UUID, override val previousMessageID: Option[UUID])
    extends ActivateNewEmailFailedMessage[String] {
    override def toJSON: String = s"ActivateNewEmailFailedMessageImpl_${iD.toString}"
  }

  case class ActivateNewEmailSucceededMessageImpl(override val iD: UUID, override val previousMessageID: Option[UUID])
    extends ActivateNewEmailSucceededMessage[String] {
    override def toJSON: String = s"ActivateNewEmailSucceededMessageImpl_${iD.toString}"
  }

}
