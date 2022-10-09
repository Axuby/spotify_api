from django.core.mail import EmailMessage


class Utils:
    @staticmethod
    def send_email(mail_subject, message, email):
        to_email = email
        send_email = EmailMessage(mail_subject, message, to=[to_email])
        send_email.send()

    @staticmethod
    def send_password_reset_verification(request, user):
        current_site = get_current_site(request)
        email_subject = "Create a new  Password"
        message = render_to_string("account/reset_password_email.html", {
            "user": user,
            "domain": current_site,
            "uid": urlsafe_base64_encode(force_bytes(user.pk)),
            "token": default_token_generator.make_token(user)
        })

        email_to = user.email
        send_email = EmailMessage(
            email_subject, message, to=[email_to])
        send_email.send()
