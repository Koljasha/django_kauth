from django.template import loader
from django.core.mail import EmailMessage


def kauth_send_mail(subject_template_name, email_template_name,
                    from_email, to_email, context):

    subject = loader.render_to_string(subject_template_name, context)
    subject = ''.join(subject.splitlines())
    body = loader.render_to_string(email_template_name, context)

    email_message = EmailMessage(subject, body, from_email, [to_email])
    email_message.send()
