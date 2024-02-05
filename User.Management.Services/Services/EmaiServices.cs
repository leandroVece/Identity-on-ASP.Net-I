using MailKit.Net.Smtp;
using MimeKit;

namespace User.Management.Services;

public class EmailServices : IEmailServices
{

    private readonly EmailConfigurations _emailConfig;

    public EmailServices(EmailConfigurations emailConfig){
        _emailConfig = emailConfig;
    } 

    public void SendMail(Message message){
        var EmailMessage = CreateEmailMessage(message);
        Send(EmailMessage);
    }

    private MimeMessage CreateEmailMessage(Message message){

        var EmailMessage = new MimeMessage();
        EmailMessage.From.Add(new MailboxAddress("email",_emailConfig.From));
        EmailMessage.To.AddRange(message.To);
        EmailMessage.Subject = message.Subject;
        EmailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Text){ Text = message.Content};

        return EmailMessage;
    }

    void Send(MimeMessage mailMessage){
        using var client = new SmtpClient();
        try
        {
            client.Connect(_emailConfig.SmtpServer, _emailConfig.Port, true);
            client.AuthenticationMechanisms.Remove("XOAUTH2");
            client.Authenticate(_emailConfig.Username,_emailConfig.Password);

            client.Send(mailMessage);
        }
        catch (System.Exception)
        {
            
            throw;
        }
        finally{
            client.Disconnect(true);
            client.Dispose();
        }
    }    
}